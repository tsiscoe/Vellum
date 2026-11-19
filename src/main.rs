#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use zeroize::{Zeroize, Zeroizing};

use vellum::cli::{Cli, Commands};
use vellum::crypto::{RepoMasterKey, normalize_repo_path, parse_repo_key, validate_scope_name};
use vellum::merge::{merge_encrypted_wireframes, unified_diff_text};
use vellum::tui::{VellumTuiApp, run_interactive_tui};
use vellum::vault::{NewAuditEvent, VellumVault, enforce_owner_only_acl};
use vellum::wire::{
    MAX_WIREFRAME_BYTES, clean_to_wireframe, diff_wireframes_stats, is_vellum_wireframe,
    parse_and_verify_wireframe, smudge_from_wireframe,
};

const KEYRING_SERVICE: &str = "vellum-vault";
const KEYRING_USER: &str = "default-passphrase";

fn default_vault_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vellum")
        .join("vellum.db")
}

fn resolve_passphrase(use_keyring: bool, creating: bool) -> Result<Vec<u8>> {
    if let Ok(env_pw) = std::env::var("VELLUM_PASSPHRASE")
        && !env_pw.is_empty()
    {
        return Ok(env_pw.into_bytes());
    }

    if use_keyring {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .map_err(|e| anyhow!("OS keyring entry init failed: {e}"))?;
        if !creating {
            match entry.get_password() {
                Ok(pw) if !pw.is_empty() => return Ok(pw.into_bytes()),
                Ok(_) => {}
                Err(err) => {
                    eprintln!("OS keyring lookup missed ({err}); falling back to prompt.");
                }
            }
        }
    }

    let prompt = if creating {
        "Create Vellum vault passphrase: "
    } else {
        "Vellum vault passphrase: "
    };
    let pw = rpassword::prompt_password(prompt).context("failed to read vault passphrase")?;
    if pw.is_empty() {
        return Err(anyhow!("vault passphrase cannot be empty"));
    }

    if creating {
        let confirm = rpassword::prompt_password("Confirm Vellum vault passphrase: ")
            .context("failed to read confirmation passphrase")?;
        if pw != confirm {
            return Err(anyhow!("passphrases did not match"));
        }
        if use_keyring {
            let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
                .map_err(|e| anyhow!("OS keyring entry init failed: {e}"))?;
            entry
                .set_password(&pw)
                .map_err(|e| anyhow!("failed to store passphrase in OS keyring: {e}"))?;
        }
    }

    Ok(pw.into_bytes())
}

fn open_vault(
    vault_arg: Option<PathBuf>,
    use_keyring: bool,
    must_exist: bool,
) -> Result<VellumVault> {
    let path = vault_arg.unwrap_or_else(default_vault_path);
    let exists = path.exists();
    if must_exist && !exists {
        return Err(anyhow!(
            "Vellum vault does not exist at {} (run `vellum init` first)",
            path.display()
        ));
    }
    let mut pw = resolve_passphrase(use_keyring, !exists)?;
    let res = VellumVault::open_with_passphrase(&path, &pw, false);
    pw.zeroize();
    res
}

fn load_repo_key_spec(spec: &str) -> Result<RepoMasterKey> {
    let p = Path::new(spec);
    if p.exists() && p.is_file() {
        let content = std::fs::read_to_string(p)
            .with_context(|| format!("failed to read Vellum key file {}", p.display()))?;
        return parse_repo_key(&content);
    }
    parse_repo_key(spec)
}

fn resolve_repo_key_and_vault(
    key_opt: Option<&str>,
    vault_arg: Option<PathBuf>,
    use_keyring: bool,
    scope: &str,
) -> Result<(RepoMasterKey, Option<VellumVault>)> {
    validate_scope_name(scope)?;
    if let Some(spec) = key_opt {
        return Ok((load_repo_key_spec(spec)?, None));
    }
    let vault = open_vault(vault_arg, use_keyring, true)?;
    let key = vault
        .get_scope_key(scope)?
        .ok_or_else(|| anyhow!("scope '{scope}' not found in Vellum vault"))?;
    Ok((key, Some(vault)))
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing to read symlinked input path {}",
            path.display()
        ));
    }
    if meta.len() > MAX_WIREFRAME_BYTES as u64 {
        return Err(anyhow!(
            "input {} exceeds Vellum 32 MiB ceiling ({} > {} bytes)",
            path.display(),
            meta.len(),
            MAX_WIREFRAME_BYTES
        ));
    }
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(64 * 1024));
    file.take((MAX_WIREFRAME_BYTES + 1) as u64)
        .read_to_end(&mut buf)?;
    if buf.len() > MAX_WIREFRAME_BYTES {
        return Err(anyhow!(
            "input {} exceeds Vellum 32 MiB ceiling",
            path.display()
        ));
    }
    Ok(buf)
}

fn read_bounded_string(path: &Path) -> Result<String> {
    let bytes = read_bounded_file(path)?;
    String::from_utf8(bytes).map_err(|_| anyhow!("input {} is not valid UTF-8", path.display()))
}

fn read_bytes_arg(input: Option<PathBuf>) -> Result<Vec<u8>> {
    match input {
        Some(path) => read_bounded_file(&path),
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .take((MAX_WIREFRAME_BYTES + 1) as u64)
                .read_to_end(&mut buf)?;
            if buf.len() > MAX_WIREFRAME_BYTES {
                return Err(anyhow!(
                    "stdin stream exceeds Vellum 32 MiB ceiling ({MAX_WIREFRAME_BYTES} bytes)"
                ));
            }
            Ok(buf)
        }
    }
}

fn write_bytes_arg(output: Option<PathBuf>, data: &[u8]) -> Result<()> {
    match output {
        Some(path) => std::fs::write(&path, data)
            .with_context(|| format!("failed to write {}", path.display())),
        None => {
            std::io::stdout().write_all(data)?;
            Ok(())
        }
    }
}

fn collect_tree_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let root_meta = std::fs::symlink_metadata(dir)?;
    if root_meta.file_type().is_symlink() {
        return Ok(());
    }
    if root_meta.is_file() {
        out.push(dir.to_path_buf());
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let meta = std::fs::symlink_metadata(&p)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if meta.is_dir() {
            if !matches!(s.as_ref(), ".git" | "target" | "node_modules" | ".venv") {
                collect_tree_files(&p, out)?;
            }
        } else if meta.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            scope,
            export_key,
            reveal,
        } => {
            validate_scope_name(&scope)?;
            let mut vault = open_vault(cli.vault, cli.keyring, false)?;
            let key = vault.ensure_scope_key(&scope)?;
            let fp = vault.scope_fingerprint(&key);
            let encoded = key.encode_key_b64();
            if let Some(out_path) = export_key {
                if let Some(parent) = out_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&out_path, format!("{}\n", *encoded))?;
                enforce_owner_only_acl(&out_path, false)?;
            }
            let display_key = if reveal {
                encoded.to_string()
            } else {
                "[REDACTED — pass --reveal or --export-key]".to_string()
            };
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "vault": vault.db_path(),
                        "scope": scope,
                        "fingerprint": fp,
                        "key": display_key,
                    }))?
                );
            } else {
                println!("Initialized Vellum vault: {}", vault.db_path().display());
                println!("Scope '{scope}' fingerprint: {fp}");
                println!("Scope '{scope}' key: {display_key}");
            }
        }

        Commands::Clean {
            path,
            scope,
            key,
            input,
            output,
        } => {
            let (repo_key, mut vault_opt) =
                resolve_repo_key_and_vault(key.as_deref(), cli.vault, cli.keyring, &scope)?;
            let subkeys = repo_key.derive_subkeys()?;
            let raw = Zeroizing::new(read_bytes_arg(input)?);
            let wire = clean_to_wireframe(&subkeys, &path, &raw, None)?;
            if let Some(ref mut v) = vault_opt {
                let verified = parse_and_verify_wireframe(&subkeys, &path, &wire)?;
                let _ = v.append_audit_event(NewAuditEvent {
                    operation: "clean".to_string(),
                    scope,
                    rel_path: verified.norm_path,
                    total_chunks: verified.chunks.len(),
                    unchanged_chunks: 0,
                    seal_short: verified.seal_hex[..16].to_string(),
                });
            }
            write_bytes_arg(output, wire.as_bytes())?;
        }

        Commands::Smudge {
            path,
            scope,
            key,
            input,
            output,
        } => {
            let (repo_key, mut vault_opt) =
                resolve_repo_key_and_vault(key.as_deref(), cli.vault, cli.keyring, &scope)?;
            let subkeys = repo_key.derive_subkeys()?;
            let raw = read_bytes_arg(input)?;
            let wire = String::from_utf8(raw)
                .map_err(|_| anyhow!("Vellum smudge expects UTF-8 VELLUM-WIRE-V1 input"))?;
            let verified = parse_and_verify_wireframe(&subkeys, &path, &wire)?;
            let plaintext = smudge_from_wireframe(&subkeys, &path, &wire)?;
            if let Some(ref mut v) = vault_opt {
                let _ = v.append_audit_event(NewAuditEvent {
                    operation: "smudge".to_string(),
                    scope,
                    rel_path: verified.norm_path,
                    total_chunks: verified.chunks.len(),
                    unchanged_chunks: verified.chunks.len(),
                    seal_short: verified.seal_hex[..16].to_string(),
                });
            }
            write_bytes_arg(output, &plaintext)?;
        }

        Commands::Merge {
            base,
            ours,
            theirs,
            path,
            out,
            scope,
            key,
        } => {
            let (repo_key, mut vault_opt) =
                resolve_repo_key_and_vault(key.as_deref(), cli.vault, cli.keyring, &scope)?;
            let subkeys = repo_key.derive_subkeys()?;
            let base_wire = read_bounded_string(&base)?;
            let ours_wire = read_bounded_string(&ours)?;
            let theirs_wire = read_bounded_string(&theirs)?;
            let (merged_wire, has_conflict) =
                merge_encrypted_wireframes(&subkeys, &path, &base_wire, &ours_wire, &theirs_wire)?;

            let dest = out.unwrap_or(ours);
            std::fs::write(&dest, merged_wire.as_bytes())?;

            if let Some(ref mut v) = vault_opt {
                let verified = parse_and_verify_wireframe(&subkeys, &path, &merged_wire)?;
                let _ = v.append_audit_event(NewAuditEvent {
                    operation: if has_conflict {
                        "merge-conflict".to_string()
                    } else {
                        "merge-clean".to_string()
                    },
                    scope,
                    rel_path: verified.norm_path,
                    total_chunks: verified.chunks.len(),
                    unchanged_chunks: 0,
                    seal_short: verified.seal_hex[..16].to_string(),
                });
            }

            if has_conflict {
                std::process::exit(1);
            }
        }

        Commands::Diff {
            file_a,
            file_b,
            path,
            scope,
            key,
        } => {
            let (repo_key, _) =
                resolve_repo_key_and_vault(key.as_deref(), cli.vault, cli.keyring, &scope)?;
            let subkeys = repo_key.derive_subkeys()?;
            let wire_a = read_bounded_string(&file_a)?;
            let wire_b = read_bounded_string(&file_b)?;
            let stats = diff_wireframes_stats(&wire_a, &wire_b)?;
            let pt_a = smudge_from_wireframe(&subkeys, &path, &wire_a)?;
            let pt_b = smudge_from_wireframe(&subkeys, &path, &wire_b)?;
            let a_str = String::from_utf8_lossy(&pt_a);
            let b_str = String::from_utf8_lossy(&pt_b);
            let patch = unified_diff_text(
                &format!("a/{}", normalize_repo_path(&path)),
                &a_str,
                &format!("b/{}", normalize_repo_path(&path)),
                &b_str,
            );
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "stats": stats,
                        "diff": patch,
                    }))?
                );
            } else {
                println!(
                    "Chunk Reuse: {}/{} ({}%) | Changed: {}",
                    stats.unchanged_chunks,
                    stats.total_chunks_b,
                    stats.reuse_pct,
                    stats.changed_chunks_b
                );
                print!("{patch}");
            }
        }

        Commands::Textconv {
            file,
            path,
            scope,
            key,
        } => {
            let (repo_key, _) =
                resolve_repo_key_and_vault(key.as_deref(), cli.vault, cli.keyring, &scope)?;
            let subkeys = repo_key.derive_subkeys()?;
            let raw = read_bounded_file(&file)?;
            if is_vellum_wireframe(&raw) {
                let wire = String::from_utf8(raw)?;
                let pt = smudge_from_wireframe(&subkeys, &path, &wire)?;
                std::io::stdout().write_all(&pt)?;
            } else {
                std::io::stdout().write_all(&raw)?;
            }
        }

        Commands::VerifyTree { dir, scope, key } => {
            let (repo_key, _) =
                resolve_repo_key_and_vault(key.as_deref(), cli.vault, cli.keyring, &scope)?;
            let subkeys = repo_key.derive_subkeys()?;
            let mut files = Vec::new();
            collect_tree_files(&dir, &mut files)?;

            let mut verified_count = 0usize;
            let mut failed: Vec<(PathBuf, String)> = Vec::new();
            for f in files {
                let Ok(raw) = read_bounded_file(&f) else {
                    continue;
                };
                if !is_vellum_wireframe(&raw) {
                    continue;
                }
                let rel = f
                    .strip_prefix(&dir)
                    .unwrap_or(&f)
                    .to_string_lossy()
                    .to_string();
                let Ok(wire) = String::from_utf8(raw) else {
                    failed.push((f, "non-UTF8 wireframe".to_string()));
                    continue;
                };
                match parse_and_verify_wireframe(&subkeys, &rel, &wire) {
                    Ok(_) => verified_count += 1,
                    Err(e) => failed.push((f, e.to_string())),
                }
            }

            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "verified": verified_count,
                        "failed": failed.iter().map(|(p, e)| serde_json::json!({"file": p, "error": e})).collect::<Vec<_>>(),
                    }))?
                );
            } else {
                println!(
                    "Verified Vellum files: {} | Failed seals: {}",
                    verified_count,
                    failed.len()
                );
                for (p, err) in &failed {
                    eprintln!("  [SEAL:FAIL] {}: {err}", p.display());
                }
            }

            if !failed.is_empty() {
                std::process::exit(1);
            }
        }

        Commands::GitConfig { scope } => {
            validate_scope_name(&scope)?;
            println!("# .gitattributes");
            println!("secret_notes/** filter=vellum diff=vellum merge=vellum\n");
            println!("# .git/config");
            println!("[filter \"vellum\"]");
            println!("    clean = vellum clean --scope {scope} --path %f");
            println!("    smudge = vellum smudge --scope {scope} --path %f");
            println!("    required = true");
            println!("[diff \"vellum\"]");
            println!("    textconv = vellum textconv --scope {scope} --path %f");
            println!("[merge \"vellum\"]");
            println!("    name = Vellum SIV 3-way encrypted merge driver");
            println!(
                "    driver = vellum merge --scope {scope} --base %O --ours %A --theirs %B --path %P"
            );
        }

        Commands::Tui { file } => {
            let vault = open_vault(cli.vault, cli.keyring, true)?;
            let scopes = vault.list_scopes()?;
            let audit = vault.list_audit_entries(200)?;
            let chain_report = vault.verify_audit_chain()?;

            let (wire_preview_path, wire_chunk_count, wire_seal_hex, wire_chunk_ids) =
                if let Some(p) = file {
                    let raw = read_bounded_string(&p)?;
                    let mut ids = Vec::new();
                    let mut seal = String::from("unverified-preview");
                    for line in raw.lines() {
                        if let Some(rest) = line.strip_prefix("@vellum:chunk:v1 ")
                            && let Some(id) = rest.split_whitespace().next()
                        {
                            ids.push(id.to_string());
                        } else if let Some(s) = line.strip_prefix("@vellum:seal:v1 ") {
                            seal = s.trim().to_string();
                        }
                    }
                    (p.display().to_string(), ids.len(), seal, ids)
                } else {
                    (
                        "none (--file omitted)".to_string(),
                        0,
                        "n/a".to_string(),
                        Vec::new(),
                    )
                };

            let app = VellumTuiApp::new(
                vault.db_path().display().to_string(),
                scopes,
                audit,
                chain_report,
                wire_preview_path,
                wire_chunk_count,
                wire_seal_hex,
                wire_chunk_ids,
            );
            run_interactive_tui(app)?;
        }
    }

    Ok(())
}
