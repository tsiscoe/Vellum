#![forbid(unsafe_code)]

mod output;
mod verify;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use zeroize::Zeroizing;

use vellum::cli::{Cli, Commands};
use vellum::crypto::{RepoMasterKey, normalize_repo_path, parse_repo_key, validate_scope_name};
use vellum::merge::{check_text_budget, merge_encrypted_wireframes, unified_diff_text};
use vellum::tui::{VellumTuiApp, run_interactive_tui};
use vellum::vault::{NewAuditEvent, VellumVault};
use vellum::wire::{
    MAX_WIREFRAME_BYTES, ParsedWireframe, clean_to_wireframe, diff_wireframes_stats,
    is_vellum_wireframe, parse_and_verify_wireframe, smudge_from_wireframe,
};

const KEYRING_SERVICE: &str = "vellum-vault";

fn default_vault_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vellum")
        .join("vellum.db")
}

fn keyring_entry(path: &Path) -> Result<keyring::Entry> {
    let canonical = path
        .canonicalize()
        .context("failed to resolve vault identity")?;
    let user = blake3::hash(canonical.as_os_str().as_encoded_bytes()).to_hex();
    keyring::Entry::new(KEYRING_SERVICE, user.as_str())
        .map_err(|error| anyhow!("OS keyring entry initialization failed: {error}"))
}

fn resolve_passphrase(path: &Path, use_keyring: bool, creating: bool) -> Result<Zeroizing<String>> {
    if let Ok(pw) = std::env::var("VELLUM_PASSPHRASE")
        && !pw.is_empty()
    {
        return Ok(Zeroizing::new(pw));
    }
    if use_keyring && !creating {
        match keyring_entry(path)?.get_password() {
            Ok(pw) if !pw.is_empty() => return Ok(Zeroizing::new(pw)),
            Ok(_) | Err(keyring::Error::NoEntry) => {}
            Err(err) => return Err(anyhow!("OS keyring lookup failed: {err}")),
        }
    }
    let prompt = if creating {
        "Create Vellum vault passphrase: "
    } else {
        "Vellum vault passphrase: "
    };
    let pw = Zeroizing::new(
        rpassword::prompt_password(prompt).context("failed to read vault passphrase")?,
    );
    if pw.is_empty() {
        return Err(anyhow!("vault passphrase cannot be empty"));
    }
    if creating {
        let confirm = Zeroizing::new(
            rpassword::prompt_password("Confirm Vellum vault passphrase: ")
                .context("failed to read confirmation passphrase")?,
        );
        if *pw != *confirm {
            return Err(anyhow!("passphrases did not match"));
        }
    }
    Ok(pw)
}

fn open_vault(
    vault_arg: Option<PathBuf>,
    use_keyring: bool,
    must_exist: bool,
) -> Result<VellumVault> {
    let path = vault_arg.unwrap_or_else(default_vault_path);
    let exists = path.try_exists()?;
    if must_exist && !exists {
        return Err(anyhow!(
            "Vellum vault does not exist at {} (run vellum init first)",
            path.display()
        ));
    }
    let pw = resolve_passphrase(&path, use_keyring, !exists)?;
    let vault = VellumVault::open_with_passphrase(&path, pw.as_bytes(), false)?;
    if use_keyring && !must_exist {
        keyring_entry(&path)?
            .set_password(&pw)
            .map_err(|err| anyhow!("vault opened, but OS keyring update failed: {err}"))?;
    }
    Ok(vault)
}

fn load_repo_key_spec(spec: &str) -> Result<RepoMasterKey> {
    let p = Path::new(spec);
    if p.exists() && p.is_file() {
        let content = Zeroizing::new(String::from_utf8(read_file_with_limit(p, 4096)?)?);
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
    read_file_with_limit(path, MAX_WIREFRAME_BYTES)
}

fn read_file_with_limit(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !meta.is_file() {
        return Err(anyhow!(
            "expected a regular input file at {}",
            path.display()
        ));
    }
    if meta.len() > limit as u64 {
        return Err(anyhow!("input {} exceeds {limit} bytes", path.display()));
    }
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(64 * 1024));
    file.take((limit + 1) as u64).read_to_end(&mut buf)?;
    if buf.len() > limit {
        return Err(anyhow!("input {} exceeds {limit} bytes", path.display()));
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
                    "stdin stream exceeds Vellum wire size limit ({MAX_WIREFRAME_BYTES} bytes)"
                ));
            }
            Ok(buf)
        }
    }
}

fn write_bytes_arg(output: Option<PathBuf>, data: &[u8]) -> Result<()> {
    match output {
        Some(path) => output::write_atomic(&path, data),
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(data)?;
            stdout.flush()?;
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

fn audit_output(
    vault: Option<&mut VellumVault>,
    operation: &str,
    scope: String,
    verified: ParsedWireframe,
    unchanged_chunks: usize,
    write: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let Some(vault) = vault else {
        return write();
    };
    let mut event = NewAuditEvent {
        operation: format!("{operation}-intent"),
        scope,
        rel_path: verified.norm_path,
        total_chunks: verified.chunks.len(),
        unchanged_chunks,
        seal_short: verified.seal_hex[..16].to_string(),
    };
    drop(verified.chunks);
    let intent = vault
        .append_audit_event(event.clone())
        .context("audit intent failed before output")?;
    let result = write();
    let outcome = if result.is_ok() {
        "complete"
    } else {
        "output-error"
    };
    event.operation = format!("{operation}-{outcome}:{}", intent.seq);
    match (result, vault.append_audit_event(event)) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(_)) => Err(error),
        (Ok(()), Err(audit)) => {
            Err(audit.context("output was written but the audit outcome failed"))
        }
        (Err(error), Err(audit)) => Err(error.context(format!(
            "output and audit outcome failed for intent {}: {audit:#}",
            intent.seq
        ))),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let merge = matches!(&cli.command, Commands::Merge { .. });
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("vellum: {error:#}");
            ExitCode::from(if merge { 129 } else { 1 })
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
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
                let mut export = Zeroizing::new(String::with_capacity(encoded.len() + 1));
                export.push_str(&encoded);
                export.push('\n');
                output::export_key(&out_path, export.as_bytes())?;
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
            if vault_opt.is_some() {
                let verified = parse_and_verify_wireframe(&subkeys, &path, &wire)?;
                audit_output(vault_opt.as_mut(), "clean", scope, verified, 0, || {
                    write_bytes_arg(output, wire.as_bytes())
                })?;
            } else {
                write_bytes_arg(output, wire.as_bytes())?;
            }
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
            let count = verified.chunks.len();
            audit_output(
                vault_opt.as_mut(),
                "smudge",
                scope,
                verified,
                count,
                || match output {
                    Some(path) => output::write_plaintext(&path, &plaintext),
                    None => write_bytes_arg(None, &plaintext),
                },
            )?;
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
            let verified = parse_and_verify_wireframe(&subkeys, &path, &merged_wire)?;
            let operation = if has_conflict {
                "merge-conflict"
            } else {
                "merge-clean"
            };
            audit_output(vault_opt.as_mut(), operation, scope, verified, 0, || {
                output::write_atomic(&dest, merged_wire.as_bytes())
            })?;
            if has_conflict {
                return Ok(ExitCode::from(1));
            }
        }

        Commands::Diff {
            file_a,
            file_b,
            path,
            scope,
            key,
        } => {
            let (repo_key, mut vault) =
                resolve_repo_key_and_vault(key.as_deref(), cli.vault, cli.keyring, &scope)?;
            let subkeys = repo_key.derive_subkeys()?;
            let wire_a = read_bounded_string(&file_a)?;
            let wire_b = read_bounded_string(&file_b)?;
            let stats = diff_wireframes_stats(&wire_a, &wire_b)?;
            let pt_a = smudge_from_wireframe(&subkeys, &path, &wire_a)?;
            let pt_b = smudge_from_wireframe(&subkeys, &path, &wire_b)?;
            let a_str = Zeroizing::new(String::from_utf8_lossy(&pt_a).into_owned());
            let b_str = Zeroizing::new(String::from_utf8_lossy(&pt_b).into_owned());
            check_text_budget(&a_str)?;
            check_text_budget(&b_str)?;
            let patch = Zeroizing::new(unified_diff_text(
                &format!("a/{}", normalize_repo_path(&path)),
                &a_str,
                &format!("b/{}", normalize_repo_path(&path)),
                &b_str,
            ));
            let write = || {
                let mut stdout = std::io::stdout().lock();
                if cli.json {
                    serde_json::to_writer_pretty(
                        &mut stdout,
                        &serde_json::json!({ "stats": stats, "diff": &*patch }),
                    )?;
                    stdout.write_all(b"\n")?;
                } else {
                    writeln!(
                        stdout,
                        "Chunk Reuse: {}/{} ({}%) | Changed: {}",
                        stats.unchanged_chunks,
                        stats.total_chunks_b,
                        stats.reuse_pct,
                        stats.changed_chunks_b
                    )?;
                    stdout.write_all(patch.as_bytes())?;
                }
                stdout.flush()?;
                Ok(())
            };
            if let Some(vault) = vault.as_mut() {
                let verified = parse_and_verify_wireframe(&subkeys, &path, &wire_b)?;
                audit_output(
                    Some(vault),
                    "diff",
                    scope,
                    verified,
                    stats.unchanged_chunks,
                    write,
                )?;
            } else {
                write()?;
            }
        }

        Commands::Textconv {
            file,
            path,
            scope,
            key,
        } => {
            let (repo_key, mut vault) =
                resolve_repo_key_and_vault(key.as_deref(), cli.vault, cli.keyring, &scope)?;
            let subkeys = repo_key.derive_subkeys()?;
            let wire = read_bounded_string(&file)?;
            let verified = parse_and_verify_wireframe(&subkeys, &path, &wire)?;
            let pt = smudge_from_wireframe(&subkeys, &path, &wire)?;
            let count = verified.chunks.len();
            audit_output(vault.as_mut(), "textconv", scope, verified, count, || {
                write_bytes_arg(None, &pt)
            })?;
        }

        Commands::VerifyTree {
            dir,
            manifest,
            staged: _,
            revision,
            scope,
            key,
        } => {
            let (repo_key, _) =
                resolve_repo_key_and_vault(key.as_deref(), cli.vault, cli.keyring, &scope)?;
            let subkeys = repo_key.derive_subkeys()?;
            let result = if let Some(manifest) = manifest {
                verify::verify_git(&dir, &manifest, revision.as_deref(), &subkeys)?
            } else {
                let mut files = Vec::new();
                collect_tree_files(&dir, &mut files)?;
                let mut result = verify::Verification::default();
                for file in files {
                    let path = file
                        .strip_prefix(&dir)
                        .ok()
                        .and_then(|rel| {
                            rel.iter()
                                .map(|part| part.to_str())
                                .collect::<Option<Vec<_>>>()
                        })
                        .map(|parts| parts.join("/"));
                    let verified = (|| {
                        let raw = read_bounded_file(&file)?;
                        if !is_vellum_wireframe(&raw) {
                            return Ok(false);
                        }
                        let path = path
                            .as_deref()
                            .context("cannot resolve a UTF-8 repository path")?;
                        parse_and_verify_wireframe(&subkeys, path, std::str::from_utf8(&raw)?)?;
                        Ok::<_, anyhow::Error>(true)
                    })();
                    match verified {
                        Ok(true) => result.verified += 1,
                        Ok(false) => result.skipped += 1,
                        Err(error) => result.fail(file.display().to_string(), error),
                    }
                }
                result
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "Verified: {} | Failed: {} | Skipped: {}",
                    result.verified,
                    result.failed.len(),
                    result.skipped
                );
                if let Some(expected) = result.expected {
                    println!("Expected protected Git paths: {expected}");
                }
                if let Some(source) = &result.git_source {
                    println!("Git source: {source}");
                }
                for failure in &result.failed {
                    eprintln!(
                        "  [SEAL:FAIL] {}: {}",
                        failure.file.escape_debug(),
                        failure.error.escape_debug()
                    );
                }
            }
            if !result.passed() {
                return Ok(ExitCode::FAILURE);
            }
        }

        Commands::AuditVerify {
            anchor_count,
            anchor_head,
        } => {
            let vault = open_vault(cli.vault, cli.keyring, true)?;
            let report = match (anchor_count, anchor_head) {
                (Some(count), Some(head)) => vault.verify_audit_checkpoint(count, &head)?,
                _ => vault.verify_audit_chain()?,
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Verified audit entries: {} | Head: {}",
                    report.total_entries, report.head_hash
                );
            }
        }

        Commands::GitConfig { scope } => {
            validate_scope_name(&scope)?;
            let keyring_flag = if cli.keyring { " --keyring" } else { "" };
            println!("# .gitattributes");
            println!("secret_notes/** filter=vellum merge=vellum -text\n");
            println!("# .git/config");
            println!("[filter \"vellum\"]");
            println!("    clean = vellum{keyring_flag} clean --scope {scope} --path %f");
            println!("    smudge = vellum{keyring_flag} smudge --scope {scope} --path %f");
            println!("    required = true");
            println!("[merge \"vellum\"]");
            println!("    name = Vellum SIV 3-way encrypted merge driver");
            println!(
                "    driver = vellum{keyring_flag} merge --scope {scope} --base %O --ours %A --theirs %B --path %P"
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

    Ok(ExitCode::SUCCESS)
}
