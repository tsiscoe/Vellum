use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Result, ensure};
use serde_json::Value;
use vellum::crypto::RepoMasterKey;
use vellum::vault::VellumVault;
use vellum::wire::{MAX_PLAINTEXT_BYTES, clean_to_wireframe, smudge_from_wireframe};

fn checked(output: Output) -> Result<Output> {
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

#[test]
fn maximum_plaintext_round_trips_with_wire_expansion() -> Result<()> {
    let keys = RepoMasterKey::from_bytes([17; 32]).derive_subkeys()?;
    let input = vec![0x83; MAX_PLAINTEXT_BYTES];
    let wire = clean_to_wireframe(&keys, "records/sample.bin", &input, None)?;
    assert!(wire.len() > MAX_PLAINTEXT_BYTES);
    assert_eq!(
        smudge_from_wireframe(&keys, "records/sample.bin", &wire)?.as_slice(),
        input.as_slice()
    );
    Ok(())
}

#[test]
fn concurrent_scope_initialization_returns_the_committed_key() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("vault.db");
    let password = b"public synthetic test passphrase";
    let vault = VellumVault::open_with_passphrase(&path, password, true)?;
    let start = std::sync::Barrier::new(2);
    let keys = std::thread::scope(|threads| {
        let create = || -> Result<RepoMasterKey> {
            start.wait();
            let mut vault = VellumVault::open_with_passphrase(&path, password, true)?;
            vault.ensure_scope_key("research")
        };
        let first = threads.spawn(create);
        let second = threads.spawn(create);
        (first.join().unwrap(), second.join().unwrap())
    });
    let persisted = vault.get_scope_key("research")?.expect("created scope");
    assert!(persisted.0 == keys.0?.0);
    assert!(persisted.0 == keys.1?.0);
    Ok(())
}

#[test]
fn reads_existing_v1_vault_scope() -> Result<()> {
    use vellum::crypto::{MasterSeed, aead_encrypt, keyed_blake3_hex};

    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("vault.db");
    let password = b"public synthetic test passphrase";
    let vault = VellumVault::open_with_passphrase(&path, password, true)?;
    let conn = rusqlite::Connection::open(path)?;
    let salt: Vec<u8> = conn.query_row("SELECT salt FROM vault_meta", [], |row| row.get(0))?;
    let salt = salt.try_into().expect("V1 salt length");
    let subkeys = MasterSeed::derive_fast_for_test(password, &salt)?.derive_subkeys(&salt)?;
    let key = RepoMasterKey::from_bytes([21; 32]);
    let created_at = "2026-01-01T00:00:00+00:00";
    let scope = "research";
    let row_id = "265a97a2-3b2d-412a-8b70-5e95d8aefc94";
    let index = keyed_blake3_hex(&subkeys.mac_key, "vellum-v1-scope", scope.as_bytes());
    let payload = serde_json::json!({
        "scope": scope,
        "master_key_b64": &*key.encode_key_b64(),
        "created_at": created_at
    });
    let aad = format!("vellum-v1|scope|{row_id}");
    let ciphertext = aead_encrypt(
        &subkeys.vault_key,
        aad.as_bytes(),
        &serde_json::to_vec(&payload)?,
    )?;
    conn.execute(
        "INSERT INTO repo_scopes (scope_index, aad_id, created_at, ciphertext) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![index, row_id, created_at, ciphertext],
    )?;
    assert!(vault.get_scope_key(scope)?.expect("legacy scope").0 == key.0);
    assert_eq!(vault.list_scopes()?[0].created_at, created_at);
    Ok(())
}

#[test]
fn cli_key_export_and_external_audit_checkpoint() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let vault = temporary.path().join("custody").join("vault.db");
    let target = temporary.path().join("owner.key");
    let input = temporary.path().join("input.txt");
    std::fs::write(&input, "synthetic file\n")?;
    let vellum = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vellum"));
        command
            .env_remove("VELLUM_KEY")
            .env("VELLUM_PASSPHRASE", "public synthetic test passphrase")
            .arg("--vault")
            .arg(&vault);
        command
    };
    checked(
        vellum()
            .args(["init", "--export-key"])
            .arg(&target)
            .output()?,
    )?;
    let original_key = std::fs::read(&target)?;
    let repeat = vellum()
        .args(["init", "--export-key"])
        .arg(&target)
        .output()?;
    assert!(!repeat.status.success());
    assert!(std::fs::read(&target)? == original_key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&target)?.permissions().mode() & 0o777,
            0o600
        );
    }

    let clean = || {
        vellum()
            .args(["clean", "--path", "records/input.txt", "--input"])
            .arg(&input)
            .output()
    };
    checked(clean()?)?;
    let receipt = checked(vellum().args(["--json", "audit-verify"]).output()?)?;
    let checkpoint: Value = serde_json::from_slice(&receipt.stdout)?;
    assert_eq!(checkpoint["total_entries"], 2);
    let anchor = checkpoint["head_hash"].as_str().expect("checkpoint hash");
    let wire = checked(clean()?)?.stdout;
    let receipt = checked(
        vellum()
            .args([
                "--json",
                "audit-verify",
                "--anchor-count",
                "2",
                "--anchor-head",
                anchor,
            ])
            .output()?,
    )?;
    let report: Value = serde_json::from_slice(&receipt.stdout)?;
    assert_eq!(report["total_entries"], 4);
    let wire_path = temporary.path().join("input.vellum");
    let restored = temporary.path().join("restored.txt");
    std::fs::write(&wire_path, wire)?;
    for _ in 0..2 {
        checked(
            vellum()
                .args(["smudge", "--path", "records/input.txt", "--input"])
                .arg(&wire_path)
                .arg("--output")
                .arg(&restored)
                .output()?,
        )?;
    }
    assert_eq!(std::fs::read_to_string(restored)?, "synthetic file\n");
    Ok(())
}

fn command_for(executable: &str, root: &Path) -> Result<Command> {
    let mut command = Command::new(executable);
    let vellum_path = Path::new(env!("CARGO_BIN_EXE_vellum")).parent().unwrap();
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(vellum_path.to_path_buf()).chain(std::env::split_paths(&search_path)),
    )?;
    command
        .current_dir(root)
        .env("PATH", path)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_CONFIG_COUNT")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", root.join("absent-global-config"))
        .env("VELLUM_KEY", "11".repeat(32));
    Ok(command)
}

#[test]
fn verify_real_git_staging_checkout_merge_and_rename() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let git = |args: &[&str]| checked(command_for("git", root)?.args(args).output()?);
    let vellum = |args: &[&str]| {
        checked(
            command_for(env!("CARGO_BIN_EXE_vellum"), root)?
                .args(args)
                .output()?,
        )
    };
    git(&["init", "-q", "-b", "main"])?;
    git(&["config", "user.email", "fixture@example.invalid"])?;
    git(&["config", "user.name", "Vellum Test"])?;
    let config = String::from_utf8(vellum(&["git-config"])?.stdout)?;
    let (attrs, config) = config
        .split_once("# .git/config")
        .expect("generated Git config");
    std::fs::write(root.join(".gitattributes"), attrs)?;
    use std::io::Write;
    let install_drivers = |root: &Path| -> Result<()> {
        let mut git_config = std::fs::OpenOptions::new()
            .append(true)
            .open(root.join(".git/config"))?;
        writeln!(git_config, "{config}")?;
        Ok(())
    };
    install_drivers(root)?;

    let path = "secret_notes/research draft.txt";
    std::fs::create_dir(root.join("secret_notes"))?;
    std::fs::write(root.join(path), "first\nkeep this\nkeep that\nlast\n")?;
    git(&["add", "--", ".gitattributes", path])?;
    let manifest = root.join("trusted-paths.json");
    std::fs::write(&manifest, serde_json::to_vec(&[path])?)?;
    let manifest_arg = manifest.to_str().expect("fixture path");
    let verified = vellum(&[
        "--json",
        "verify-tree",
        "--staged",
        "--manifest",
        manifest_arg,
    ])?;
    let report: Value = serde_json::from_slice(&verified.stdout)?;
    assert_eq!(report["expected"], 1);
    assert_eq!(report["verified"], 1);
    assert!(
        report["git_source"]
            .as_str()
            .unwrap()
            .starts_with("staged inventory")
    );
    let missing = "secret_notes/expected-later.txt";
    std::fs::write(&manifest, serde_json::to_vec(&[path, missing])?)?;
    let output = command_for(env!("CARGO_BIN_EXE_vellum"), root)?
        .args([
            "--json",
            "verify-tree",
            "--staged",
            "--manifest",
            manifest_arg,
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["expected"], 2);
    assert_eq!(report["verified"], 1);
    assert_eq!(report["failed"][0]["file"], missing);
    std::fs::write(&manifest, serde_json::to_vec(&[path])?)?;
    git(&["commit", "-qm", "base"])?;
    std::fs::remove_file(root.join(path))?;
    git(&["checkout", "--", path])?;
    assert_eq!(
        std::fs::read_to_string(root.join(path))?,
        "first\nkeep this\nkeep that\nlast\n"
    );

    git(&["switch", "-qc", "second"])?;
    std::fs::write(
        root.join(path),
        "first\nkeep this\nkeep that\nlast revised\n",
    )?;
    git(&["commit", "-qam", "second"])?;
    git(&["switch", "-q", "main"])?;
    std::fs::write(
        root.join(path),
        "first revised\nkeep this\nkeep that\nlast\n",
    )?;
    git(&["commit", "-qam", "first"])?;
    git(&["merge", "--no-edit", "second"])?;
    assert_eq!(
        std::fs::read_to_string(root.join(path))?,
        "first revised\nkeep this\nkeep that\nlast revised\n"
    );
    vellum(&[
        "verify-tree",
        "--revision",
        "HEAD",
        "--manifest",
        manifest_arg,
    ])?;

    let other = tempfile::tempdir()?;
    let clone = other.path().join("clone");
    checked(
        command_for("git", other.path())?
            .args(["clone", "--no-checkout", "--quiet"])
            .arg(root)
            .arg(&clone)
            .output()?,
    )?;
    install_drivers(&clone)?;
    checked(
        command_for("git", &clone)?
            .args(["checkout", "--force", "main"])
            .output()?,
    )?;
    assert_eq!(
        std::fs::read_to_string(clone.join(path))?,
        "first revised\nkeep this\nkeep that\nlast revised\n"
    );

    let renamed = "secret_notes/research final.txt";
    git(&["mv", "--", path, renamed])?;
    git(&["add", "--renormalize", "--", renamed])?;
    std::fs::write(&manifest, serde_json::to_vec(&[renamed])?)?;
    vellum(&["verify-tree", "--staged", "--manifest", manifest_arg])?;
    Ok(())
}

#[test]
fn merge_preserves_input_on_output_error_and_reports_content_conflict() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let keys = RepoMasterKey::from_bytes([0x11; 32]).derive_subkeys()?;
    let path = "records/plan.txt";
    for (file, text) in [
        ("base.vellum", "draft\n"),
        ("ours.vellum", "first revision\n"),
        ("theirs.vellum", "second revision\n"),
    ] {
        std::fs::write(
            root.join(file),
            clean_to_wireframe(&keys, path, text.as_bytes(), None)?,
        )?;
    }
    let merge = || -> Result<Command> {
        let mut command = command_for(env!("CARGO_BIN_EXE_vellum"), root)?;
        command.args([
            "merge",
            "--path",
            path,
            "--base",
            "base.vellum",
            "--ours",
            "ours.vellum",
            "--theirs",
            "theirs.vellum",
        ]);
        Ok(command)
    };
    let before = std::fs::read(root.join("ours.vellum"))?;
    std::fs::create_dir(root.join("occupied-directory"))?;
    let error = merge()?.args(["--out", "occupied-directory"]).output()?;
    assert_eq!(error.status.code(), Some(129));
    assert_eq!(std::fs::read(root.join("ours.vellum"))?, before);
    let conflict = merge()?.output()?;
    assert_eq!(conflict.status.code(), Some(1));
    let wire = std::fs::read_to_string(root.join("ours.vellum"))?;
    let plaintext = smudge_from_wireframe(&keys, path, &wire)?;
    assert!(vellum::wire::contains_conflict_markers(&plaintext));
    assert!(clean_to_wireframe(&keys, path, wire.as_bytes(), None).is_err());
    Ok(())
}
