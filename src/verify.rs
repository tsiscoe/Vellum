use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use vellum::crypto::{RepoSubkeys, validate_and_normalize_repo_path};
use vellum::wire::{MAX_WIREFRAME_BYTES, parse_and_verify_wireframe};

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_GIT_INVENTORY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default, Serialize)]
pub struct Verification {
    pub expected: Option<usize>,
    pub git_source: Option<String>,
    pub verified: usize,
    pub skipped: usize,
    pub failed: Vec<Failure>,
}

#[derive(Serialize)]
pub struct Failure {
    pub file: String,
    pub error: String,
}

impl Verification {
    pub fn fail(&mut self, file: impl Into<String>, error: impl ToString) {
        self.failed.push(Failure {
            file: file.into(),
            error: error.to_string(),
        });
    }

    pub fn passed(&self) -> bool {
        self.failed.is_empty() && self.verified != 0
    }
}

pub fn verify_git(
    root: &Path,
    manifest: &Path,
    revision: Option<&str>,
    keys: &RepoSubkeys,
) -> Result<Verification> {
    let mut manifest_file = std::fs::File::open(manifest)?;
    let input = bounded_read(&mut manifest_file, MAX_MANIFEST_BYTES)?;
    let entries: Vec<String> =
        serde_json::from_slice(&input).context("invalid protected path manifest")?;
    let mut paths = BTreeSet::new();
    for path in entries {
        let path = validate_and_normalize_repo_path(&path)?;
        if !paths.insert(path) {
            bail!("protected path manifest has a duplicate path");
        }
    }
    if paths.is_empty() {
        bail!("protected path manifest is empty");
    }

    let prefix = git_output(root, &["rev-parse", "--show-prefix"], 4096)?;
    if !std::str::from_utf8(&prefix)?
        .trim_end_matches(['\r', '\n'])
        .is_empty()
    {
        bail!("--dir must be the Git repository root");
    }
    let (inventory, git_source) = if let Some(revision) = revision {
        let treeish = format!("{revision}^{{tree}}");
        let output = git_output(
            root,
            &["rev-parse", "--verify", "--end-of-options", &treeish],
            128,
        )?;
        let tree = std::str::from_utf8(&output)?.trim_end_matches(['\r', '\n']);
        if !valid_oid(tree) {
            bail!("Git returned an invalid tree object ID");
        }
        let inventory = git_output(
            root,
            &["ls-tree", "-r", "-z", "--full-tree", tree],
            MAX_GIT_INVENTORY_BYTES,
        )?;
        (inventory, format!("tree {tree}"))
    } else {
        let inventory = git_output(
            root,
            &["ls-files", "--stage", "-z"],
            MAX_GIT_INVENTORY_BYTES,
        )?;
        let digest = blake3::hash(&inventory).to_hex();
        (inventory, format!("staged inventory BLAKE3 {digest}"))
    };

    let mut selected = BTreeMap::new();
    for record in inventory
        .split(|&byte| byte == 0)
        .filter(|item| !item.is_empty())
    {
        let tab = record
            .iter()
            .position(|&byte| byte == b'\t')
            .context("malformed Git object record")?;
        let Ok(path) = std::str::from_utf8(&record[tab + 1..]) else {
            continue;
        };
        if !paths.contains(path) {
            continue;
        }
        let fields: Vec<_> = std::str::from_utf8(&record[..tab])?
            .split_ascii_whitespace()
            .collect();
        let oid = match (revision, fields.as_slice()) {
            (Some(_), ["100644" | "100755", "blob", oid])
            | (None, ["100644" | "100755", oid, "0"])
                if valid_oid(oid) =>
            {
                Some(*oid)
            }
            _ => None,
        };
        selected
            .entry(path)
            .and_modify(|value| *value = None)
            .or_insert(oid);
    }

    let mut result = Verification {
        expected: Some(paths.len()),
        git_source: Some(git_source),
        ..Verification::default()
    };
    for path in paths {
        let Some(Some(oid)) = selected.get(path.as_str()) else {
            result.fail(path, "expected a single regular Git blob");
            continue;
        };
        let verified =
            git_output(root, &["cat-file", "blob", oid], MAX_WIREFRAME_BYTES).and_then(|wire| {
                let wire =
                    std::str::from_utf8(&wire).context("Git blob is not a UTF-8 wireframe")?;
                parse_and_verify_wireframe(keys, &path, wire)?;
                Ok(())
            });
        match verified {
            Ok(()) => result.verified += 1,
            Err(error) => result.fail(path, error),
        }
    }
    Ok(result)
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn git_output(root: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env_remove("VELLUM_PASSPHRASE")
        .env_remove("VELLUM_KEY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .context("could not start Git")?;
    let output = bounded_read(&mut child.stdout.take().expect("piped Git stdout"), limit);
    if output.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let output = output?;
    if !status.success() {
        return Err(anyhow!("git {} failed ({status})", args[0]));
    }
    Ok(output)
}

fn bounded_read(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("input exceeds {limit} bytes");
    }
    Ok(bytes)
}
