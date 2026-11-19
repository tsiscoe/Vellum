//! `VELLUM-WIRE-V1` serializer, Merkle file seal verifier, smudge decryptor & delta stats
//! (`#![forbid(unsafe_code)]`).

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::chunker::{ChunkMode, chunk_bytes};
use crate::crypto::{
    RepoSubkeys, constant_time_eq_slice, keyed_blake3_hex, open_convergent_chunk,
    seal_convergent_chunk, validate_and_normalize_repo_path,
};

const HEADER_PREFIX: &str = "@vellum:header:v1 ";
const CHUNK_PREFIX: &str = "@vellum:chunk:v1 ";
const SEAL_PREFIX: &str = "@vellum:seal:v1 ";

/// Maximum number of chunks permitted in a single `VELLUM-WIRE-V1` document before aborting pre-seal.
pub const MAX_WIREFRAME_CHUNKS: usize = 65_536;
/// Maximum input/wireframe size (`32 MiB`) permitted to prevent heap exhaustion (`CWE-400`).
pub const MAX_WIREFRAME_BYTES: usize = 32 * 1024 * 1024;

/// Detect unresolved 3-way Git merge conflict marker triplets in UTF-8 plaintext.
pub fn contains_conflict_markers(raw: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(raw) else {
        return false;
    };
    let mut has_ours = false;
    let mut has_sep = false;
    let mut has_theirs = false;
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with("<<<<<<< ") {
            has_ours = true;
        } else if has_ours && line == "=======" {
            has_sep = true;
        } else if has_ours && has_sep && line.starts_with(">>>>>>> ") {
            has_theirs = true;
            break;
        }
    }
    has_ours && has_sep && has_theirs
}

/// Parsed and Merkle-verified wireframe components.
#[derive(Debug, Clone)]
pub struct ParsedWireframe {
    pub norm_path: String,
    pub path_mac: String,
    pub mode: ChunkMode,
    pub chunks: Vec<(String, Vec<u8>)>,
    pub seal_hex: String,
}

/// Chunk-level delta reuse telemetry comparing two `VELLUM-WIRE-V1` revisions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireDiffStats {
    pub total_chunks_a: usize,
    pub total_chunks_b: usize,
    pub unchanged_chunks: usize,
    pub changed_chunks_b: usize,
    pub reuse_pct: usize,
}

/// Quick structural check to make `vellum clean` idempotent on already-sealed wireframes.
pub fn is_vellum_wireframe(data: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(data) else {
        return false;
    };
    let mut lines = s.lines();
    let Some(first) = lines.next() else {
        return false;
    };
    let Some(last) = s.lines().last() else {
        return false;
    };
    first.starts_with(HEADER_PREFIX) && last.starts_with(SEAL_PREFIX)
}

fn compute_path_mac(seal_key: &[u8; 32], norm_path: &str) -> String {
    keyed_blake3_hex(seal_key, "vellum-v1-path-mac", norm_path.as_bytes())[..16].to_string()
}

fn compute_file_seal(
    seal_key: &[u8; 32],
    norm_path: &str,
    mode: ChunkMode,
    chunk_entries: &[(String, Vec<u8>)],
) -> String {
    let mut manifest = format!(
        "vellum-v1|seal|{norm_path}|{}|{}|",
        mode.as_str(),
        chunk_entries.len()
    );
    for (chunk_id, blob) in chunk_entries {
        let blob_digest = blake3::hash(blob).to_hex();
        manifest.push_str(chunk_id);
        manifest.push(':');
        manifest.push_str(&blob_digest);
        manifest.push(';');
    }
    keyed_blake3_hex(seal_key, "vellum-v1-file-seal", manifest.as_bytes())
}

/// Encrypt raw file bytes into a deterministic, Merkle-sealed `VELLUM-WIRE-V1` text wireframe.
///
/// Idempotent: if `raw` is already a valid `VELLUM-WIRE-V1` document for `rel_path`, it verifies
/// the Merkle seal and returns it unchanged rather than double-encrypting. Refuses unresolved
/// Git merge conflict markers unless invoked via [`clean_to_wireframe_allow_conflicts`].
pub fn clean_to_wireframe(
    subkeys: &RepoSubkeys,
    rel_path: &str,
    raw: &[u8],
    forced_mode: Option<ChunkMode>,
) -> Result<String> {
    clean_to_wireframe_inner(subkeys, rel_path, raw, forced_mode, false)
}

/// Variant of [`clean_to_wireframe`] used strictly by the 3-way merge driver to re-seal an
/// intentional conflicted merge result back into `VELLUM-WIRE-V1`.
pub fn clean_to_wireframe_allow_conflicts(
    subkeys: &RepoSubkeys,
    rel_path: &str,
    raw: &[u8],
    forced_mode: Option<ChunkMode>,
) -> Result<String> {
    clean_to_wireframe_inner(subkeys, rel_path, raw, forced_mode, true)
}

fn clean_to_wireframe_inner(
    subkeys: &RepoSubkeys,
    rel_path: &str,
    raw: &[u8],
    forced_mode: Option<ChunkMode>,
    allow_conflicts: bool,
) -> Result<String> {
    if raw.len() > MAX_WIREFRAME_BYTES {
        return Err(anyhow!(
            "input exceeds Vellum 32 MiB ceiling ({} > {} bytes)",
            raw.len(),
            MAX_WIREFRAME_BYTES
        ));
    }
    let norm_path = validate_and_normalize_repo_path(rel_path)?;

    if is_vellum_wireframe(raw) {
        let s = std::str::from_utf8(raw)?;
        let _verified = parse_and_verify_wireframe(subkeys, &norm_path, s)?;
        return Ok(s.to_string());
    }

    if !allow_conflicts && contains_conflict_markers(raw) {
        return Err(anyhow!(
            "refusing to encrypt unresolved Git merge conflict markers on '{norm_path}'"
        ));
    }

    let (mode, parts) = chunk_bytes(&subkeys.cdc_key, raw, forced_mode);
    if parts.len() > MAX_WIREFRAME_CHUNKS {
        return Err(anyhow!(
            "chunk count {} exceeds MAX_WIREFRAME_CHUNKS ({MAX_WIREFRAME_CHUNKS})",
            parts.len()
        ));
    }

    let mut chunk_entries = Vec::with_capacity(parts.len());
    for part in parts {
        let (chunk_id, blob) = seal_convergent_chunk(subkeys, &norm_path, part)?;
        chunk_entries.push((chunk_id, blob));
    }

    let path_mac = compute_path_mac(&subkeys.seal_key, &norm_path);
    let seal_hex = compute_file_seal(&subkeys.seal_key, &norm_path, mode, &chunk_entries);

    let mut out = String::with_capacity(256 + raw.len() * 2);
    out.push_str(&format!(
        "{HEADER_PREFIX}path_mac={path_mac} mode={} chunks={}\n",
        mode.as_str(),
        chunk_entries.len()
    ));
    for (chunk_id, blob) in chunk_entries {
        let b64 = BASE64_URL.encode(&blob);
        out.push_str(&format!("{CHUNK_PREFIX}{chunk_id} {b64}\n"));
    }
    out.push_str(&format!("{SEAL_PREFIX}{seal_hex}\n"));
    Ok(out)
}

/// Parse a `VELLUM-WIRE-V1` wireframe and verify its path MAC and Merkle file seal BEFORE any
/// decryption occurs.
pub fn parse_and_verify_wireframe(
    subkeys: &RepoSubkeys,
    rel_path: &str,
    wire: &str,
) -> Result<ParsedWireframe> {
    if wire.len() > MAX_WIREFRAME_BYTES {
        return Err(anyhow!(
            "wireframe exceeds Vellum 32 MiB ceiling ({} > {} bytes)",
            wire.len(),
            MAX_WIREFRAME_BYTES
        ));
    }
    let norm_path = validate_and_normalize_repo_path(rel_path)?;
    let mut lines = wire.lines();

    let header_line = lines
        .next()
        .ok_or_else(|| anyhow!("empty Vellum wireframe"))?;
    let header_rest = header_line
        .strip_prefix(HEADER_PREFIX)
        .ok_or_else(|| anyhow!("missing @vellum:header:v1 banner"))?;

    let mut path_mac: Option<&str> = None;
    let mut mode: Option<ChunkMode> = None;
    let mut declared_chunks: Option<usize> = None;

    for token in header_rest.split_whitespace() {
        if let Some(v) = token.strip_prefix("path_mac=") {
            path_mac = Some(v);
        } else if let Some(v) = token.strip_prefix("mode=") {
            mode = ChunkMode::parse(v);
        } else if let Some(v) = token.strip_prefix("chunks=") {
            declared_chunks = Some(
                v.parse::<usize>()
                    .map_err(|_| anyhow!("invalid chunk count in wireframe header"))?,
            );
        }
    }

    let path_mac = path_mac.ok_or_else(|| anyhow!("missing path_mac in wireframe header"))?;
    let mode = mode.ok_or_else(|| anyhow!("invalid or missing mode in wireframe header"))?;
    let declared_chunks =
        declared_chunks.ok_or_else(|| anyhow!("missing chunks count in wireframe header"))?;

    if declared_chunks > MAX_WIREFRAME_CHUNKS {
        return Err(anyhow!(
            "wireframe header declares {declared_chunks} chunks exceeding MAX_WIREFRAME_CHUNKS ({MAX_WIREFRAME_CHUNKS})"
        ));
    }

    let expected_mac = compute_path_mac(&subkeys.seal_key, &norm_path);
    if !constant_time_eq_slice(path_mac.as_bytes(), expected_mac.as_bytes()) {
        return Err(anyhow!(
            "wireframe path MAC mismatch: refusing cross-file transplant onto '{norm_path}'"
        ));
    }

    let mut chunk_entries = Vec::with_capacity(declared_chunks.min(1024));
    let mut seal_hex: Option<String> = None;

    for line in lines {
        if seal_hex.is_some() {
            return Err(anyhow!("unexpected trailing content after @vellum:seal:v1"));
        }
        if let Some(rest) = line.strip_prefix(CHUNK_PREFIX) {
            if chunk_entries.len() >= MAX_WIREFRAME_CHUNKS {
                return Err(anyhow!(
                    "chunk entries exceed MAX_WIREFRAME_CHUNKS ({MAX_WIREFRAME_CHUNKS})"
                ));
            }
            let mut parts = rest.split_whitespace();
            let chunk_id = parts
                .next()
                .ok_or_else(|| anyhow!("missing chunk_id in @vellum:chunk:v1"))?;
            let b64 = parts
                .next()
                .ok_or_else(|| anyhow!("missing base64 payload in @vellum:chunk:v1"))?;
            if parts.next().is_some() {
                return Err(anyhow!("malformed extra tokens in @vellum:chunk:v1"));
            }
            let blob = BASE64_URL
                .decode(b64)
                .map_err(|e| anyhow!("invalid Base64URL chunk payload: {e}"))?;
            chunk_entries.push((chunk_id.to_string(), blob));
        } else if let Some(rest) = line.strip_prefix(SEAL_PREFIX) {
            seal_hex = Some(rest.trim().to_string());
        } else if !line.trim().is_empty() {
            return Err(anyhow!("unexpected line in Vellum wireframe: '{line}'"));
        }
    }

    let seal_hex = seal_hex.ok_or_else(|| anyhow!("missing @vellum:seal:v1 footer"))?;
    if chunk_entries.len() != declared_chunks {
        return Err(anyhow!(
            "chunk count mismatch: header declared {declared_chunks}, found {}",
            chunk_entries.len()
        ));
    }

    let expected_seal = compute_file_seal(&subkeys.seal_key, &norm_path, mode, &chunk_entries);
    if !constant_time_eq_slice(seal_hex.as_bytes(), expected_seal.as_bytes()) {
        return Err(anyhow!(
            "Merkle file seal verification failed on '{norm_path}' (tampered, reordered, or wrong key)"
        ));
    }

    Ok(ParsedWireframe {
        norm_path,
        path_mac: path_mac.to_string(),
        mode,
        chunks: chunk_entries,
        seal_hex,
    })
}

/// Verify the Merkle seal and decrypt all chunks back into exact plaintext bytes in `Zeroizing` RAM.
pub fn smudge_from_wireframe(
    subkeys: &RepoSubkeys,
    rel_path: &str,
    wire: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let parsed = parse_and_verify_wireframe(subkeys, rel_path, wire)?;
    let mut out = Zeroizing::new(Vec::new());
    for (chunk_id, blob) in &parsed.chunks {
        let pt = open_convergent_chunk(subkeys, &parsed.norm_path, chunk_id, blob)?;
        out.extend_from_slice(&pt);
    }
    Ok(out)
}

/// Parse chunk IDs without requiring keys so structural chunk reuse can be inspected quickly.
fn extract_chunk_ids(wire: &str) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    for line in wire.lines() {
        if let Some(rest) = line.strip_prefix(CHUNK_PREFIX)
            && let Some(id) = rest.split_whitespace().next()
        {
            ids.push(id.to_string());
        }
    }
    Ok(ids)
}

/// Measure chunk-level convergence/reuse between two `VELLUM-WIRE-V1` snapshots.
pub fn diff_wireframes_stats(wire_a: &str, wire_b: &str) -> Result<WireDiffStats> {
    let ids_a = extract_chunk_ids(wire_a)?;
    let ids_b = extract_chunk_ids(wire_b)?;

    let mut counts_a: HashMap<String, usize> = HashMap::new();
    for id in &ids_a {
        *counts_a.entry(id.clone()).or_insert(0) += 1;
    }

    let mut unchanged = 0usize;
    for id in &ids_b {
        if let Some(cnt) = counts_a.get_mut(id)
            && *cnt > 0
        {
            *cnt -= 1;
            unchanged += 1;
        }
    }

    let total_b = ids_b.len();
    let changed_b = total_b.saturating_sub(unchanged);
    let reuse_pct = (unchanged * 100).checked_div(total_b).unwrap_or(100);

    Ok(WireDiffStats {
        total_chunks_a: ids_a.len(),
        total_chunks_b: total_b,
        unchanged_chunks: unchanged,
        changed_chunks_b: changed_b,
        reuse_pct,
    })
}
