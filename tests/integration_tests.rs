//! Comprehensive cryptographic, chunking, Merkle seal, 3-way merge, vault, and Ratatui
//! TestBackend integration tests for **Vellum** (`vellum v0.1.0`).

#![forbid(unsafe_code)]

use proptest::prelude::*;
use ratatui::{Terminal, backend::TestBackend};
use rusqlite::Connection;
use tempfile::TempDir;

use vellum::chunker::{ChunkMode, chunk_bytes, split_binary_cdc};
use vellum::crypto::{
    RepoMasterKey, aead_decrypt, aead_encrypt, normalize_repo_path, open_convergent_chunk,
    parse_repo_key, seal_convergent_chunk, validate_and_normalize_repo_path, validate_scope_name,
};
use vellum::merge::{merge_encrypted_wireframes, merge_three_way_lines, unified_diff_text};
use vellum::tui::{
    VellumTuiApp,
    ui::{render, sanitize_terminal_str},
};
use vellum::vault::{NewAuditEvent, VellumVault, enforce_vault_and_sidecar_acls};
use vellum::wire::{
    clean_to_wireframe, clean_to_wireframe_allow_conflicts, diff_wireframes_stats,
    is_vellum_wireframe, parse_and_verify_wireframe, smudge_from_wireframe,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_chunker_and_convergent_siv_roundtrip(
        data in proptest::collection::vec(any::<u8>(), 0..6144),
        use_binary in any::<bool>(),
    ) {
        let key = RepoMasterKey::from_bytes([0x3Au8; 32]);
        let subkeys = key.derive_subkeys().unwrap();
        let forced = if use_binary { Some(ChunkMode::BinaryCdc) } else { None };
        let wire = clean_to_wireframe(&subkeys, "research/notes.md", &data, forced).unwrap();
        prop_assert!(is_vellum_wireframe(wire.as_bytes()));

        let restored = smudge_from_wireframe(&subkeys, "research/notes.md", &wire).unwrap();
        prop_assert_eq!(restored.as_slice(), data.as_slice());
    }
}

#[test]
fn test_convergent_delta_preservation_on_single_paragraph_edit() {
    let key = RepoMasterKey::from_bytes([0x5Cu8; 32]);
    let subkeys = key.derive_subkeys().unwrap();

    let mut paras_a = Vec::new();
    for i in 1..=20 {
        paras_a.push(format!(
            "Paragraph {i:02}: Deterministic convergent storage leaves unchanged blocks invariant.\n\n"
        ));
    }
    let doc_a = paras_a.concat();

    let mut paras_b = paras_a.clone();
    paras_b[6] =
        "Paragraph 07: Updated hypothesis with revised experimental thresholds.\n\n".to_string();
    let doc_b = paras_b.concat();

    let wire_a =
        clean_to_wireframe(&subkeys, "manuscript/draft.md", doc_a.as_bytes(), None).unwrap();
    let wire_b =
        clean_to_wireframe(&subkeys, "manuscript/draft.md", doc_b.as_bytes(), None).unwrap();

    let stats = diff_wireframes_stats(&wire_a, &wire_b).unwrap();
    assert_eq!(stats.total_chunks_a, 20);
    assert_eq!(stats.total_chunks_b, 20);
    assert_eq!(stats.unchanged_chunks, 19);
    assert_eq!(stats.changed_chunks_b, 1);
    assert_eq!(stats.reuse_pct, 95);

    let lines_a: Vec<&str> = wire_a.lines().collect();
    let lines_b: Vec<&str> = wire_b.lines().collect();
    let mut matching_chunk_lines = 0usize;
    for idx in 1..=20 {
        if lines_a[idx] == lines_b[idx] {
            matching_chunk_lines += 1;
        }
    }
    assert_eq!(matching_chunk_lines, 19);
}

#[test]
fn test_merkle_seal_rejects_chunk_reordering_deletion_truncation_and_path_swap() {
    let key = RepoMasterKey::from_bytes([0x77u8; 32]);
    let wrong_key = RepoMasterKey::from_bytes([0x88u8; 32]);
    let subkeys = key.derive_subkeys().unwrap();
    let wrong_subkeys = wrong_key.derive_subkeys().unwrap();

    let doc = "First section alpha.\n\nSecond section beta.\n\nThird section gamma.\n\n";
    let wire = clean_to_wireframe(&subkeys, "specs/protocol.md", doc.as_bytes(), None).unwrap();
    let lines: Vec<String> = wire.lines().map(ToString::to_string).collect();
    assert_eq!(lines.len(), 5); // header + 3 chunks + seal

    // 1. Reorder chunks 1 and 2 -> Merkle seal rejects BEFORE decrypt
    let mut reordered = lines.clone();
    reordered.swap(1, 2);
    let reordered_wire = format!("{}\n", reordered.join("\n"));
    assert!(smudge_from_wireframe(&subkeys, "specs/protocol.md", &reordered_wire).is_err());

    // 2. Delete a chunk -> rejected
    let deleted_wire = format!("{}\n{}\n{}\n{}\n", lines[0], lines[1], lines[3], lines[4]);
    assert!(smudge_from_wireframe(&subkeys, "specs/protocol.md", &deleted_wire).is_err());

    // 3. Cross-file transplant onto another path -> rejected
    assert!(smudge_from_wireframe(&subkeys, "specs/other.md", &wire).is_err());

    // 4. Wrong key -> rejected
    assert!(smudge_from_wireframe(&wrong_subkeys, "specs/protocol.md", &wire).is_err());

    // 5. Path normalization parity across Windows backslash and POSIX `./` prefix
    let restored = smudge_from_wireframe(&subkeys, r".\specs\protocol.md", &wire).unwrap();
    assert_eq!(restored.as_slice(), doc.as_bytes());
    assert_eq!(
        normalize_repo_path(r"./specs\protocol.md"),
        "specs/protocol.md"
    );

    // 6. Direct SIV tampering check on single chunk
    let (cid, mut blob) =
        seal_convergent_chunk(&subkeys, "specs/protocol.md", b"hello chunk").unwrap();
    assert!(open_convergent_chunk(&subkeys, "specs/protocol.md", &cid, &blob).is_ok());
    blob[0] ^= 0x01; // flip 1 bit in nonce/SIV
    assert!(open_convergent_chunk(&subkeys, "specs/protocol.md", &cid, &blob).is_err());
}

#[test]
fn test_clean_idempotency_never_double_encrypts() {
    let key = RepoMasterKey::generate();
    let subkeys = key.derive_subkeys().unwrap();
    let doc = "# Heading\n\nBody text.\n";
    let wire1 = clean_to_wireframe(&subkeys, "docs/note.md", doc.as_bytes(), None).unwrap();
    let wire2 = clean_to_wireframe(&subkeys, "docs/note.md", wire1.as_bytes(), None).unwrap();
    assert_eq!(wire1, wire2);
}

#[test]
fn test_in_ram_three_way_merge_clean_and_conflict_detection() {
    let key = RepoMasterKey::from_bytes([0x99u8; 32]);
    let subkeys = key.derive_subkeys().unwrap();
    let rel = "notes/roadmap.md";

    let base = "# Roadmap\n\nSection A: Original line A.\n\nSection B: Original line B.\n\nSection C: Original line C.\n";
    let ours = "# Roadmap\n\nSection A: Updated by branch Alpha.\n\nSection B: Original line B.\n\nSection C: Original line C.\n";
    let theirs = "# Roadmap\n\nSection A: Original line A.\n\nSection B: Original line B.\n\nSection C: Updated by branch Beta.\n";

    let base_w = clean_to_wireframe(&subkeys, rel, base.as_bytes(), None).unwrap();
    let ours_w = clean_to_wireframe(&subkeys, rel, ours.as_bytes(), None).unwrap();
    let theirs_w = clean_to_wireframe(&subkeys, rel, theirs.as_bytes(), None).unwrap();

    let (merged_w, has_conflict) =
        merge_encrypted_wireframes(&subkeys, rel, &base_w, &ours_w, &theirs_w).unwrap();
    assert!(!has_conflict);
    let merged_pt = String::from_utf8(
        smudge_from_wireframe(&subkeys, rel, &merged_w)
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(merged_pt.contains("Updated by branch Alpha."));
    assert!(merged_pt.contains("Updated by branch Beta."));

    // Conflicting edit on the same section
    let ours_conflict = "# Roadmap\n\nSection A: Alpha takes lane 1.\n";
    let theirs_conflict = "# Roadmap\n\nSection A: Beta takes lane 2.\n";
    let base_short = "# Roadmap\n\nSection A: Shared.\n";
    let (conflict_text, conflict_flag) =
        merge_three_way_lines(base_short, ours_conflict, theirs_conflict);
    assert!(conflict_flag);
    assert!(conflict_text.contains("<<<<<<< OURS"));
    assert!(conflict_text.contains(">>>>>>> THEIRS"));

    let diff_str = unified_diff_text("a/notes/roadmap.md", base, "b/notes/roadmap.md", ours);
    assert!(diff_str.contains("-Section A: Original line A."));
    assert!(diff_str.contains("+Section A: Updated by branch Alpha."));
}

#[test]
fn test_binary_gear_cdc_roundtrip_and_shift_resilience() {
    let key = RepoMasterKey::from_bytes([0x44u8; 32]);
    let subkeys = key.derive_subkeys().unwrap();

    // Build deterministic pseudo-random 24 KiB binary buffer containing NUL bytes
    let mut raw = vec![0u8; 24 * 1024];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(131).wrapping_add(i >> 7)) & 0xff) as u8;
    }
    raw[42] = 0;

    let (mode, chunks) = chunk_bytes(&subkeys.cdc_key, &raw, None);
    assert_eq!(mode, ChunkMode::BinaryCdc);
    assert!(chunks.len() >= 3);
    let reassembled: Vec<u8> = chunks.into_iter().flatten().copied().collect();
    assert_eq!(reassembled, raw);

    // Prepend 37 bytes -> Gear-CDC realigns at downstream cut points and preserves trailing chunks!
    let mut shifted = vec![0xABu8; 37];
    shifted.extend_from_slice(&raw);
    let chunks_orig = split_binary_cdc(&subkeys.cdc_key, &raw);
    let chunks_shifted = split_binary_cdc(&subkeys.cdc_key, &shifted);
    assert!(
        chunks_shifted.iter().any(|c| chunks_orig.contains(c)),
        "Gear-CDC should resynchronize and reuse downstream chunks after insertion shift"
    );

    let wire = clean_to_wireframe(&subkeys, "artifacts/weights.bin", &raw, None).unwrap();
    let restored = smudge_from_wireframe(&subkeys, "artifacts/weights.bin", &wire).unwrap();
    assert_eq!(restored.as_slice(), raw.as_slice());
}

#[test]
fn test_vault_encryption_zero_plaintext_on_disk_and_merkle_audit_tamper() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("vault").join("vellum.db");
    let passphrase = b"vellum-vault-passphrase-99";

    let mut vault = VellumVault::open_with_passphrase(&db_path, passphrase, true).unwrap();
    let scope_key = vault.ensure_scope_key("research-enclave").unwrap();
    let parsed_back = parse_repo_key(&scope_key.encode_key_b64()).unwrap();
    assert_eq!(scope_key.0, parsed_back.0);

    vault
        .append_audit_event(NewAuditEvent {
            operation: "clean".to_string(),
            scope: "research-enclave".to_string(),
            rel_path: "classified/kernel-notes.md".to_string(),
            total_chunks: 12,
            unchanged_chunks: 11,
            seal_short: "abcdef0123456789".to_string(),
        })
        .unwrap();
    vault
        .append_audit_event(NewAuditEvent {
            operation: "merge-clean".to_string(),
            scope: "research-enclave".to_string(),
            rel_path: "classified/kernel-notes.md".to_string(),
            total_chunks: 13,
            unchanged_chunks: 11,
            seal_short: "9876543210fedcba".to_string(),
        })
        .unwrap();

    let report = vault.verify_audit_chain().unwrap();
    assert!(report.valid);
    assert_eq!(report.total_entries, 2);
    enforce_vault_and_sidecar_acls(&db_path).unwrap();
    drop(vault);

    // Zero plaintext repo paths or scope names in raw DB file
    let raw_db = std::fs::read(&db_path).unwrap();
    let raw_lossy = String::from_utf8_lossy(&raw_db);
    assert!(!raw_lossy.contains("classified/kernel-notes.md"));
    assert!(!raw_lossy.contains("research-enclave"));
    assert!(!raw_lossy.contains("vellum-key-v1:"));

    // Wrong passphrase rejected fail-closed
    assert!(VellumVault::open_with_passphrase(&db_path, b"wrong-pass", true).is_err());

    // Tampering 1 field in SQLite breaks Merkle verification
    {
        let raw_conn = Connection::open(&db_path).unwrap();
        raw_conn
            .execute(
                "UPDATE seal_audit_log SET operation = 'tampered' WHERE seq = 1",
                [],
            )
            .unwrap();
    }
    let reopened = VellumVault::open_with_passphrase(&db_path, passphrase, true).unwrap();
    assert!(reopened.verify_audit_chain().is_err());
}

#[test]
fn test_verify_tree_wireframe_validation_and_empty_file_support() {
    let key = RepoMasterKey::generate();
    let subkeys = key.derive_subkeys().unwrap();

    let empty_wire = clean_to_wireframe(&subkeys, "empty.txt", b"", None).unwrap();
    let parsed = parse_and_verify_wireframe(&subkeys, "empty.txt", &empty_wire).unwrap();
    assert_eq!(parsed.chunks.len(), 0);
    let restored = smudge_from_wireframe(&subkeys, "empty.txt", &empty_wire).unwrap();
    assert!(restored.is_empty());
}

#[test]
fn test_ratatui_test_backend_snapshot_and_cwe150_ansi_sanitization() {
    let poisoned_path = "docs/evil\x1b[31mESCAPE\x07\x1b]0;title\x07.md";
    let clean = sanitize_terminal_str(poisoned_path);
    assert!(!clean.contains('\x1b'));
    assert!(!clean.contains('\x07'));

    let mut vault = VellumVault::open_in_memory_for_test(b"tui-pass").unwrap();
    let _ = vault.ensure_scope_key("default").unwrap();
    vault
        .append_audit_event(NewAuditEvent {
            operation: "clean".to_string(),
            scope: "default".to_string(),
            rel_path: poisoned_path.to_string(),
            total_chunks: 4,
            unchanged_chunks: 3,
            seal_short: "deadbeef12345678".to_string(),
        })
        .unwrap();

    let mut app = VellumTuiApp::new(
        ":memory:".to_string(),
        vault.list_scopes().unwrap(),
        vault.list_audit_entries(20).unwrap(),
        vault.verify_audit_chain().unwrap(),
        poisoned_path.to_string(),
        4,
        "0123456789abcdef".to_string(),
        vec!["aaaa1111bbbb2222".to_string()],
    );
    app.next_pane();
    app.next_pane();
    app.prev_pane();
    app.prev_pane();

    let backend = TestBackend::new(120, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();

    let rendered: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(rendered.contains("VELLUM v0.1.0"));
    assert!(rendered.contains("MERKLE AUDIT: VERIFIED"));
    assert!(rendered.contains("SCOPED REPOSITORY KEYS"));
    assert!(rendered.contains("WIREFRAME CHUNK & MERKLE SEAL INSPECTOR"));
    assert!(rendered.contains("BLAKE3 MERKLE FILTER & MERGE AUDIT LOG"));
    assert!(!rendered.contains('\x1b'));
}

#[test]
fn test_tier5_red_team_hardening_invariants() {
    let key = RepoMasterKey::from_bytes([0x55u8; 32]);
    let subkeys = key.derive_subkeys().unwrap();

    // [RT-VEL-01] Unauthenticated chunks allocation bomb rejected pre-seal
    let malicious_wire = "@vellum:header:v1 path_mac=0000000000000000 mode=text chunks=999999999\n@vellum:seal:v1 00\n";
    let err = parse_and_verify_wireframe(&subkeys, "docs/spec.md", malicious_wire)
        .unwrap_err()
        .to_string();
    assert!(err.contains("MAX_WIREFRAME_CHUNKS"));

    // [RT-VEL-01] 5,000-line 3-way merge executes in linear time via prefix/suffix trimming
    let mut base_lines = Vec::with_capacity(5000);
    for i in 0..5000 {
        base_lines.push(format!("line {i:04}: steady unchanged invariant text\n"));
    }
    let mut ours_lines = base_lines.clone();
    let mut theirs_lines = base_lines.clone();
    ours_lines[100] = "line 0100: alpha branch patch\n".to_string();
    theirs_lines[4900] = "line 4900: beta branch patch\n".to_string();
    let (merged, has_conflict) = merge_three_way_lines(
        &base_lines.concat(),
        &ours_lines.concat(),
        &theirs_lines.concat(),
    );
    assert!(!has_conflict);
    assert!(merged.contains("alpha branch patch"));
    assert!(merged.contains("beta branch patch"));

    // [RT-VEL-02] Git config & CLI scope injection blocked
    assert!(validate_scope_name("default\n    clean = calc.exe").is_err());
    assert!(validate_scope_name("prod; rm -rf /").is_err());
    assert!(validate_scope_name("-flag").is_err());
    assert!(validate_scope_name("prod_2026-main").is_ok());

    let mut vault = VellumVault::open_in_memory_for_test(b"red-team-pass").unwrap();
    assert!(vault.ensure_scope_key("bad scope; id").is_err());
    let sk = vault.ensure_scope_key("prod_2026-main").unwrap();
    let fp = vault.scope_fingerprint(&sk);
    assert_eq!(fp.len(), 12);

    // [RT-VEL-03] Path traversal & colon rejection + deterministic collapsing
    assert!(validate_and_normalize_repo_path("../secrets.txt").is_err());
    assert!(validate_and_normalize_repo_path("docs/../../etc/passwd").is_err());
    assert!(validate_and_normalize_repo_path("C:secret.md").is_err());
    assert!(validate_and_normalize_repo_path("bad\0path.md").is_err());
    assert_eq!(
        validate_and_normalize_repo_path(r".\docs//./arch.md").unwrap(),
        "docs/arch.md"
    );

    // [RT-VEL-04] AEAD decrypt & key encoder return Zeroizing wrappers
    let k = [0xAAu8; 32];
    let ct = aead_encrypt(&k, b"aad", b"top-secret").unwrap();
    let pt: zeroize::Zeroizing<Vec<u8>> = aead_decrypt(&k, b"aad", &ct).unwrap();
    assert_eq!(pt.as_slice(), b"top-secret");
    let encoded: zeroize::Zeroizing<String> = key.encode_key_b64();
    assert!(encoded.starts_with("vellum-key-v1:"));

    // [RT-VEL-05] Unresolved conflict markers rejected on regular clean, permitted on merge driver
    let conflicted = "<<<<<<< OURS\nalpha\n=======\nbeta\n>>>>>>> THEIRS\n";
    assert!(clean_to_wireframe(&subkeys, "docs/spec.md", conflicted.as_bytes(), None).is_err());
    assert!(
        clean_to_wireframe_allow_conflicts(&subkeys, "docs/spec.md", conflicted.as_bytes(), None)
            .is_ok()
    );
}
