# Changelog

All notable changes to **Vellum** (`vellum`) live here.

## [0.1.0] - 2026-11-18

Initial release: encrypted Git repositories that stop acting like unmergeable binary bricks.

### Added
- **Convergent `BLAKE3-XChaCha20-SIV` Engine (`src/crypto/mod.rs`).** `RepoMasterKey` + `HKDF-SHA256` expansion (`cdc_key`, `siv_key`, `enc_key`, `seal_key`), path-normalized synthetic IVs, per-chunk encryption keys, and constant-time plaintext SIV re-verification (`CWE-208`, `Zeroizing`).
- **TextBlocks & Keyed Gear-CDC Chunker (`src/chunker/mod.rs`).** Structure-aware Markdown/prose/code paragraph splitting alongside a `BLAKE3 XOF`-keyed 64-bit Gear rolling-hash binary chunker guaranteeing lossless byte roundtrips.
- **`VELLUM-WIRE-V1` & Merkle File Seal (`src/wire/mod.rs`).** Ordered chunk serialization, header `path_mac`, full-file `@vellum:seal:v1` authentication defeating reordering/deletion/cross-file swaps, idempotent `clean`, and `diff_wireframes_stats`.
- **Zero-Disk In-RAM 3-Way Merge Driver (`src/merge/mod.rs`).** LCS 3-way line merger over decrypted `Zeroizing` wireframes with clean non-overlapping merges, Git conflict markers, and unified `textconv` diffing.
- **Encrypted Vault, CLI & 3-Pane `Ratatui` TUI (`src/vault/`, `src/cli.rs`, `src/main.rs`, `src/tui/`).** `Argon2id` + `XChaCha20-Poly1305` SQLite WAL vault (`rusqlite 0.42.0`, `BEGIN IMMEDIATE`, `PRAGMA secure_delete = ON`, fail-closed `icacls` / `0600`), `BLAKE3`-chained encrypted `seal_audit_log`, full CLI (`init`, `clean`, `smudge`, `merge`, `diff`, `textconv`, `verify-tree`, `git-config`, `tui`), and `CWE-150` ANSI-sanitized `Ratatui v0.30` dashboard.
- **CI & Verification Suite.** Cross-platform GitHub Actions workflow (`.github/workflows/ci.yml`) and 9 unit/integration/`proptest!` suites.
