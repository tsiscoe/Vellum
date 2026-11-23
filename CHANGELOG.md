# Changelog

Everything that changed in **Vellum**, written so you don't need a decoder ring to read the release notes.

## [0.1.0] - 2026-11-22

Initial public release after two rounds of adversarial red-team vetting: Git file encryption that stops treating every typo fix like a full-file binary demolition derby.

### What's In the Box
- **Paragraph-by-Paragraph Encryption (`src/crypto/`, `src/chunker/`):** Splits text documents cleanly on paragraphs and headings (and binary files with a secret-keyed rolling slicer) so editing one paragraph leaves the other 95% of the encrypted file untouched in `git diff`.
- **Tamper-Proof File Seals (`src/wire/`):** Stamps every encrypted file with a keyed `BLAKE3` seal locking its exact file path, chunk count, and paragraph order—stopping cut-and-paste, deletion, and file-swap attacks cold before decryption even starts.
- **Zero-Disk In-RAM 3-Way Git Merges (`src/merge/`):** Unlocks divergent branches inside self-wiping RAM, merges non-overlapping edits cleanly, flags genuine line collisions with normal Git conflict markers, and re-seals the result without dropping plaintext temp files onto your drive.
- **Locked-Down Local Key Vault & TUI (`src/vault/`, `src/tui/`):** Stores scoped repo keys and a hash-chained encrypted audit log inside an owner-only SQLite vault (`Argon2id` + `XChaCha20-Poly1305`), paired with an ANSI-scrubbed 3-pane `Ratatui` terminal inspector.
- **Two-Pass Red-Team Hardening:** Bolted down pre-seal memory caps against fake-header bombs, bounded 3-way merge memory on giant files, locked scope names against `.git/config` command injection, blocked symlink and `..` path escapes, wiped decrypted buffers on drop, hid raw keys from terminal output unless `--reveal` is passed, and added real Git index/revision manifest verification (`verify-tree --staged` / `--revision`) plus external audit checkpoints (`audit-verify`).
