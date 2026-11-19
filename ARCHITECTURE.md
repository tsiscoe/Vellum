# Vellum Architecture (`vellum` v0.1.0)

> Or: how to let Git diff and merge encrypted files without handing your plaintext to a cloud host or an angry binary merge conflict.

---

## 1. Why Conventional Encrypted Git Tools Break

Standard Git encryption wrappers fall into one of two equally depressing ditches:

1. **Monolithic File Ciphers (`git-crypt`, full-file `age`):** Random nonces mean editing a single character anywhere in a file changes 100% of the ciphertext bytes. Git sees an opaque binary rewrite every commit, repo history balloons, and two branches editing paragraphs 2 and 48 collide into a hopeless binary merge conflict.
2. **Naive Block-by-Block Convergent Encryption Without a File Seal:** Encrypting blocks deterministically gives you chunk reuse, right up until somebody realizes they can swap chunks 3 and 7, drop the paragraph containing your safety caveat, or paste a ciphertext line from another file into yours—and your decryptor cheerfully hands back Frankensteined nonsense.

**Vellum** fixes both halves: **chunk-level `BLAKE3-XChaCha20-SIV`** restores Git delta efficiency and 3-way merging, while a **full-file keyed `BLAKE3` Merkle seal** locks chunk ordering, count, and repository path before any chunk gets decrypted.

---

## 2. Key Hierarchy & Convergent SIV (`src/crypto/mod.rs`)

Each repository scope holds a 256-bit `RepoMasterKey`, expanded via `HKDF-SHA256` (`salt = "vellum-repo-salt-v1"`) into four domain-separated subkeys:

- `cdc_key` (`vellum-v1-cdc-key`): Seeds the 256-entry 64-bit Gear rolling-hash table so binary chunk cut points aren't predictable without the repo key.
- `siv_key` (`vellum-v1-siv-key`): Computes the synthetic IV (`siv = BLAKE3_K_siv("vellum-v1-chunk-siv|" || len(path) || path || chunk)`), yielding the 24-byte deterministic `XNonce` and 16-hex `chunk_id`.
- `enc_key` (`vellum-v1-enc-key`): Derives a per-chunk encryption key `BLAKE3_K_enc("vellum-v1-chunk-key|" || len(path) || path || nonce24)` for `XChaCha20-Poly1305` (`AAD = "vellum-v1|chunk|" || path`).
- `seal_key` (`vellum-v1-seal-key`): Computes `@vellum:header` `path_mac` and the file-wide `@vellum:seal:v1` authentication digest.

**True SIV Verification:** On decryption (`open_convergent_chunk`), Vellum doesn't blindly trust the Poly1305 check alone—it re-evaluates `compute_chunk_siv` on the decrypted plaintext and enforces in constant time (`CWE-208`) that `siv[0..24]` matches the wire nonce and `chunk_id` matches `siv[0..8]`.

---

## 3. Chunker & `VELLUM-WIRE-V1` Format (`src/chunker/`, `src/wire/`)

```text
@vellum:header:v1 path_mac=<16hex> mode=<text|cdc> chunks=<N>
@vellum:chunk:v1 <chunk_id_16hex> <base64url(nonce24 || ct_and_tag)>
...
@vellum:seal:v1 <keyed_blake3_64hex>
```

- **`TextBlocks` (`src/chunker/mod.rs`):** Splits valid UTF-8 (without NUL bytes) on blank lines, Markdown headings (`# `..`#### `), soft 4 KiB limits, and hard 8 KiB limits while preserving exact `\n` / `\r\n` bytes. Editing one paragraph in a 20-paragraph document keeps the other 19 `@vellum:chunk:v1` lines byte-for-byte identical.
- **`BinaryCdc`:** Uses a keyed 64-bit Gear table (`1 KiB` min, `8 KiB` max, `0x0fff` mask) so inserting bytes near the start of a binary artifact still lets downstream blocks resynchronize.
- **Anti-Transplant & Anti-Reorder Guard (`parse_and_verify_wireframe`):** Checks `path_mac`, line count, and `@vellum:seal:v1` (committing to `norm_path`, `mode`, `chunks.len()`, and the ordered sequence of `(chunk_id, blake3(blob))`) before decrypting a single chunk.
- **Idempotency:** Passing an already-sealed `VELLUM-WIRE-V1` blob back into `clean_to_wireframe` verifies its seal and returns it verbatim rather than double-encrypting.

---

## 4. Zero-Disk In-RAM 3-Way Merge (`src/merge/mod.rs`)

When Git encounters divergent encrypted commits on `Ours` (`%A`) and `Theirs` (`%B`) against common ancestor `Base` (`%O`):

1. `merge_encrypted_wireframes` verifies and decrypts all three files into `Zeroizing` memory buffers.
2. `merge_three_way_lines` builds Longest Common Subsequence (`LCS`) edit hunks for `(Base, Ours)` and `(Base, Theirs)`, merges overlapping edit clusters, resolves non-overlapping edits cleanly, and wraps colliding edits in standard `<<<<<<< OURS` / `>>>>>>> THEIRS` conflict markers (`exit(1)` on conflict, `exit(0)` on clean merge).
3. The merged buffer is immediately re-encrypted and Merkle-sealed via `clean_to_wireframe` before touching `--out` / `%A`.

---

## 5. Encrypted Custody Vault (`src/vault/mod.rs`)

- Uses bundled `rusqlite 0.42.0` in WAL mode with `PRAGMA secure_delete = ON` and `BEGIN IMMEDIATE` serialization (`CWE-362`).
- Encrypts scoped `RepoMasterKey` entries (`repo_scopes`) and `seal_audit_log` payloads (`scope`, `rel_path`, `total_chunks`, `unchanged_chunks`, `seal_short`) using `Argon2id` (`64 MiB, t=3, p=4`) + `XChaCha20-Poly1305` so zero file paths sit in plaintext inside `vellum.db`.
- Links audit records into a `BLAKE3` chain. Vault-backed operations write intent before output and write an outcome after output. A separately retained checkpoint lets verification detect loss of history through the checkpoint.
- Verifies owner-only permissions on the dedicated vault directory and managed files. Export builds a protected file before writing the key and publishes it without clobbering an existing path.

---

## 6. Known Limits (Because Pretending Otherwise Is How Breaches Happen)

- **Convergent chunking reveals equality of identical blocks at identical paths.** That's the price of `95%` Git diff convergence: if an adversary with read access to your Git remote already knows you haven't touched paragraph 3, they can confirm paragraph 3's ciphertext didn't change—and if two files share identical plaintexts at different `rel_path`s, domain-separating every SIV by `norm_path` guarantees cross-file ciphertexts never collide.
- **Line-level 3-way merge requires UTF-8 text.** Binary CDC files decrypt and roundtrip cleanly under `clean`/`smudge`, but `vellum merge` refuses binary inputs rather than stuffing conflict markers into a compiled ELF or SQLite blob.
