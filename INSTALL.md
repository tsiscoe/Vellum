# Installing Vellum

Compiling Vellum takes two minutes; reconstructing a mangled research manuscript after `git-crypt` loses a binary merge conflict takes the rest of the weekend.

## Prerequisites

- **Rust `1.99.1`** as used by CI, via [rustup.rs](https://rustup.rs/).
- **Supported platforms:**
  - Windows 10 / 11 (`x86_64-pc-windows-msvc`)
  - Linux (`x86_64-unknown-linux-gnu`)
  - macOS 13+ (`aarch64-apple-darwin` & `x86_64-apple-darwin`)

`rusqlite` bundles SQLite from source, so no system SQLite or OpenSSL libraries are needed.

## Build from Source

```bash
git clone https://github.com/tsiscoe/Vellum.git
cd Vellum
cargo build --locked --release
```

Install the `vellum` binary onto your `PATH`:

```bash
cargo install --locked --path .
```

## Environment Variables

| Variable | What It Does | Default |
| :--- | :--- | :--- |
| `VELLUM_VAULT` | Path to encrypted SQLite WAL custody vault. | `~/.config/vellum/vellum.db` (`%APPDATA%\vellum\vellum.db` on Windows) |
| `VELLUM_PASSPHRASE` | Master vault passphrase for headless CI pipelines. | Interactive prompt, or OS keyring with `--keyring` |
| `VELLUM_KEY` | Raw `vellum-key-v1:...` key or `.key` file path for vaultless Git filter execution. | Loaded from unlocked vault if omitted |

## Verify & Wire Into Git

```bash
vellum --version
vellum --keyring init --scope default
vellum --keyring git-config --scope default
```

Paste the printed filter and merge stanzas into `.gitattributes` and `.git/config` before staging protected files. Each clone needs its own driver configuration. Remove the earlier Vellum textconv stanza and use `vellum diff --path` for plaintext comparisons.

Keep the vault in a dedicated owner-only directory. A new vault creates that directory. If the directory already exists, Vellum checks its permissions before opening the vault. To adopt an existing vault on Windows, use a dedicated directory with a protected DACL granting the current owner full control and inheritance to files and subdirectories. On Unix the directory needs mode `0700`. Back up the closed vault before moving it. To migrate from the old shared keyring entry or rebind a moved vault, supply its passphrase to `vellum --keyring init`.

If you need `--export-key`, choose a new destination outside the worktree under a directory you control. It creates an owner-only file and refuses an existing destination. Pass the path as `VELLUM_KEY` for intentional vaultless operation.

### Verify the Git objects before publishing

Maintain a trusted JSON array of the exact protected Git paths outside the branch being checked. For example, the manifest can contain `["secret_notes/research.md"]`.

```bash
vellum --keyring --json verify-tree --staged --manifest /trusted/protected-paths.json
vellum --keyring --json verify-tree --revision HEAD --manifest /trusted/protected-paths.json
```

The staged check reads the index. The revision check resolves and reads a Git tree. Require all expected paths to verify before allowing publication. Keep authority over the manifest and keys with the verification operator. Vaultless key holders can verify and seal objects under that key.

Use canonical UTF-8 Git paths with `/` separators. V1 blobs for canonical names remain readable. To recover older content sealed using a path alias, decrypt under its former canonical label on a trusted host, then re-seal at the chosen supported Git path. After moving a decrypted worktree file, run `git add --renormalize -- NEW_PATH` and verify the new index against the revised manifest.

The upgraded vault reads existing V1 scope rows and authenticates their decrypted scope. Newly created scope rows use a stronger binding and require the upgraded reader. Keep the original keys and a verified backup until migration and recovery have been exercised. Rerunning `init` returns the existing scope key.

Vault-backed clean, smudge, merge and plaintext comparisons record durable intent and outcome rows. An intent without an outcome calls for reconciliation of the actual output. Direct key mode has no vault audit. Retain the audit checkpoint outside the vault in your trusted evidence store.

```bash
vellum --keyring --json audit-verify
vellum --keyring --json audit-verify --anchor-count COUNT --anchor-head HASH
```
