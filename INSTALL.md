# Installing Vellum

Compiling Vellum takes two minutes; reconstructing a mangled research manuscript after `git-crypt` loses a binary merge conflict takes the rest of the weekend.

## Prerequisites

- **Rust `1.85+`** (2024 Edition) via [rustup.rs](https://rustup.rs/).
- **Supported platforms:**
  - Windows 10 / 11 (`x86_64-pc-windows-msvc`)
  - Linux (`x86_64-unknown-linux-gnu`)
  - macOS 13+ (`aarch64-apple-darwin` & `x86_64-apple-darwin`)

`rusqlite` bundles SQLite from source, so no system SQLite or OpenSSL libraries are needed.

## Build from Source

```bash
git clone https://github.com/tsiscoe/Vellum.git
cd Vellum
cargo build --release
```

Install the `vellum` binary onto your `PATH`:

```bash
cargo install --path .
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
vellum --keyring init --scope default --export-key ./vellum.key
# Add --reveal if you explicitly need the raw key printed on stdout
vellum git-config --scope default
```

Drop `vellum.key` outside the working tree (for instance inside `~/.config/vellum/` or `VELLUM_KEY`), paste the printed filter/diff/merge stanzas into `.gitattributes` and `.git/config`, and commit without leaking plaintext blobs to GitHub.
