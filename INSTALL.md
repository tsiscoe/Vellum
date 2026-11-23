# Installing & Wiring Up Vellum

Compiling Vellum takes about two minutes. Rebuilding a forty-page research draft by hand because `git-crypt` turned a two-line merge into a binary hostage crisis takes the rest of your weekend.

---

## What You Need

- **Rust (`1.99.1` pinned in CI, Rust 2024 Edition)** — install it in thirty seconds via [rustup.rs](https://rustup.rs/).
- **Works on:** Windows 10/11, Linux (`x86_64`), and macOS 13+ (Apple Silicon & Intel).

SQLite is compiled straight into the single `vellum` binary from source. No wrestling with OpenSSL headers, DLL hell, or Homebrew ritual sacrifices required.

---

## 1. Build & Install

```bash
git clone https://github.com/tsiscoe/Vellum.git
cd Vellum
cargo build --locked --release
cargo install --locked --path .
```

Check it's alive:

```bash
vellum --version
```

---

## 2. Create Your Vault & Hook Up Git

First, spin up your local encrypted key vault and generate a key for your repo scope:

```bash
vellum --keyring init --scope default
vellum --keyring git-config --scope default
```

That second command prints two short config blocks:
1. One for your repo's **`.gitattributes`** (telling Git *which* files or folders Vellum should automatically lock and unlock—for example, `secret_notes/**`).
2. One for your local **`.git/config`** (telling Git how to call Vellum when staging, checking out, and merging).

**Important:** Paste both blocks in *before* you `git add` any sensitive files, otherwise Git will happily stage raw plaintext like an overeager golden retriever. Because Git deliberately doesn't let remote repos smuggle `.git/config` scripts onto people's machines, every fresh `git clone` needs that `vellum --keyring git-config` step run once locally. (If you upgraded from an early build, ditch any old `textconv` stanza from `.git/config` and use `vellum diff --path` instead when comparing encrypted files.)

---

## 3. Environment Variables (For Scripts & Headless Boxes)

| Variable | What It's For | Default |
| :--- | :--- | :--- |
| `VELLUM_VAULT` | Where your encrypted `vellum.db` vault lives. | `~/.config/vellum/vellum.db` (`%APPDATA%\vellum\vellum.db` on Windows) |
| `VELLUM_PASSPHRASE` | Unlocks the vault in automated scripts where nobody's at the keyboard. | Prompts you, or uses OS Keyring when `--keyring` is passed |
| `VELLUM_KEY` | A standalone `vellum-key-v1:...` key or `.key` file path when running without a vault (e.g., locked-down CI). | Pulled automatically from your unlocked vault |

---

## 4. Keeping Your Keys & Folders Out of Trouble

- **Private folder means private folder.** Vellum insists that its vault directory belongs strictly to your OS user (`0700` on Linux/macOS, owner-only protected DACL on Windows). When creating a brand-new vault, Vellum locks those permissions down automatically. If you point it at an existing folder that lets the whole street read your files, Vellum will refuse to open it until you tighten the permissions.
- **Exporting standalone key files (`--export-key`):** If you ever export a raw key file for a headless build server, pick a brand-new file path *outside* your Git repository. Vellum creates it with owner-only permissions and flatly refuses to overwrite an existing file so you don't nuke an old key by accident. Never commit a `.key` file into Git unless your threat model is "comedic tragedy."
- **Moving files:** Because Vellum binds every encrypted paragraph to its Git file path (so people can't swap secret files around undetected), after you rename or `git mv` a protected file in your worktree, run:
  ```bash
  git add --renormalize -- path/to/new_name.md
  ```
  That tells Git to re-seal the file cleanly under its new name.

---

## 5. Pre-Push Sanity Check (Don't Trust Your Own Muscle Memory)

Humans forget `.gitattributes` rules. Keep a simple JSON list—stored *outside* the branch you're checking—naming every file path in your repo that must never leave your laptop unencrypted (for example: `["secret_notes/research.md", "ops/runbook.md"]`).

Before pushing to GitHub, make Vellum inspect what's actually staged in Git's index or committed at `HEAD`:

```bash
vellum --keyring --json verify-tree --staged --manifest /trusted/protected-paths.json
vellum --keyring --json verify-tree --revision HEAD --manifest /trusted/protected-paths.json
```

If someone bypassed the Git filter, staged plaintext by mistake, or tampered with a seal, Vellum returns a non-zero exit code and names the offending file before `git push` ruins your week.

---

## 6. Checking Your Local Audit Chain

Every vault-backed lock, unlock, merge, and diff records an encrypted, hash-chained receipt inside `vellum.db`. You can verify nothing in that local history was tampered with—and save a tiny checkpoint (`total_entries` + `head_hash`) somewhere separate so even rolling back the vault file gets caught:

```bash
vellum --keyring --json audit-verify
vellum --keyring --json audit-verify --anchor-count COUNT --anchor-head HASH
```
