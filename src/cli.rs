//! Clap v4 CLI surface for **Vellum** (`vellum v0.1.0`).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "vellum",
    version,
    about = "Chunk-convergent BLAKE3-XChaCha20-SIV Git clean/smudge filter, zero-disk in-RAM 3-way merge driver, and Merkle-sealed diff engine"
)]
pub struct Cli {
    /// Path to encrypted SQLite WAL custody vault (`vellum.db`).
    #[arg(long, env = "VELLUM_VAULT", global = true)]
    pub vault: Option<PathBuf>,

    /// Store or retrieve vault passphrase via the native OS credential manager.
    #[arg(long, global = true)]
    pub keyring: bool,

    /// Emit machine-readable JSON output.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize `vellum.db` and provision a 256-bit scoped `RepoMasterKey`.
    Init {
        /// Key scope name (e.g., default, research, prod).
        #[arg(long, default_value = "default")]
        scope: String,

        /// Optional file path to export the `vellum-key-v1:...` key with owner-only ACLs.
        #[arg(long)]
        export_key: Option<PathBuf>,

        /// Reveal the raw `vellum-key-v1:...` key on stdout/JSON (redacted by default).
        #[arg(long)]
        reveal: bool,
    },

    /// Git clean filter: encrypt plaintext stdin/file into `VELLUM-WIRE-V1`.
    Clean {
        /// Repository-relative file path bound into SIV and Merkle seal.
        #[arg(long)]
        path: String,

        /// Scope name inside `vellum.db` when `--key` is omitted.
        #[arg(long, default_value = "default")]
        scope: String,

        /// Raw `vellum-key-v1:...` key or file path for vaultless Git filter execution.
        #[arg(long, env = "VELLUM_KEY")]
        key: Option<String>,

        /// Optional input file (defaults to stdin).
        #[arg(short = 'i', long)]
        input: Option<PathBuf>,

        /// Optional output file (defaults to stdout).
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },

    /// Git smudge filter: verify Merkle seal and decrypt `VELLUM-WIRE-V1` to plaintext.
    Smudge {
        /// Repository-relative file path bound into SIV and Merkle seal.
        #[arg(long)]
        path: String,

        /// Scope name inside `vellum.db` when `--key` is omitted.
        #[arg(long, default_value = "default")]
        scope: String,

        /// Raw `vellum-key-v1:...` key or file path for vaultless execution.
        #[arg(long, env = "VELLUM_KEY")]
        key: Option<String>,

        /// Optional input file (defaults to stdin).
        #[arg(short = 'i', long)]
        input: Option<PathBuf>,

        /// Optional output file (defaults to stdout).
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },

    /// Zero-disk in-RAM 3-way Git merge driver over encrypted `VELLUM-WIRE-V1` revisions.
    Merge {
        /// Base (`%O`) encrypted wireframe file.
        #[arg(long)]
        base: PathBuf,

        /// Ours (`%A`) encrypted wireframe file (overwritten in place if `--out` omitted).
        #[arg(long)]
        ours: PathBuf,

        /// Theirs (`%B`) encrypted wireframe file.
        #[arg(long)]
        theirs: PathBuf,

        /// Repository-relative file path (`%P`).
        #[arg(long)]
        path: String,

        /// Optional destination path (defaults to overwriting `--ours`).
        #[arg(long)]
        out: Option<PathBuf>,

        /// Scope name inside `vellum.db` when `--key` is omitted.
        #[arg(long, default_value = "default")]
        scope: String,

        /// Raw `vellum-key-v1:...` key or file path.
        #[arg(long, env = "VELLUM_KEY")]
        key: Option<String>,
    },

    /// Compare two encrypted wireframes, reporting chunk reuse and in-RAM unified diff.
    Diff {
        /// Baseline encrypted wireframe file.
        file_a: PathBuf,

        /// Target encrypted wireframe file.
        file_b: PathBuf,

        /// Repository-relative file path.
        #[arg(long)]
        path: String,

        /// Scope name inside `vellum.db` when `--key` is omitted.
        #[arg(long, default_value = "default")]
        scope: String,

        /// Raw `vellum-key-v1:...` key or file path.
        #[arg(long, env = "VELLUM_KEY")]
        key: Option<String>,
    },

    /// Decrypt a wireframe to stdout with an explicit authenticated Git path.
    Textconv {
        /// Encrypted wireframe file.
        file: PathBuf,

        /// Repository-relative file path.
        #[arg(long)]
        path: String,

        /// Scope name inside `vellum.db` when `--key` is omitted.
        #[arg(long, default_value = "default")]
        scope: String,

        /// Raw `vellum-key-v1:...` key or file path.
        #[arg(long, env = "VELLUM_KEY")]
        key: Option<String>,
    },

    /// Audit recognized worktree files or require verified Git objects for a trusted manifest.
    VerifyTree {
        /// Root directory to audit.
        #[arg(long, default_value = ".")]
        dir: PathBuf,

        /// Independently maintained JSON array of canonical Git-relative protected paths.
        #[arg(long, requires = "git_source")]
        manifest: Option<PathBuf>,

        /// Verify one snapshot of the staged index against the manifest.
        #[arg(long, group = "git_source", requires = "manifest")]
        staged: bool,

        /// Verify the Git tree of this revision against the manifest.
        #[arg(long, group = "git_source", requires = "manifest")]
        revision: Option<String>,

        /// Scope name inside `vellum.db` when `--key` is omitted.
        #[arg(long, default_value = "default")]
        scope: String,

        /// Raw `vellum-key-v1:...` key or file path.
        #[arg(long, env = "VELLUM_KEY")]
        key: Option<String>,
    },

    /// Print copy-pasteable `.gitattributes` and `.git/config` filter/merge configuration.
    GitConfig {
        /// Scope name inside `vellum.db`.
        #[arg(long, default_value = "default")]
        scope: String,
    },

    /// Verify the vault's audit history and emit a checkpoint for external retention.
    AuditVerify {
        /// Entry count from a trusted, externally retained checkpoint.
        #[arg(long, requires = "anchor_head")]
        anchor_count: Option<usize>,

        /// Head hash from the same trusted checkpoint.
        #[arg(long, requires = "anchor_count")]
        anchor_head: Option<String>,
    },

    /// Launch the 3-pane Ratatui v0.30 custody, wireframe inspector, and Merkle audit dashboard.
    Tui {
        /// Optional wireframe file to inspect inside Pane 2 on startup.
        #[arg(long)]
        file: Option<PathBuf>,
    },
}
