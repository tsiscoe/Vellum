//! Encrypted SQLite WAL Scoped Key Custody Vault & `BLAKE3` Merkle Audit Ledger (`vellum.db`)
//! (`#![forbid(unsafe_code)]`).
//!
//! Security Invariants:
//! - **Encrypted Scoped Repo Keys:** `RepoMasterKey` values are wrapped with `Argon2id` ->
//!   `HKDF-SHA256` -> `XChaCha20-Poly1305` using per-scope UUID AAD (`vellum-v1|scope|<aad_id>`).
//! - **Encrypted Audit Payloads:** `seal_audit_log` stores `rel_path`, `scope`, and chunk metrics
//!   exclusively inside `XChaCha20-Poly1305` `ciphertext` so zero repository filenames sit in
//!   plaintext inside `vellum.db`.
//! - **`BLAKE3` audit chain and verified owner-only filesystem access.** Writes use
//!   `BEGIN IMMEDIATE` and full WAL synchronization.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{
    MasterSeed, RepoMasterKey, SALT_LEN, VaultSubkeys, aead_decrypt, aead_encrypt, blake3_hash_hex,
    constant_time_eq_32, generate_salt, keyed_blake3_hex, parse_repo_key, validate_scope_name,
};

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Public summary metadata for a stored repository key scope (raw key omitted).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeKeySummary {
    pub scope: String,
    pub fingerprint: String,
    pub created_at: String,
}

/// Decrypted internal scope key record serialized inside `repo_scopes.ciphertext`.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct ScopedKeyPayload {
    scope: String,
    master_key_b64: String,
    created_at: String,
}

/// Input event to append an encrypted Merkle audit row.
#[derive(Debug, Clone)]
pub struct NewAuditEvent {
    pub operation: String,
    pub scope: String,
    pub rel_path: String,
    pub total_chunks: usize,
    pub unchanged_chunks: usize,
    pub seal_short: String,
}

/// Decrypted `BLAKE3`-chained audit row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealAuditEntry {
    pub seq: i64,
    pub timestamp: String,
    pub operation: String,
    pub scope: String,
    pub rel_path: String,
    pub total_chunks: usize,
    pub unchanged_chunks: usize,
    pub seal_short: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct EncryptedAuditBody {
    scope: String,
    rel_path: String,
    total_chunks: usize,
    unchanged_chunks: usize,
    seal_short: String,
}

/// Chain verification report returned by [`VellumVault::verify_audit_chain`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditChainReport {
    pub total_entries: usize,
    pub head_hash: String,
    pub valid: bool,
}

struct RawVaultMetaRow {
    salt: Vec<u8>,
    verifier: Vec<u8>,
}

struct VaultMetaRow {
    salt: [u8; SALT_LEN],
    verifier: [u8; 32],
}

/// Encrypted SQLite WAL vault managing scoped `RepoMasterKey`s and the Merkle audit chain.
pub struct VellumVault {
    conn: Connection,
    db_path: PathBuf,
    subkeys: VaultSubkeys,
}

impl VellumVault {
    /// Open or initialize a `VellumVault` at `db_path` using `passphrase`.
    pub fn open_with_passphrase(db_path: &Path, passphrase: &[u8], fast_kdf: bool) -> Result<Self> {
        let parent = db_path.parent().filter(|path| !path.as_os_str().is_empty());
        if fast_kdf {
            if let Some(parent) = parent {
                std::fs::create_dir_all(parent)?;
            }
        } else {
            let parent = parent.context("vault requires a dedicated owner-only directory")?;
            prepare_vault_directory(parent)?;
            enforce_vault_and_sidecar_acls(db_path)?;
        }

        let conn = Connection::open(db_path).with_context(|| {
            format!(
                "failed to open Vellum SQLite vault at {}",
                db_path.display()
            )
        })?;

        conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;

        Self::init_schema(&conn)?;

        let unlock = |meta: VaultMetaRow| -> Result<VaultSubkeys> {
            let sk = derive_vault_subkeys(passphrase, &meta.salt, fast_kdf)?;
            if !constant_time_eq_32(&sk.verifier, &meta.verifier) {
                return Err(anyhow!("invalid master passphrase for Vellum vault"));
            }
            Ok(sk)
        };
        let subkeys = match Self::load_meta(&conn)? {
            Some(meta) => unlock(meta)?,
            None => {
                let salt = generate_salt();
                let candidate = derive_vault_subkeys(passphrase, &salt, fast_kdf)?;
                if Self::save_meta(&conn, &salt, &candidate.verifier)? {
                    candidate
                } else {
                    unlock(Self::load_meta(&conn)?.context("vault metadata unavailable")?)?
                }
            }
        };

        if !fast_kdf {
            enforce_vault_and_sidecar_acls(db_path)?;
        }

        Ok(Self {
            conn,
            db_path: db_path.to_path_buf(),
            subkeys,
        })
    }

    /// Open an in-memory `VellumVault` for unit and TUI tests.
    pub fn open_in_memory_for_test(passphrase: &[u8]) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        let salt = [0x61u8; SALT_LEN];
        let seed = MasterSeed::derive_fast_for_test(passphrase, &salt)?;
        let subkeys = seed.derive_subkeys(&salt)?;
        Self::save_meta(&conn, &salt, &subkeys.verifier)?;
        Ok(Self {
            conn,
            db_path: PathBuf::from(":memory:"),
            subkeys,
        })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS repo_scopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_index TEXT UNIQUE NOT NULL,
                aad_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                ciphertext BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seal_audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                ciphertext BLOB NOT NULL
            );",
        )?;
        Ok(())
    }

    fn load_meta(conn: &Connection) -> Result<Option<VaultMetaRow>> {
        let row = conn
            .query_row(
                "SELECT salt, verifier FROM vault_meta WHERE id = 1",
                [],
                |r| {
                    Ok(RawVaultMetaRow {
                        salt: r.get(0)?,
                        verifier: r.get(1)?,
                    })
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some(raw) => {
                let salt: [u8; SALT_LEN] = raw
                    .salt
                    .try_into()
                    .map_err(|_| anyhow!("corrupt vault salt length"))?;
                let verifier: [u8; 32] = raw
                    .verifier
                    .try_into()
                    .map_err(|_| anyhow!("corrupt vault verifier length"))?;
                Ok(Some(VaultMetaRow { salt, verifier }))
            }
        }
    }

    fn save_meta(conn: &Connection, salt: &[u8; SALT_LEN], verifier: &[u8; 32]) -> Result<bool> {
        let inserted = conn.execute(
            "INSERT INTO vault_meta (id, salt, verifier) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO NOTHING",
            params![salt.as_slice(), verifier.as_slice()],
        )?;
        Ok(inserted == 1)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Compute the 12-hex blind-indexed fingerprint of a `RepoMasterKey` without exposing raw bytes.
    pub fn scope_fingerprint(&self, key: &RepoMasterKey) -> String {
        let encoded = key.encode_key_b64();
        keyed_blake3_hex(&self.subkeys.mac_key, "vellum-v1-fp", encoded.as_bytes())[..12]
            .to_string()
    }

    /// Retrieve an existing scope key or provision a fresh 256-bit `RepoMasterKey`.
    pub fn ensure_scope_key(&mut self, scope: &str) -> Result<RepoMasterKey> {
        validate_scope_name(scope)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let key = match self.read_scope_key(&tx, scope)? {
            Some(existing) => existing,
            None => {
                let key = RepoMasterKey::generate();
                self.write_scope_key(&tx, scope, &key, false)?;
                key
            }
        };
        tx.commit()?;
        Ok(key)
    }

    /// Store or rotate a scoped `RepoMasterKey` inside `BEGIN IMMEDIATE`.
    pub fn set_scope_key(&mut self, scope: &str, key: &RepoMasterKey) -> Result<()> {
        validate_scope_name(scope)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        self.write_scope_key(&tx, scope, key, true)?;
        tx.commit()?;
        Ok(())
    }

    fn write_scope_key(
        &self,
        conn: &Connection,
        scope: &str,
        key: &RepoMasterKey,
        rotate: bool,
    ) -> Result<()> {
        let scope_index =
            keyed_blake3_hex(&self.subkeys.mac_key, "vellum-v1-scope", scope.as_bytes());
        let aad_id = format!("v2:{}", Uuid::new_v4());
        let created_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let encoded = key.encode_key_b64();
        let payload = ScopedKeyPayload {
            scope: scope.to_string(),
            master_key_b64: encoded.to_string(),
            created_at: created_at.clone(),
        };
        let payload_json = Zeroizing::new(serde_json::to_vec(&payload)?);
        let aad = scope_aad(&scope_index, &aad_id);
        let ct = aead_encrypt(&self.subkeys.vault_key, aad.as_bytes(), &payload_json)?;

        let insert = "INSERT INTO repo_scopes (scope_index, aad_id, created_at, ciphertext)
                      VALUES (?1, ?2, ?3, ?4)";
        let rotate_stmt = format!(
            "{insert} ON CONFLICT(scope_index) DO UPDATE SET aad_id = excluded.aad_id,
                         created_at = excluded.created_at, ciphertext = excluded.ciphertext"
        );
        conn.execute(
            if rotate { &rotate_stmt } else { insert },
            params![scope_index, aad_id, created_at, ct],
        )?;
        Ok(())
    }

    /// Retrieve a stored `RepoMasterKey` for `scope`.
    pub fn get_scope_key(&self, scope: &str) -> Result<Option<RepoMasterKey>> {
        validate_scope_name(scope)?;
        self.read_scope_key(&self.conn, scope)
    }

    fn read_scope_key(&self, conn: &Connection, scope: &str) -> Result<Option<RepoMasterKey>> {
        let scope_index =
            keyed_blake3_hex(&self.subkeys.mac_key, "vellum-v1-scope", scope.as_bytes());
        let row: Option<(String, Vec<u8>)> = conn
            .query_row(
                "SELECT aad_id, ciphertext FROM repo_scopes WHERE scope_index = ?1",
                params![scope_index],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((aad_id, ct)) => {
                let payload = self.read_scope_payload(&scope_index, &aad_id, &ct)?;
                if payload.scope != scope {
                    return Err(anyhow!(
                        "authenticated vault scope does not match requested scope"
                    ));
                }
                Ok(Some(parse_repo_key(&payload.master_key_b64)?))
            }
        }
    }

    fn read_scope_payload(&self, index: &str, aad_id: &str, ct: &[u8]) -> Result<ScopedKeyPayload> {
        let aad = scope_aad(index, aad_id);
        let pt = aead_decrypt(&self.subkeys.vault_key, aad.as_bytes(), ct)?;
        let payload: ScopedKeyPayload = serde_json::from_slice(&pt)?;
        let expected = keyed_blake3_hex(
            &self.subkeys.mac_key,
            "vellum-v1-scope",
            payload.scope.as_bytes(),
        );
        if !crate::crypto::constant_time_eq_slice(index.as_bytes(), expected.as_bytes()) {
            return Err(anyhow!("authenticated vault scope index mismatch"));
        }
        Ok(payload)
    }

    /// List scope summaries without exposing secret key material.
    pub fn list_scopes(&self) -> Result<Vec<ScopeKeySummary>> {
        let mut stmt = self
            .conn
            .prepare("SELECT scope_index, aad_id, ciphertext FROM repo_scopes ORDER BY id ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (index, aad_id, ct) = row?;
            let payload = self.read_scope_payload(&index, &aad_id, &ct)?;
            let fp = keyed_blake3_hex(
                &self.subkeys.mac_key,
                "vellum-v1-fp",
                payload.master_key_b64.as_bytes(),
            )[..12]
                .to_string();
            out.push(ScopeKeySummary {
                scope: payload.scope.clone(),
                fingerprint: fp,
                created_at: payload.created_at.clone(),
            });
        }
        Ok(out)
    }

    /// Append an encrypted, `BLAKE3` Merkle-chained operation event into `seal_audit_log`.
    pub fn append_audit_event(&mut self, event: NewAuditEvent) -> Result<SealAuditEntry> {
        validate_scope_name(&event.scope)?;
        let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;

        let prev_hash: String = tx
            .query_row(
                "SELECT entry_hash FROM seal_audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());

        let entry_hash = compute_audit_entry_hash(
            &prev_hash,
            &timestamp,
            &event.operation,
            &event.scope,
            &event.rel_path,
            event.total_chunks,
            event.unchanged_chunks,
            &event.seal_short,
        );

        let body = EncryptedAuditBody {
            scope: event.scope.clone(),
            rel_path: event.rel_path.clone(),
            total_chunks: event.total_chunks,
            unchanged_chunks: event.unchanged_chunks,
            seal_short: event.seal_short.clone(),
        };
        let body_json = Zeroizing::new(serde_json::to_vec(&body)?);
        let aad = format!(
            "vellum-v1|audit|{prev_hash}|{timestamp}|{}",
            event.operation
        );
        let ct = aead_encrypt(&self.subkeys.vault_key, aad.as_bytes(), &body_json)?;

        tx.execute(
            "INSERT INTO seal_audit_log (timestamp, operation, prev_hash, entry_hash, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![timestamp, event.operation, prev_hash, entry_hash, ct],
        )?;
        let seq = tx.last_insert_rowid();
        tx.commit()?;

        Ok(SealAuditEntry {
            seq,
            timestamp,
            operation: event.operation,
            scope: event.scope,
            rel_path: event.rel_path,
            total_chunks: event.total_chunks,
            unchanged_chunks: event.unchanged_chunks,
            seal_short: event.seal_short,
            prev_hash,
            entry_hash,
        })
    }

    fn decrypt_audit_row(
        &self,
        seq: i64,
        timestamp: String,
        operation: String,
        prev_hash: String,
        entry_hash: String,
        ciphertext: Vec<u8>,
    ) -> Result<SealAuditEntry> {
        let aad = format!("vellum-v1|audit|{prev_hash}|{timestamp}|{operation}");
        let pt = aead_decrypt(&self.subkeys.vault_key, aad.as_bytes(), &ciphertext)?;
        let body: EncryptedAuditBody = serde_json::from_slice(&pt)?;
        Ok(SealAuditEntry {
            seq,
            timestamp,
            operation,
            scope: body.scope.clone(),
            rel_path: body.rel_path.clone(),
            total_chunks: body.total_chunks,
            unchanged_chunks: body.unchanged_chunks,
            seal_short: body.seal_short.clone(),
            prev_hash,
            entry_hash,
        })
    }

    /// List recent decrypted audit entries newest-first.
    pub fn list_audit_entries(&self, limit: usize) -> Result<Vec<SealAuditEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, timestamp, operation, prev_hash, entry_hash, ciphertext
             FROM seal_audit_log ORDER BY seq DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, ts, op, prev, hash, ct) = row?;
            out.push(self.decrypt_audit_row(seq, ts, op, prev, hash, ct)?);
        }
        Ok(out)
    }

    /// Verify every Merkle link and AEAD ciphertext in `seal_audit_log` from genesis to head.
    pub fn verify_audit_chain(&self) -> Result<AuditChainReport> {
        self.verify_audit_chain_inner(None)
    }

    /// Verify the chain and require an independently obtained checkpoint within its history.
    pub fn verify_audit_checkpoint(&self, count: usize, head: &str) -> Result<AuditChainReport> {
        if count == 0 || head.len() != 64 || !head.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(anyhow!("invalid audit checkpoint"));
        }
        self.verify_audit_chain_inner(Some((count, head)))
    }

    fn verify_audit_chain_inner(
        &self,
        checkpoint: Option<(usize, &str)>,
    ) -> Result<AuditChainReport> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, timestamp, operation, prev_hash, entry_hash, ciphertext
             FROM seal_audit_log ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?;

        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        let mut count = 0usize;
        for row in rows {
            let (seq, ts, op, prev, hash, ct) = row?;
            let entry = self.decrypt_audit_row(seq, ts, op, prev, hash, ct)?;
            if usize::try_from(entry.seq).ok() != Some(count + 1) {
                return Err(anyhow!("unexpected audit sequence at entry {}", count + 1));
            }
            if entry.prev_hash != expected_prev {
                return Err(anyhow!(
                    "Merkle audit chain break at seq {}: expected prev_hash {}, found {}",
                    entry.seq,
                    expected_prev,
                    entry.prev_hash
                ));
            }
            let recomputed = compute_audit_entry_hash(
                &entry.prev_hash,
                &entry.timestamp,
                &entry.operation,
                &entry.scope,
                &entry.rel_path,
                entry.total_chunks,
                entry.unchanged_chunks,
                &entry.seal_short,
            );
            if entry.entry_hash != recomputed {
                return Err(anyhow!(
                    "Merkle audit entry hash mismatch at seq {}: expected {}, found {}",
                    entry.seq,
                    recomputed,
                    entry.entry_hash
                ));
            }
            expected_prev = entry.entry_hash;
            count += 1;
            if let Some((anchor_count, anchor_hash)) = checkpoint
                && count == anchor_count
                && expected_prev != anchor_hash
            {
                return Err(anyhow!("audit checkpoint does not match retained history"));
            }
        }

        if let Some((anchor_count, _)) = checkpoint
            && count < anchor_count
        {
            return Err(anyhow!("audit history ends before its trusted checkpoint"));
        }

        Ok(AuditChainReport {
            total_entries: count,
            head_hash: expected_prev,
            valid: true,
        })
    }
}

fn derive_vault_subkeys(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    fast: bool,
) -> Result<VaultSubkeys> {
    let seed = if fast {
        MasterSeed::derive_fast_for_test(passphrase, salt)?
    } else {
        MasterSeed::derive_from_passphrase(passphrase, salt)?
    };
    seed.derive_subkeys(salt)
}

fn scope_aad(index: &str, aad_id: &str) -> String {
    if aad_id.starts_with("v2:") {
        format!("vellum-v2|scope|{index}|{aad_id}")
    } else {
        format!("vellum-v1|scope|{aad_id}")
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_audit_entry_hash(
    prev_hash: &str,
    timestamp: &str,
    operation: &str,
    scope: &str,
    rel_path: &str,
    total_chunks: usize,
    unchanged_chunks: usize,
    seal_short: &str,
) -> String {
    let payload = serde_json::json!([
        "vellum-audit-v1",
        prev_hash,
        timestamp,
        operation,
        scope,
        rel_path,
        total_chunks,
        unchanged_chunks,
        seal_short,
    ])
    .to_string();
    blake3_hash_hex(&[prev_hash.as_bytes(), b"|", payload.as_bytes()])
}

/// Enforce owner-only ACLs on vault directory, `vellum.db`, `-wal`, and `-shm` sidecars (`CWE-732`).
pub fn enforce_vault_and_sidecar_acls(db_path: &Path) -> Result<()> {
    enforce_vault_file_if_present(db_path)?;
    let db_os = db_path.as_os_str();
    for suffix in ["-wal", "-shm"] {
        let mut sidecar_os = db_os.to_os_string();
        sidecar_os.push(suffix);
        let sidecar_path = PathBuf::from(sidecar_os);
        enforce_vault_file_if_present(&sidecar_path)?;
    }
    Ok(())
}

fn enforce_vault_file_if_present(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => enforce_owner_only_acl(path, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
fn prepare_vault_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    enforce_windows_acl(path, true, false, true)
        .context("use a dedicated owner-only vault directory")
}

#[cfg(not(windows))]
fn prepare_vault_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    match builder.create(path) {
        Ok(()) => enforce_owner_only_acl(path, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            owner_only_acl(path, true, false).context("use a dedicated owner-only vault directory")
        }
        Err(error) => Err(error.into()),
    }
}

/// Apply and verify owner-only filesystem access for a vault object.
pub fn enforce_owner_only_acl(path: &Path, is_dir: bool) -> Result<()> {
    owner_only_acl(path, is_dir, true)
}

fn owner_only_acl(path: &Path, is_dir: bool, modify: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (is_dir && !metadata.is_dir())
        || (!is_dir && !metadata.is_file())
    {
        return Err(anyhow!(
            "unexpected vault object type at {}",
            path.display()
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir { 0o700 } else { 0o600 };
        if modify && metadata.permissions().mode() & 0o777 != mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .with_context(|| format!("failed to set mode {:o} on {}", mode, path.display()))?;
        }
        let applied = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if applied != mode {
            return Err(anyhow!(
                "effective Unix mode {:o} != expected {:o} on {}",
                applied,
                mode,
                path.display()
            ));
        }
    }

    #[cfg(windows)]
    enforce_windows_acl(path, is_dir, modify, false)?;

    #[cfg(not(any(unix, windows)))]
    return Err(anyhow!(
        "vault ACL enforcement is unavailable on this platform"
    ));

    Ok(())
}

#[cfg(windows)]
fn enforce_windows_acl(path: &Path, is_dir: bool, modify: bool, create: bool) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    const SET_VAULT_ACL: &str = r#"
$ErrorActionPreference = 'Stop'
$path = [IO.Path]::GetFullPath($env:VELLUM_ACL_TARGET)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$sidType = [Security.Principal.SecurityIdentifier]
$rights = [Security.AccessControl.FileSystemRights]::FullControl
$inherit = [Security.AccessControl.InheritanceFlags]::None
if ($env:VELLUM_ACL_DIRECTORY -eq 'true') {
    $target = [IO.Directory]
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
} else {
    $target = [IO.File]
}
$ownerRule = [Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, $inherit, 'None', 'Allow')
if ($env:VELLUM_ACL_CREATE -eq 'true') {
    $newAcl = [Security.AccessControl.DirectorySecurity]::new()
    $newAcl.SetOwner($sid)
    $newAcl.SetAccessRuleProtection($true, $false)
    $newAcl.AddAccessRule($ownerRule)
    [IO.Directory]::CreateDirectory($path, $newAcl) | Out-Null
}
$item = Get-Item -Force -LiteralPath $path
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Vault path is a reparse point' }
if ($env:VELLUM_ACL_MODIFY -eq 'true') {
    $acl = $target::GetAccessControl($path)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.GetAccessRules($true, $false, $sidType))) {
        $acl.RemoveAccessRuleAll($rule)
    }
    $acl.SetOwner($sid)
    $acl.AddAccessRule($ownerRule)
    $target::SetAccessControl($path, $acl)
}
$actual = $target::GetAccessControl($path)
$rules = @($actual.GetAccessRules($true, $true, $sidType))
if (!$actual.AreAccessRulesProtected -or $actual.GetOwner($sidType) -ne $sid -or $rules.Count -ne 1 -or
    $rules[0].IdentityReference -ne $sid -or $rules[0].AccessControlType -ne 'Allow' -or
    $rules[0].FileSystemRights -ne $rights -or $rules[0].InheritanceFlags -ne $inherit) {
    throw 'Unable to verify owner-only vault permissions'
}
"#;
    let system_root = std::env::var_os("SystemRoot").context("Windows system root unavailable")?;
    let powershell = Path::new(&system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let output = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", SET_VAULT_ACL])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .env("VELLUM_ACL_TARGET", path)
        .env("VELLUM_ACL_DIRECTORY", is_dir.to_string())
        .env("VELLUM_ACL_MODIFY", modify.to_string())
        .env("VELLUM_ACL_CREATE", create.to_string())
        .env_remove("VELLUM_PASSPHRASE")
        .env_remove("VELLUM_KEY")
        .stdin(Stdio::null())
        .output()
        .with_context(|| {
            format!(
                "failed to start vault ACL verification for {}",
                path.display()
            )
        })?;
    if !output.status.success() {
        return Err(anyhow!(
            "failed to verify vault ACL on {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}
