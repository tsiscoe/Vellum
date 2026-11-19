//! Cryptographic Core for **Vellum** (`vellum v0.1.0`):
//! - `Argon2id` (`64 MiB, t=3, p=4`) + `HKDF-SHA256` vault key hierarchy
//! - `RepoMasterKey` -> domain-separated `cdc_key`, `siv_key`, `enc_key`, `seal_key`
//! - RFC 5297-style `BLAKE3-XChaCha20-SIV` convergent chunk AEAD (`ZeroizeOnDrop`)

use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const XNONCE_LEN: usize = 24;
pub const MAX_SCOPE_NAME_LEN: usize = 64;

/// 256-bit Master Seed derived from vault passphrase via `Argon2id`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed([u8; KEY_LEN]);

/// Vault encryption and blind-index keys expanded from [`MasterSeed`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultSubkeys {
    pub vault_key: [u8; KEY_LEN],
    pub mac_key: [u8; KEY_LEN],
    pub verifier: [u8; KEY_LEN],
}

/// 256-bit scoped repository master key protecting tracked `.vellum` files.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RepoMasterKey(pub [u8; KEY_LEN]);

/// Domain-separated subkeys derived from [`RepoMasterKey`] via `HKDF-SHA256`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RepoSubkeys {
    pub cdc_key: [u8; KEY_LEN],
    pub siv_key: [u8; KEY_LEN],
    pub enc_key: [u8; KEY_LEN],
    pub seal_key: [u8; KEY_LEN],
}

/// Validate a key scope identifier (`1..=64` ASCII `[A-Za-z0-9_-]`, cannot start with `'-'`)
/// to prevent `.git/config` directive injection, shell metacharacters, and CLI flag injection.
pub fn validate_scope_name(scope: &str) -> Result<()> {
    if scope.is_empty() || scope.len() > MAX_SCOPE_NAME_LEN {
        return Err(anyhow!(
            "invalid Vellum scope name length (must be 1..={MAX_SCOPE_NAME_LEN} ASCII chars)"
        ));
    }
    if scope.starts_with('-') {
        return Err(anyhow!(
            "invalid Vellum scope '{scope}': scope cannot start with '-'"
        ));
    }
    if !scope
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(anyhow!(
            "invalid Vellum scope '{scope}': only ASCII [A-Za-z0-9_-] characters are permitted"
        ));
    }
    Ok(())
}

/// Strictly canonicalize and validate a repository-relative path before binding it into
/// `BLAKE3-XChaCha20-SIV` keys, AAD, or Merkle seals (`CWE-22`).
///
/// Rejects empty paths, ASCII control bytes, Windows drive colons (`:`), and `..` traversal
/// segments while collapsing duplicate `/` and `.` segments deterministically.
pub fn validate_and_normalize_repo_path(rel_path: &str) -> Result<String> {
    let trimmed = rel_path.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("repository path cannot be empty"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(anyhow!(
            "repository path contains illegal control characters"
        ));
    }
    if trimmed.contains(':') {
        return Err(anyhow!(
            "repository path '{trimmed}' cannot contain drive or stream colons"
        ));
    }

    let mut segments = Vec::new();
    for seg in trimmed.split(['/', '\\']) {
        match seg {
            "" | "." => continue,
            ".." => {
                return Err(anyhow!(
                    "parent traversal ('..') is forbidden in repository path '{trimmed}'"
                ));
            }
            s => segments.push(s),
        }
    }

    if segments.is_empty() {
        return Err(anyhow!("repository path '{trimmed}' resolves to empty"));
    }
    Ok(segments.join("/"))
}

/// Canonicalize repository-relative paths (`\` -> `/`, collapse empty & `.` segments) for display
/// helpers where fallible errors are omitted. Cryptographic paths MUST use
/// [`validate_and_normalize_repo_path`].
pub fn normalize_repo_path(rel_path: &str) -> String {
    validate_and_normalize_repo_path(rel_path).unwrap_or_else(|_| "untitled".to_string())
}

impl RepoMasterKey {
    pub fn generate() -> Self {
        let mut raw = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut raw);
        Self(raw)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn encode_key_b64(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("vellum-key-v1:{}", BASE64_STD.encode(self.0)))
    }

    /// Derive `cdc_key`, `siv_key`, `enc_key`, and `seal_key` via `HKDF-SHA256`.
    pub fn derive_subkeys(&self) -> Result<RepoSubkeys> {
        let hk = Hkdf::<Sha256>::new(Some(b"vellum-repo-salt-v1"), &self.0);
        let mut cdc_key = [0u8; KEY_LEN];
        let mut siv_key = [0u8; KEY_LEN];
        let mut enc_key = [0u8; KEY_LEN];
        let mut seal_key = [0u8; KEY_LEN];

        hk.expand(b"vellum-v1-cdc-key", &mut cdc_key)
            .map_err(|_| anyhow!("HKDF expand failed for cdc_key"))?;
        hk.expand(b"vellum-v1-siv-key", &mut siv_key)
            .map_err(|_| anyhow!("HKDF expand failed for siv_key"))?;
        hk.expand(b"vellum-v1-enc-key", &mut enc_key)
            .map_err(|_| anyhow!("HKDF expand failed for enc_key"))?;
        hk.expand(b"vellum-v1-seal-key", &mut seal_key)
            .map_err(|_| anyhow!("HKDF expand failed for seal_key"))?;

        Ok(RepoSubkeys {
            cdc_key,
            siv_key,
            enc_key,
            seal_key,
        })
    }
}

/// Parse `vellum-key-v1:<base64>`, bare 32-byte Base64, or 64-char hex repository key.
pub fn parse_repo_key(spec: &str) -> Result<RepoMasterKey> {
    let trimmed = spec.trim();
    let body = trimmed.strip_prefix("vellum-key-v1:").unwrap_or(trimmed);

    let mut raw_vec = if body.len() == 64 && body.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(body).map_err(|e| anyhow!("invalid hex repository key: {e}"))?
    } else {
        BASE64_STD
            .decode(body)
            .map_err(|e| anyhow!("invalid Base64 repository key: {e}"))?
    };

    let arr: [u8; KEY_LEN] = raw_vec
        .clone()
        .try_into()
        .map_err(|_| anyhow!("repository key must decode to 32 bytes"))?;
    raw_vec.zeroize();
    Ok(RepoMasterKey::from_bytes(arr))
}

impl MasterSeed {
    /// Derive a 256-bit `MasterSeed` using production `Argon2id` parameters (`64 MiB, t=3, p=4`).
    pub fn derive_from_passphrase(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(64 * 1024, 3, 4, Some(KEY_LEN))
            .map_err(|e| anyhow!("invalid Argon2id params: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {e}"))?;
        Ok(Self(out))
    }

    /// Fast `Argon2id` derivation (`8 MiB, t=1, p=1`) strictly for automated test suites.
    pub fn derive_fast_for_test(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(8 * 1024, 1, 1, Some(KEY_LEN))
            .map_err(|e| anyhow!("invalid test Argon2id params: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("test Argon2id derivation failed: {e}"))?;
        Ok(Self(out))
    }

    pub fn derive_subkeys(&self, salt: &[u8; SALT_LEN]) -> Result<VaultSubkeys> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut vault_key = [0u8; KEY_LEN];
        let mut mac_key = [0u8; KEY_LEN];
        let mut verifier = [0u8; KEY_LEN];

        hk.expand(b"vellum-v1-vault-key", &mut vault_key)
            .map_err(|_| anyhow!("HKDF expand failed for vault_key"))?;
        hk.expand(b"vellum-v1-mac-key", &mut mac_key)
            .map_err(|_| anyhow!("HKDF expand failed for mac_key"))?;
        hk.expand(b"vellum-v1-verifier", &mut verifier)
            .map_err(|_| anyhow!("HKDF expand failed for verifier"))?;

        Ok(VaultSubkeys {
            vault_key,
            mac_key,
            verifier,
        })
    }
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Constant-time 32-byte equality check (`CWE-208`).
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time slice equality check (`CWE-208`).
pub fn constant_time_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compute the deterministic 32-byte Synthetic IV (`SIV`) over `(norm_path, chunk_plaintext)`.
fn compute_chunk_siv(siv_key: &[u8; KEY_LEN], norm_path: &str, chunk_plaintext: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(siv_key);
    h.update(b"vellum-v1-chunk-siv|");
    h.update(&(norm_path.len() as u32).to_le_bytes());
    h.update(norm_path.as_bytes());
    h.update(b"|");
    h.update(chunk_plaintext);
    *h.finalize().as_bytes()
}

/// Derive a per-chunk `XChaCha20-Poly1305` subkey bound to `(norm_path, nonce24)`.
fn derive_chunk_enc_key(
    enc_key: &[u8; KEY_LEN],
    norm_path: &str,
    nonce24: &[u8; XNONCE_LEN],
) -> [u8; KEY_LEN] {
    let mut h = blake3::Hasher::new_keyed(enc_key);
    h.update(b"vellum-v1-chunk-key|");
    h.update(&(norm_path.len() as u32).to_le_bytes());
    h.update(norm_path.as_bytes());
    h.update(b"|");
    h.update(nonce24);
    *h.finalize().as_bytes()
}

/// Deterministically encrypt and authenticate a chunk via `BLAKE3-XChaCha20-SIV`.
///
/// Returns `(chunk_id_16hex, nonce24 || ciphertext_and_tag)`.
pub fn seal_convergent_chunk(
    subkeys: &RepoSubkeys,
    rel_path: &str,
    chunk_plaintext: &[u8],
) -> Result<(String, Vec<u8>)> {
    let norm_path = validate_and_normalize_repo_path(rel_path)?;
    let mut siv = compute_chunk_siv(&subkeys.siv_key, &norm_path, chunk_plaintext);
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    nonce_bytes.copy_from_slice(&siv[0..XNONCE_LEN]);
    let chunk_id = hex::encode(&siv[0..8]);

    let mut chunk_key = derive_chunk_enc_key(&subkeys.enc_key, &norm_path, &nonce_bytes);
    let cipher = XChaCha20Poly1305::new_from_slice(&chunk_key)
        .map_err(|_| anyhow!("invalid convergent chunk cipher key"))?;
    let aad = format!("vellum-v1|chunk|{norm_path}");
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: chunk_plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("convergent chunk AEAD encryption failed"))?;

    siv.zeroize();
    chunk_key.zeroize();

    let mut out = Vec::with_capacity(XNONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok((chunk_id, out))
}

/// Decrypt a convergent `BLAKE3-XChaCha20-SIV` chunk and verify its synthetic IV & `chunk_id`.
pub fn open_convergent_chunk(
    subkeys: &RepoSubkeys,
    rel_path: &str,
    expected_chunk_id: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < XNONCE_LEN + 16 {
        return Err(anyhow!("convergent chunk blob too short"));
    }
    let norm_path = validate_and_normalize_repo_path(rel_path)?;
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[..XNONCE_LEN]);

    let mut chunk_key = derive_chunk_enc_key(&subkeys.enc_key, &norm_path, &nonce_bytes);
    let cipher = XChaCha20Poly1305::new_from_slice(&chunk_key)
        .map_err(|_| anyhow!("invalid convergent chunk cipher key"))?;
    chunk_key.zeroize();

    let aad = format!("vellum-v1|chunk|{norm_path}");
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &blob[XNONCE_LEN..],
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("chunk AEAD authentication failed for path '{norm_path}'"))?,
    );

    // True SIV invariant: verify decrypted plaintext recomputes the exact wire nonce & chunk_id.
    let mut recomputed_siv = compute_chunk_siv(&subkeys.siv_key, &norm_path, &plaintext);
    let nonce_ok = constant_time_eq_slice(&recomputed_siv[0..XNONCE_LEN], &nonce_bytes);
    let id_ok = constant_time_eq_slice(
        hex::encode(&recomputed_siv[0..8]).as_bytes(),
        expected_chunk_id.as_bytes(),
    );
    recomputed_siv.zeroize();

    if !nonce_ok || !id_ok {
        return Err(anyhow!(
            "SIV mismatch after chunk decryption on path '{norm_path}'"
        ));
    }

    Ok(plaintext)
}

/// Encrypt arbitrary bytes under `XChaCha20-Poly1305` with fresh 192-bit CSPRNG nonce and AAD.
pub fn aead_encrypt(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("invalid XChaCha20-Poly1305 key"))?;
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))?;
    let mut out = Vec::with_capacity(XNONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt `nonce[24] || ciphertext+tag` under `XChaCha20-Poly1305` into `Zeroizing` RAM.
pub fn aead_decrypt(key: &[u8; KEY_LEN], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < XNONCE_LEN + 16 {
        return Err(anyhow!("AEAD blob too short"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("invalid XChaCha20-Poly1305 key"))?;
    let pt = cipher
        .decrypt(
            XNonce::from_slice(&blob[..XNONCE_LEN]),
            Payload {
                msg: &blob[XNONCE_LEN..],
                aad,
            },
        )
        .map_err(|_| anyhow!("AEAD authentication failed (tampered vault row or wrong key)"))?;
    Ok(Zeroizing::new(pt))
}

pub fn keyed_blake3_hex(mac_key: &[u8; KEY_LEN], domain: &str, data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(domain.as_bytes());
    hasher.update(b"|");
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

pub fn blake3_hash_hex(parts: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().to_hex().to_string()
}
