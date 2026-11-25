/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! At-rest wrapping for wallet secrets stored in SQLite (S14).
//!
//! Full-DB encryption uses SQLCipher (`bundled-sqlcipher-vendored-openssl`)
//! keyed by `MOONSHINE_WALLET_PASS` or a legacy `{db}.pass` file (mode 0600).
//!
//! Sensitive secrets (`addresses.secret_key`, `notes.owner_secret`,
//! `wallet_meta['derivation_seed']`, `token_mints`, `deploy_auths.secret_key`,
//! `dao_records.params_toml`) are additionally AEAD-wrapped at rest using
//! `XChaCha20Poly1305` (`MSK2` magic + 24-byte random nonce + full 128-bit
//! Poly1305 tag with `MSK2` bound as AAD).
//!
//! The 32-byte wrap key lives inside `wallet_meta['wrap_key']`, itself wrapped
//! under a key derived from the wallet passphrase and a per-wallet random
//! 16-byte salt stored in `wallet_meta['pass_salt']` (Argon2id for user
//! passphrases; salted blake3 for 256-bit auto-generated hex passphrases).
//!
//! Legacy `MSK1` (blake3-CTR + truncated MAC) and plaintext rows are upgraded
//! one-time on wallet open via [`unwrap_secret_for_migration`]; runtime reads
//! via [`unwrap_secret`] fail closed and refuse plaintext or legacy formats.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Current AEAD secret wrap format: `MSK2 || 24B XNonce || XChaCha20Poly1305(pt, aad="MSK2")`.
pub const MAGIC_V2: &[u8; 4] = b"MSK2";
const XNONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// Prefix for wrapped UTF-8 text columns (e.g. `dao_records.params_toml`).
pub const TEXT_PREFIX_V2: &str = "MSK2:";

/// Legacy blake3-CTR + truncated MAC format (migration-read only).
const MAGIC_V1: &[u8; 4] = b"MSK1";
const NONCE_LEN_V1: usize = 16;
const DOMAIN_V1: &[u8] = b"DarkFi-Moonshine-SecretWrap-v1";
const PASS_DOMAIN_V1: &[u8] = b"DarkFi-Moonshine-WalletPass-v1";
const PASS_DOMAIN_V2: &[u8] = b"DarkFi-Moonshine-WalletPass-v2";

/// `wallet_meta` key for the passphrase-wrapped wrap key.
pub const META_WRAP_KEY: &str = "wrap_key";
/// `wallet_meta` key for the per-wallet random 16-byte KDF salt.
pub const META_PASS_SALT: &str = "pass_salt";
/// Byte length of the per-wallet random KDF salt.
pub const PASS_SALT_LEN: usize = 16;

fn legacy_keystream(key: &[u8; 32], nonce: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u64;
    while out.len() < len {
        let mut h = blake3::Hasher::new_keyed(key);
        h.update(DOMAIN_V1);
        h.update(nonce);
        h.update(&counter.to_le_bytes());
        let block = *h.finalize().as_bytes();
        let need = (len - out.len()).min(32);
        out.extend_from_slice(&block[..need]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// Legacy `MSK1` wrap helper (test-only, to test one-time migration from `MSK1` -> `MSK2`).
#[cfg(test)]
pub fn wrap_secret_legacy_v1(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN_V1];
    OsRng.fill_bytes(&mut nonce);
    let mut stream = legacy_keystream(key, &nonce, plaintext.len());
    let mut ct: Vec<u8> = plaintext
        .iter()
        .zip(stream.iter())
        .map(|(p, s)| p ^ s)
        .collect();
    stream.zeroize();

    let mut out = Vec::with_capacity(4 + NONCE_LEN_V1 + ct.len() + 16);
    out.extend_from_slice(MAGIC_V1);
    out.extend_from_slice(&nonce);
    out.append(&mut ct);

    let mut mac = blake3::Hasher::new_keyed(key);
    mac.update(DOMAIN_V1);
    mac.update(b"-mac");
    mac.update(&out);
    out.extend_from_slice(&mac.finalize().as_bytes()[..16]);
    out
}

fn unwrap_secret_legacy_v1(stored: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if stored.len() < 4 + NONCE_LEN_V1 + 16 || &stored[..4] != MAGIC_V1 {
        return Err("Legacy MSK1 secret malformed or too short".into());
    }
    let (body, mac) = stored.split_at(stored.len() - 16);
    let mut expected = blake3::Hasher::new_keyed(key);
    expected.update(DOMAIN_V1);
    expected.update(b"-mac");
    expected.update(body);
    let digest = expected.finalize();
    let got = &digest.as_bytes()[..16];
    if !ct_eq(mac, got) {
        return Err("Legacy MSK1 secret MAC mismatch".into());
    }
    let nonce = &body[4..4 + NONCE_LEN_V1];
    let ct = &body[4 + NONCE_LEN_V1..];
    let mut stream = legacy_keystream(key, nonce, ct.len());
    let out = ct.iter().zip(stream.iter()).map(|(c, s)| c ^ s).collect();
    stream.zeroize();
    Ok(out)
}

/// Wrap plaintext secret bytes for at-rest storage using `XChaCha20Poly1305` (`MSK2`).
pub fn wrap_secret(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: MAGIC_V2,
            },
        )
        .expect("XChaCha20Poly1305 encrypt");

    let mut out = Vec::with_capacity(MAGIC_V2.len() + XNONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC_V2);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Unwrap an `MSK2`-wrapped secret. Fail-closed: rejects plaintext, legacy `MSK1`,
/// truncated buffers, wrong keys, or tampered ciphertext/tags.
pub fn unwrap_secret(stored: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if stored.len() < MAGIC_V2.len() + XNONCE_LEN + TAG_LEN {
        return Err("Wrapped secret missing MSK2 header or truncated".into());
    }
    if &stored[..4] != MAGIC_V2 {
        return Err("Wrapped secret does not have MSK2 header (unmigrated or corrupted)".into());
    }
    let nonce = &stored[4..4 + XNONCE_LEN];
    let ct = &stored[4 + XNONCE_LEN..];
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: MAGIC_V2,
            },
        )
        .map_err(|_| "Wrapped secret AEAD authentication failed".into())
}

/// Unwrap a stored secret during one-time migration on wallet open.
///
/// Returns `(plaintext, needs_rewrite)`:
/// - `MSK2` -> `(pt, false)`
/// - `MSK1` -> verifies legacy MAC, returns `(pt, true)`
/// - Plaintext (no recognized magic) -> returns `(stored, true)`
pub fn unwrap_secret_for_migration(
    stored: &[u8],
    key: &[u8; 32],
) -> Result<(Vec<u8>, bool), String> {
    if stored.len() >= 4 && &stored[..4] == MAGIC_V2 {
        return Ok((unwrap_secret(stored, key)?, false));
    }
    if stored.len() >= 4 && &stored[..4] == MAGIC_V1 {
        return Ok((unwrap_secret_legacy_v1(stored, key)?, true));
    }
    Ok((stored.to_vec(), true))
}

/// Wrap UTF-8 text (e.g. `dao_records.params_toml`) into an `MSK2:<hex>` string.
pub fn wrap_secret_text(plaintext: &str, key: &[u8; 32]) -> String {
    let wrapped = wrap_secret(plaintext.as_bytes(), key);
    format!("{TEXT_PREFIX_V2}{}", hex::encode(wrapped))
}

/// Unwrap an `MSK2:<hex>` text secret. Fail-closed: rejects plaintext or tampered rows.
pub fn unwrap_secret_text(stored: &str, key: &[u8; 32]) -> Result<String, String> {
    let hex_body = stored
        .strip_prefix(TEXT_PREFIX_V2)
        .ok_or_else(|| "Wrapped text secret missing MSK2: prefix".to_string())?;
    let bytes = hex::decode(hex_body).map_err(|e| format!("Wrapped text secret bad hex: {e}"))?;
    let plain = unwrap_secret(&bytes, key)?;
    String::from_utf8(plain).map_err(|e| format!("Wrapped text secret invalid UTF-8: {e}"))
}

/// Unwrap a text secret during one-time migration on wallet open.
/// Returns `(plaintext, needs_rewrite)`.
pub fn unwrap_secret_text_for_migration(
    stored: &str,
    key: &[u8; 32],
) -> Result<(String, bool), String> {
    if stored.starts_with(TEXT_PREFIX_V2) {
        return Ok((unwrap_secret_text(stored, key)?, false));
    }
    Ok((stored.to_string(), true))
}

/// Generate a fresh per-wallet random 16-byte KDF salt.
pub fn random_pass_salt() -> [u8; PASS_SALT_LEN] {
    let mut salt = [0u8; PASS_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a 32-byte meta-encryption key from a passphrase and per-wallet random salt.
///
/// Uses Argon2id (64 MB, 3 iterations, 1 lane) for user passphrases. Auto-generated
/// 64-hex-char (256-bit entropy) passphrases use salted blake3 to keep CLI open fast.
pub fn meta_key_from_passphrase_salted(pass: &str, salt: &[u8; PASS_SALT_LEN]) -> [u8; 32] {
    if pass.len() == 64 && pass.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut h = blake3::Hasher::new();
        h.update(PASS_DOMAIN_V2);
        h.update(salt);
        h.update(pass.as_bytes());
        return *h.finalize().as_bytes();
    }
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(
        64 * 1024, // 64 MB memory cost
        3,         // 3 iterations
        1,         // 1 lane of parallelism
        Some(32),  // 32-byte output
    )
    .expect("valid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .expect("Argon2id hash");
    key
}

/// Legacy unsalted (static domain) passphrase key derivation — used ONLY when
/// migrating pre-v2 wallets that lack `wallet_meta['pass_salt']`.
fn meta_key_from_passphrase_legacy(pass: &str) -> [u8; 32] {
    if pass.len() == 64 && pass.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut h = blake3::Hasher::new();
        h.update(PASS_DOMAIN_V1);
        h.update(pass.as_bytes());
        return *h.finalize().as_bytes();
    }
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(64 * 1024, 3, 1, Some(32)).expect("valid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(pass.as_bytes(), PASS_DOMAIN_V1, &mut key)
        .expect("Argon2id hash");
    key
}

/// Load passphrase from `MOONSHINE_WALLET_PASS`, else legacy `{db}.pass`.
pub fn load_or_create_passphrase(db_path: &str) -> Result<Zeroizing<String>, String> {
    if let Ok(pass) = env::var("MOONSHINE_WALLET_PASS") {
        if !pass.is_empty() {
            return Ok(Zeroizing::new(pass));
        }
    }
    let pass_path = format!("{db_path}.pass");
    if Path::new(&pass_path).exists() {
        let mut s = Zeroizing::new(String::new());
        fs::File::open(&pass_path)
            .and_then(|mut f| f.read_to_string(&mut s))
            .map_err(|e| e.to_string())?;
        let trimmed = Zeroizing::new(s.trim().to_string());
        if trimmed.is_empty() {
            return Err("Empty wallet passphrase file".into());
        }
        return Ok(trimmed);
    }
    Err(format!(
        "No wallet passphrase. Set MOONSHINE_WALLET_PASS (it is not written next to the database). \
         Existing wallets that already have {pass_path} still open."
    ))
}

/// Constant-time equality for fixed-length legacy MAC tags.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Wrap key previously stored beside the database, if that legacy file exists.
pub fn read_legacy_wrap_key(db_path: &str) -> Result<Option<[u8; 32]>, String> {
    let key_path = format!("{db_path}.wrapkey");
    if !Path::new(&key_path).exists() {
        return Ok(None);
    }
    let mut f = fs::File::open(&key_path).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    f.read_exact(&mut key).map_err(|e| e.to_string())?;
    Ok(Some(key))
}

/// Remove `{db}.wrapkey` after the key has been stored inside the encrypted DB.
pub fn delete_legacy_wrap_key(db_path: &str) {
    let key_path = format!("{db_path}.wrapkey");
    if Path::new(&key_path).exists() {
        let _ = fs::remove_file(&key_path);
    }
}

pub fn random_wrap_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Recover the wrap key stored in `wallet_meta` under the passphrase.
///
/// Returns `(wrap_key, needs_rekey)` where `needs_rekey` is true if the wallet
/// had no per-wallet `pass_salt` or stored the wrap key in legacy `MSK1`/plaintext.
pub fn unwrap_meta_wrap_key(
    stored: &[u8],
    passphrase: &str,
    salt: Option<&[u8]>,
) -> Result<([u8; 32], bool), String> {
    let (mut meta_key, missing_salt) = match salt {
        Some(s) if s.len() == PASS_SALT_LEN => {
            let mut arr = [0u8; PASS_SALT_LEN];
            arr.copy_from_slice(s);
            (meta_key_from_passphrase_salted(passphrase, &arr), false)
        }
        Some(s) => {
            return Err(format!(
                "wallet_meta pass_salt has invalid length {} (expected {PASS_SALT_LEN})",
                s.len()
            ));
        }
        None => (meta_key_from_passphrase_legacy(passphrase), true),
    };
    let res = if missing_salt {
        unwrap_secret_for_migration(stored, &meta_key)
    } else if stored.len() >= 4 && &stored[..4] == MAGIC_V2 {
        unwrap_secret(stored, &meta_key).map(|pt| (pt, false))
    } else {
        unwrap_secret_for_migration(stored, &meta_key)
    };
    meta_key.zeroize();
    let (mut raw, migrated_blob) = res?;
    if raw.len() != 32 {
        raw.zeroize();
        return Err("wallet_meta wrap key has the wrong length".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    raw.zeroize();
    Ok((key, missing_salt || migrated_blob))
}

/// Persist the per-wallet salt and `MSK2`-wrapped wrap key into `wallet_meta`.
pub fn store_wrap_key_in_meta(
    mut set_meta: impl FnMut(&str, &[u8]) -> Result<(), String>,
    wrap_key: &[u8; 32],
    passphrase: &str,
    salt: &[u8; PASS_SALT_LEN],
) -> Result<(), String> {
    let mut meta_key = meta_key_from_passphrase_salted(passphrase, salt);
    let wrapped = wrap_secret(wrap_key, &meta_key);
    meta_key.zeroize();
    set_meta(META_PASS_SALT, salt)?;
    set_meta(META_WRAP_KEY, &wrapped)
}

/// Create `dir` (and parents) and restrict `dir` to mode 0700 (owner only).
pub fn ensure_dir_0700(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(dir, perms).map_err(|e| e.to_string())?;
    Ok(())
}

/// Restrict an existing file to mode 0600 (owner read/write only).
pub fn set_file_mode_0600(path: &Path) -> Result<(), String> {
    if path.exists() {
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Write bytes to a file with mode 0600, replacing any previous contents and
/// tightening permissions on pre-existing files.
pub fn write_mode_0600_overwrite(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir_0700(parent)?;
        }
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts.open(path).map_err(|e| e.to_string())?;
    set_file_mode_0600(path)?;
    f.write_all(data).map_err(|e| e.to_string())?;
    Ok(())
}

/// Fixed key for in-memory unit tests.
#[cfg(test)]
pub fn test_wrap_key() -> [u8; 32] {
    *blake3::hash(b"moonshine-test-wrap-key").as_bytes()
}

/// Fixed passphrase for in-memory SQLCipher unit tests.
#[cfg(test)]
pub fn test_passphrase() -> &'static str {
    "moonshine-test-sqlcipher-pass"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_v2_roundtrip() {
        let key = test_wrap_key();
        let pt = [0xABu8; 32];
        let wrapped = wrap_secret(&pt, &key);
        assert!(wrapped.starts_with(MAGIC_V2));
        assert_eq!(wrapped.len(), 4 + XNONCE_LEN + pt.len() + TAG_LEN);
        assert_ne!(&wrapped[4 + XNONCE_LEN..4 + XNONCE_LEN + 32], &pt);
        let out = unwrap_secret(&wrapped, &key).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn unwrap_fails_closed_on_plaintext_and_legacy_v1() {
        let key = test_wrap_key();
        let pt = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        assert!(
            unwrap_secret(&pt, &key).is_err(),
            "plaintext must be rejected by fail-closed unwrap_secret"
        );

        let v1 = wrap_secret_legacy_v1(&pt, &key);
        assert!(v1.starts_with(MAGIC_V1));
        assert!(
            unwrap_secret(&v1, &key).is_err(),
            "legacy MSK1 must be rejected by fail-closed unwrap_secret"
        );

        // Migration helper explicitly accepts MSK1 and plaintext and flags needs_rewrite=true.
        let (mig_v1, rewrite_v1) = unwrap_secret_for_migration(&v1, &key).unwrap();
        assert_eq!(mig_v1, pt);
        assert!(rewrite_v1);

        let (mig_pt, rewrite_pt) = unwrap_secret_for_migration(&pt, &key).unwrap();
        assert_eq!(mig_pt, pt);
        assert!(rewrite_pt);

        let v2 = wrap_secret(&pt, &key);
        let (mig_v2, rewrite_v2) = unwrap_secret_for_migration(&v2, &key).unwrap();
        assert_eq!(mig_v2, pt);
        assert!(!rewrite_v2);
    }

    #[test]
    fn wrap_text_roundtrip_and_fail_closed() {
        let key = test_wrap_key();
        let toml = "name = \"DAO\"\nnotes_secret_key = \"secret\"";
        let wrapped = wrap_secret_text(toml, &key);
        assert!(wrapped.starts_with(TEXT_PREFIX_V2));
        assert!(!wrapped.contains("notes_secret_key"));
        assert_eq!(unwrap_secret_text(&wrapped, &key).unwrap(), toml);
        assert!(
            unwrap_secret_text(toml, &key).is_err(),
            "plaintext TOML must be rejected by fail-closed unwrap_secret_text"
        );
        let (mig, needs_rewrite) = unwrap_secret_text_for_migration(toml, &key).unwrap();
        assert_eq!(mig, toml);
        assert!(needs_rewrite);
    }

    #[test]
    fn salted_argon2_varies_with_salt_and_legacy_meta_migrates() {
        let salt_a = [0x11u8; PASS_SALT_LEN];
        let salt_b = [0x22u8; PASS_SALT_LEN];
        let key_a = meta_key_from_passphrase_salted("user-passphrase", &salt_a);
        let key_b = meta_key_from_passphrase_salted("user-passphrase", &salt_b);
        assert_ne!(key_a, key_b, "distinct salts must produce distinct keys");

        // Simulate legacy wallet: static PASS_DOMAIN_V1 + MSK1 wrapped wrap_key.
        let legacy_pass = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let wrap_key = random_wrap_key();
        let legacy_meta_key = meta_key_from_passphrase_legacy(legacy_pass);
        let legacy_stored = wrap_secret_legacy_v1(&wrap_key, &legacy_meta_key);

        let (recovered, needs_rekey) =
            unwrap_meta_wrap_key(&legacy_stored, legacy_pass, None).unwrap();
        assert_eq!(recovered, wrap_key);
        assert!(needs_rekey);

        // Re-wrap with per-wallet random salt as MSK2.
        let new_salt = random_pass_salt();
        let mut stored_salt = Vec::new();
        let mut stored_wrap = Vec::new();
        store_wrap_key_in_meta(
            |k, v| {
                if k == META_PASS_SALT {
                    stored_salt = v.to_vec();
                } else if k == META_WRAP_KEY {
                    stored_wrap = v.to_vec();
                }
                Ok(())
            },
            &wrap_key,
            legacy_pass,
            &new_salt,
        )
        .unwrap();
        assert!(stored_wrap.starts_with(MAGIC_V2));
        let (recovered2, needs_rekey2) =
            unwrap_meta_wrap_key(&stored_wrap, legacy_pass, Some(&stored_salt)).unwrap();
        assert_eq!(recovered2, wrap_key);
        assert!(!needs_rekey2);
    }

    #[test]
    fn overwrite_0600_replaces_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("moonshine-last-tx-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("last-tx.hex");
        write_mode_0600_overwrite(&path, b"aaa").unwrap();
        // Pre-existing permissive mode must be tightened back to 0600.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_mode_0600_overwrite(&path, b"bbb").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"bbb");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_tag_and_wrong_key_rejected() {
        let key = test_wrap_key();
        let mut wrapped = wrap_secret(&[9u8; 32], &key);
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xFF;
        assert!(unwrap_secret(&wrapped, &key).is_err());

        let valid = wrap_secret(&[9u8; 32], &key);
        let mut wrong_key = key;
        wrong_key[0] ^= 0x01;
        assert!(unwrap_secret(&valid, &wrong_key).is_err());
    }
}
