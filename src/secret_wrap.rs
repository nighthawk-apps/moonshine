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

//! At-rest wrapping for wallet secret keys stored in SQLite (S14).
//!
//! Full-DB encryption uses SQLCipher (`bundled-sqlcipher-vendored-openssl`)
//! keyed by `MOONSHINE_WALLET_PASS` or a generated `{db}.pass` file (mode 0600).
//!
//! Address `secret_key` BLOBs are additionally wrapped with a blake3 keystream
//! (MSK1 magic) keyed by a 32-byte wrap key in `{db}.wrapkey` (mode 0600).
//! That wrap key is also stored inside `wallet_meta`, itself wrapped under a
//! key derived from the wallet passphrase.

use rand::RngCore;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const MAGIC: &[u8; 4] = b"MSK1";
const NONCE_LEN: usize = 16;
const DOMAIN: &[u8] = b"DarkFi-Moonshine-SecretWrap-v1";
const PASS_DOMAIN: &[u8] = b"DarkFi-Moonshine-WalletPass-v1";
/// `wallet_meta` key for the passphrase-wrapped wrap key.
pub const META_WRAP_KEY: &str = "wrap_key";

fn keystream(key: &[u8; 32], nonce: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u64;
    while out.len() < len {
        let mut h = blake3::Hasher::new_keyed(key);
        h.update(DOMAIN);
        h.update(nonce);
        h.update(&counter.to_le_bytes());
        let block = *h.finalize().as_bytes();
        let need = (len - out.len()).min(32);
        out.extend_from_slice(&block[..need]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// Wrap plaintext secret bytes for storage.
pub fn wrap_secret(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let stream = keystream(key, &nonce, plaintext.len());
    let mut ct: Vec<u8> = plaintext
        .iter()
        .zip(stream.iter())
        .map(|(p, s)| p ^ s)
        .collect();

    let mut out = Vec::with_capacity(4 + NONCE_LEN + ct.len() + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.append(&mut ct);

    let mut mac = blake3::Hasher::new_keyed(key);
    mac.update(DOMAIN);
    mac.update(b"-mac");
    mac.update(&out);
    out.extend_from_slice(&mac.finalize().as_bytes()[..16]);
    out
}

/// Unwrap a stored secret. Plaintext (no MAGIC) is returned as-is for migration.
pub fn unwrap_secret(stored: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if stored.len() < 4 || &stored[..4] != MAGIC {
        // Plaintext row — accept for migration.
        return Ok(stored.to_vec());
    }
    if stored.len() < 4 + NONCE_LEN + 16 {
        return Err("Wrapped secret too short".into());
    }
    let (body, mac) = stored.split_at(stored.len() - 16);
    let mut expected = blake3::Hasher::new_keyed(key);
    expected.update(DOMAIN);
    expected.update(b"-mac");
    expected.update(body);
    if mac != &expected.finalize().as_bytes()[..16] {
        return Err("Wrapped secret MAC mismatch".into());
    }
    let nonce = &body[4..4 + NONCE_LEN];
    let ct = &body[4 + NONCE_LEN..];
    let stream = keystream(key, nonce, ct.len());
    Ok(ct.iter().zip(stream.iter()).map(|(c, s)| c ^ s).collect())
}

/// Derive a 32-byte meta-encryption key from a user passphrase.
///
/// H4: Uses Argon2id (64MB, 3 iterations) for key stretching to resist
/// brute-force attacks on user-chosen passphrases. Auto-generated hex
/// passphrases (64 hex chars = 256 bits entropy) are already strong and
/// skip Argon2id for performance — they use fast blake3 instead.
fn meta_key_from_passphrase(pass: &str) -> [u8; 32] {
    // Auto-generated passphrases are 64 hex chars (256-bit entropy);
    // stretching is unnecessary and would slow every wallet open.
    if pass.len() == 64 && pass.chars().all(|c| c.is_ascii_hexdigit()) {
        return meta_key_from_passphrase_fast(pass);
    }
    meta_key_from_passphrase_argon2(pass)
}

/// Legacy fast-hash derivation (blake3). Used for auto-generated high-entropy
/// passphrases and backwards compatibility during migration.
fn meta_key_from_passphrase_fast(pass: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PASS_DOMAIN);
    h.update(pass.as_bytes());
    *h.finalize().as_bytes()
}

/// Argon2id key stretching for user-supplied passphrases.
/// Parameters: 64 MB memory, 3 iterations, 1 parallelism.
fn meta_key_from_passphrase_argon2(pass: &str) -> [u8; 32] {
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
        .hash_password_into(pass.as_bytes(), PASS_DOMAIN, &mut key)
        .expect("Argon2id hash");
    key
}

/// Load passphrase from `MOONSHINE_WALLET_PASS`, else `{db}.pass` (create 0600).
pub fn load_or_create_passphrase(db_path: &str) -> Result<String, String> {
    if let Ok(pass) = env::var("MOONSHINE_WALLET_PASS") {
        if !pass.is_empty() {
            return Ok(pass);
        }
    }
    let pass_path = format!("{db_path}.pass");
    if Path::new(&pass_path).exists() {
        let mut s = String::new();
        fs::File::open(&pass_path)
            .and_then(|mut f| f.read_to_string(&mut s))
            .map_err(|e| e.to_string())?;
        let s = s.trim().to_string();
        if s.is_empty() {
            return Err("Empty wallet passphrase file".into());
        }
        return Ok(s);
    }
    // Generate a random passphrase and store with mode 0600.
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let pass = hex::encode(raw);
    write_mode_0600(&pass_path, pass.as_bytes())?;
    Ok(pass)
}

/// Write bytes to a new file with mode 0600.
fn write_mode_0600(path: &str, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut f = opts.open(path).map_err(|e| e.to_string())?;
    f.write_all(data).map_err(|e| e.to_string())?;
    Ok(())
}

/// Load or create a 32-byte wrap key beside the wallet DB path (`{db}.wrapkey`).
pub fn load_or_create_wrap_key(db_path: &str) -> Result<[u8; 32], String> {
    let key_path = format!("{db_path}.wrapkey");
    if Path::new(&key_path).exists() {
        let mut f = fs::File::open(&key_path).map_err(|e| e.to_string())?;
        let mut key = [0u8; 32];
        f.read_exact(&mut key).map_err(|e| e.to_string())?;
        return Ok(key);
    }
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    write_mode_0600(&key_path, &key)?;
    Ok(key)
}

/// Persist the wrap key into `wallet_meta`, wrapped under a passphrase-derived key.
pub fn store_wrap_key_in_meta(
    set_meta: impl FnOnce(&str, &[u8]) -> Result<(), String>,
    wrap_key: &[u8; 32],
    passphrase: &str,
) -> Result<(), String> {
    let meta_key = meta_key_from_passphrase(passphrase);
    let wrapped = wrap_secret(wrap_key, &meta_key);
    set_meta(META_WRAP_KEY, &wrapped)
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
    fn wrap_roundtrip() {
        let key = test_wrap_key();
        let pt = [0xABu8; 32];
        let wrapped = wrap_secret(&pt, &key);
        assert!(wrapped.starts_with(MAGIC));
        assert_ne!(&wrapped[4 + NONCE_LEN..4 + NONCE_LEN + 32], &pt);
        let out = unwrap_secret(&wrapped, &key).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn plaintext_passthrough() {
        let key = test_wrap_key();
        let pt = vec![1u8, 2, 3, 4];
        assert_eq!(unwrap_secret(&pt, &key).unwrap(), pt);
    }

    #[test]
    fn tampered_mac_rejected() {
        let key = test_wrap_key();
        let mut wrapped = wrap_secret(&[9u8; 32], &key);
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xFF;
        assert!(unwrap_secret(&wrapped, &key).is_err());
    }
}
