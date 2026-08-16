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

//! Payment memo encoding for `MoneyNote::memo` (OMR-aware wire format).
//!
//! Matches mobile FFI `memo.rs` so CLI and GUIs stay uniform.

/// Magic byte identifying an OMR-aware memo.
pub const OMR_MEMO_MAGIC: u8 = 0x4F;

/// UnifOMR scheme identifier.
pub const SCHEME_UNIFOMR: u8 = 0x05;

const FLAG_HAS_USER_MEMO: u8 = 0x01;
const FLAG_UNIFOMR_VALIDATED: u8 = 0x02;

pub const MAX_PAYMENT_MEMO_BYTES: usize = 255;

/// Build OMR-aware memo bytes for a `MoneyNote`.
pub fn build_omr_memo(
    sender_secret: &[u8; 32],
    recipient_pubkey: &[u8; 32],
    user_memo: Option<&str>,
    scheme: Option<u8>,
) -> Result<Vec<u8>, String> {
    let scheme = scheme.unwrap_or(SCHEME_UNIFOMR);

    let mut hasher = blake3::Hasher::new_keyed(sender_secret);
    hasher.update(recipient_pubkey);
    hasher.update(b"DarkFi-OMR-TxClue-v1");
    hasher.update(&[scheme]);
    let clue_seed: [u8; 32] = hasher.finalize().into();

    let memo_text = user_memo.map(str::trim).filter(|s| !s.is_empty());
    if let Some(text) = memo_text {
        if text.len() > MAX_PAYMENT_MEMO_BYTES {
            return Err(format!(
                "memo exceeds {} bytes (UTF-8 length {})",
                MAX_PAYMENT_MEMO_BYTES,
                text.len()
            ));
        }
    }

    let mut buf = Vec::with_capacity(36 + memo_text.map_or(0, |t| t.len()));
    buf.push(OMR_MEMO_MAGIC);
    buf.push(scheme);

    let mut flags: u8 = 0;
    if memo_text.is_some() {
        flags |= FLAG_HAS_USER_MEMO;
    }
    if scheme == SCHEME_UNIFOMR {
        flags |= FLAG_UNIFOMR_VALIDATED;
    }
    buf.push(flags);
    buf.extend_from_slice(&clue_seed);

    if let Some(text) = memo_text {
        let text_bytes = text.as_bytes();
        buf.push(text_bytes.len() as u8);
        buf.extend_from_slice(text_bytes);
    } else {
        buf.push(0u8);
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_omr_metadata_roundtrip() {
        use darkfi_sdk::crypto::{PublicKey, SecretKey};

        let sk = SecretKey::random(&mut rand_core::OsRng);
        let pk = PublicKey::from_secret(sk);

        let metadata = build_omr_memo(&[0x42; 32], &[0xAB; 32], Some("hello"), None).unwrap();
        let encrypted = encrypt_omr_metadata(&metadata, &pk).unwrap();
        let decrypted = decrypt_omr_metadata(&encrypted, &sk).unwrap();
        assert_eq!(decrypted, metadata);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        use darkfi_sdk::crypto::{PublicKey, SecretKey};

        let sk1 = SecretKey::random(&mut rand_core::OsRng);
        let pk1 = PublicKey::from_secret(sk1);
        let sk2 = SecretKey::random(&mut rand_core::OsRng);

        let metadata = build_omr_memo(&[0x01; 32], &[0x02; 32], None, None).unwrap();
        let encrypted = encrypt_omr_metadata(&metadata, &pk1).unwrap();
        assert!(decrypt_omr_metadata(&encrypted, &sk2).is_none());
    }
}

// ---------------------------------------------------------------------------
// Encrypted OMR metadata — off-chain channel via LWD
// ---------------------------------------------------------------------------

#[cfg(test)]
use darkfi_sdk::crypto::SecretKey;
use darkfi_sdk::crypto::{note::AeadEncryptedNote, PublicKey};
use darkfi_serial::{serialize, Decodable, Encodable};

#[derive(Clone, Debug)]
struct OmrMetadataBlob(Vec<u8>);

impl Encodable for OmrMetadataBlob {
    fn encode<S: std::io::Write>(&self, s: &mut S) -> std::result::Result<usize, std::io::Error> {
        self.0.encode(s)
    }
}

impl Decodable for OmrMetadataBlob {
    fn decode<D: std::io::Read>(d: &mut D) -> std::result::Result<Self, std::io::Error> {
        let v = Vec::<u8>::decode(d)?;
        Ok(Self(v))
    }
}

/// Encrypt OMR metadata for the recipient via AeadEncryptedNote.
pub fn encrypt_omr_metadata(
    metadata: &[u8],
    recipient_pubkey: &PublicKey,
) -> Result<Vec<u8>, String> {
    let blob = OmrMetadataBlob(metadata.to_vec());
    let mut rng = rand_core::OsRng;
    let enc_note = AeadEncryptedNote::encrypt(&blob, recipient_pubkey, &mut rng)
        .map_err(|e| format!("Failed to encrypt OMR metadata: {e}"))?;
    Ok(serialize(&enc_note))
}

/// Decrypt OMR metadata from CompactOutput.omr_metadata_enc.
///
/// The receive path recovers memos from the trial-decrypted `MoneyNote`
/// itself, so this is only exercised as the AEAD round-trip check in tests.
#[cfg(test)]
pub fn decrypt_omr_metadata(encrypted_bytes: &[u8], secret_key: &SecretKey) -> Option<Vec<u8>> {
    if encrypted_bytes.len() < 48 {
        return None;
    }
    let mut cursor = std::io::Cursor::new(encrypted_bytes);
    let enc_note = AeadEncryptedNote::decode(&mut cursor).ok()?;
    let blob: OmrMetadataBlob = enc_note.decrypt(secret_key).ok()?;
    Some(blob.0)
}
