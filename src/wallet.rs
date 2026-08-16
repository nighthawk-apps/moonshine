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

//! Moonshine wallet implementation.
//!
//! Manages key derivation, address generation, and local state
//! backed by the SQLite database. Uses the same DarkFi 22-word mnemonic
//! format as the Android/iOS wallet apps, ensuring full wallet compatibility.

use crate::db::WalletDb;
use crate::mnemonic::{self, DarkfiMnemonic};
use darkfi_sdk::crypto::keypair::{Address, Network, StandardAddress};
use darkfi_sdk::crypto::pasta_prelude::PrimeField;
use darkfi_sdk::crypto::SecretKey;
use std::error::Error;
use std::io::IsTerminal;
use std::path::Path;

/// Domain separation for `RegisterCluePublicKey` ownership proofs (v2:
/// binds network byte + monotonic key_version against replay).
const CLUE_PK_OWNERSHIP_DOMAIN: &[u8] = b"DarkFi-UnifOMR-CluePK-v2";

/// Sign `RegisterCluePublicKey` with the payment [`SecretKey`] (Schnorr + darkfi-serial).
///
/// Message: `domain || network || key_version (u64 LE) || payment_pubkey || clue_public_key`.
pub fn sign_clue_pk_ownership(
    payment_sk: &SecretKey,
    network: u8,
    key_version: u64,
    payment_pubkey: &[u8; 32],
    clue_public_key: &[u8],
) -> Vec<u8> {
    use darkfi_sdk::crypto::schnorr::SchnorrSecret;
    use darkfi_serial::serialize;
    let mut msg = Vec::with_capacity(
        CLUE_PK_OWNERSHIP_DOMAIN.len() + 9 + payment_pubkey.len() + clue_public_key.len(),
    );
    msg.extend_from_slice(CLUE_PK_OWNERSHIP_DOMAIN);
    msg.push(network);
    msg.extend_from_slice(&key_version.to_le_bytes());
    msg.extend_from_slice(payment_pubkey);
    msg.extend_from_slice(clue_public_key);
    let sig = payment_sk.sign(&msg);
    serialize(&sig)
}

/// Monotonic clue-key version for registrations (unix seconds).
pub fn clue_key_version_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
}

/// The main wallet handle.
pub struct Wallet {
    pub name: String,
    pub db: WalletDb,
}

impl Wallet {
    /// Create a new wallet with a fresh DarkFi 22-word mnemonic.
    ///
    /// The mnemonic format is identical to the Android/iOS apps:
    /// - 22 words from the standard 2048-word English wordlist
    /// - Electrum-style BigUint encoding
    /// - HMAC-SHA512 prefix validation
    /// - 232 bits of entropy
    ///
    /// The resulting mnemonic can be imported into any DarkFi wallet
    /// (Android, iOS, Moonshine) and will produce the same secret key.
    pub fn create(name: &str, network: &str) -> Result<Self, Box<dyn Error>> {
        let db_path = Self::db_path(name);

        // Ensure wallet directory exists
        if let Some(parent) = Path::new(&db_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        if Path::new(&db_path).exists() {
            return Err(format!("Wallet '{}' already exists at {}", name, db_path).into());
        }

        let db = WalletDb::open(&db_path)?;

        // Generate a new DarkFi 22-word mnemonic
        let mnemonic_engine = DarkfiMnemonic::default();
        let phrase = mnemonic_engine
            .make_seed(None, None)
            .map_err(|e| format!("Failed to generate mnemonic: {e}"))?;

        let words: Vec<String> = phrase.split_whitespace().map(|s| s.to_string()).collect();

        // Derive the secret key (same derivation as Android/iOS)
        let secret_key = mnemonic::secret_key_from_mnemonic(&words)
            .map_err(|e| format!("Key derivation failed: {e}"))?;

        let secret_bytes = secret_key.inner().to_repr();

        // Store seed hash for OMR key derivation (never store the seed/mnemonic)
        let seed_hash = blake3::hash(&secret_bytes);
        db.set_meta("seed_hash", seed_hash.as_bytes())?;
        db.set_meta("wallet_version", &[0x02])?;
        db.set_meta("mnemonic_word_count", &[words.len() as u8])?;
        db.set_meta("network", network.as_bytes())?;

        // Derive address from public key (DarkFi Address for configured network)
        let public_key = darkfi_sdk::crypto::PublicKey::from_secret(secret_key);
        let addr = Address::Standard(StandardAddress::from_public(
            Self::sdk_network(network),
            public_key,
        ));
        let public_hex = addr.to_string();

        db.insert_address(&public_hex, &secret_bytes)?;
        db.set_default_address(&public_hex)?;

        // Mnemonic must never hit stdout (pipes/logs). Only print to an interactive stderr TTY.
        if !std::io::stderr().is_terminal() {
            return Err("Refusing to print mnemonic: stderr is not a TTY. \
                 Run `moonshine wallet create` in an interactive terminal to back up the seed."
                .into());
        }
        eprintln!();
        eprintln!("╔════════════════════════════════════════════════╗");
        eprintln!("║         BACKUP YOUR MNEMONIC SEED              ║");
        eprintln!("╠════════════════════════════════════════════════╣");
        for (i, word) in words.iter().enumerate() {
            eprintln!("║  {:2}. {:<42} ║", i + 1, word);
        }
        eprintln!("╠════════════════════════════════════════════════╣");
        eprintln!("║  WARNING: Write these words down and store     ║");
        eprintln!("║  them securely offline. Anyone with this       ║");
        eprintln!("║  mnemonic can spend your funds. It works in    ║");
        eprintln!("║  ALL DarkFi wallets and CANNOT be recovered.   ║");
        eprintln!("╚════════════════════════════════════════════════╝");
        eprintln!();

        println!("Wallet '{}' created successfully.", name);
        println!("Default address: {}", public_hex);

        Ok(Self {
            name: name.to_string(),
            db,
        })
    }

    /// Import a wallet from an existing DarkFi mnemonic phrase.
    ///
    /// Accepts the same 22-word mnemonic used by Android/iOS DarkFi wallets.
    pub fn import(
        name: &str,
        mnemonic_words: &[String],
        network: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let db_path = Self::db_path(name);

        if let Some(parent) = Path::new(&db_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        if Path::new(&db_path).exists() {
            return Err(format!("Wallet '{}' already exists at {}", name, db_path).into());
        }

        // Validate the mnemonic
        let engine = DarkfiMnemonic::default();
        let phrase = mnemonic_words.join(" ");
        if !engine.validate(&phrase) {
            return Err("Invalid DarkFi mnemonic phrase. Check your words and try again.".into());
        }

        // Derive the same secret key as the mobile wallet
        let secret_key = mnemonic::secret_key_from_mnemonic(mnemonic_words)
            .map_err(|e| format!("Key derivation failed: {e}"))?;

        let secret_bytes = secret_key.inner().to_repr();

        let db = WalletDb::open(&db_path)?;

        // Store seed hash (same as create)
        let seed_hash = blake3::hash(&secret_bytes);
        db.set_meta("seed_hash", seed_hash.as_bytes())?;
        db.set_meta("wallet_version", &[0x02])?;
        db.set_meta("network", network.as_bytes())?;

        let public_key = darkfi_sdk::crypto::PublicKey::from_secret(secret_key);
        let addr = Address::Standard(StandardAddress::from_public(
            Self::sdk_network(network),
            public_key,
        ));
        let public_hex = addr.to_string();
        db.insert_address(&public_hex, &secret_bytes)?;
        db.set_default_address(&public_hex)?;

        println!("Wallet '{}' imported successfully.", name);
        println!("Default address: {}", public_hex);

        Ok(Self {
            name: name.to_string(),
            db,
        })
    }

    /// Open an existing wallet.
    pub fn open(name: &str) -> Result<Self, Box<dyn Error>> {
        let db_path = Self::db_path(name);
        if !Path::new(&db_path).exists() {
            return Err(format!("Wallet '{}' not found at {}", name, db_path).into());
        }

        let db = WalletDb::open(&db_path)?;
        Ok(Self {
            name: name.to_string(),
            db,
        })
    }

    /// Max wallet pubkeys registered for UnifOMR clue PK (sub-address cap).
    pub const MAX_OMR_DETECT_PUBKEYS: usize = 16;

    /// Map config network string to SDK `Network` (mainnet vs testnet/localnet).
    pub fn sdk_network(network: &str) -> Network {
        if network.eq_ignore_ascii_case("mainnet") {
            Network::Mainnet
        } else {
            Network::Testnet
        }
    }

    /// Network stored at wallet create/import (defaults to testnet).
    pub fn stored_network(&self) -> Network {
        match self.db.get_meta("network") {
            Ok(Some(bytes)) => Self::sdk_network(&String::from_utf8_lossy(&bytes)),
            _ => Network::Testnet,
        }
    }

    /// Map config network string to OMR network byte (mainnet=0x00, else 0x01).
    pub fn network_byte(network: &str) -> u8 {
        if network.eq_ignore_ascii_case("mainnet") {
            0x00
        } else {
            0x01
        }
    }

    /// Build paper UnifOMR detection key (BFV Enc of RLWE sk_clue coeffs).
    pub fn derive_unifomr_detection_key(&self, network: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let secret = self.wallet_secret_bytes()?;
        let net = Self::network_byte(network);
        let client = darkfi_lightwalletd::unifomr::UnifOmrClient::from_wallet(&secret, net)?;
        Ok(client.build_detection_key(net)?)
    }

    /// Serialized UnifOMR clue public key for RegisterCluePublicKey.
    pub fn unifomr_clue_public_key(&self, network: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let secret = self.wallet_secret_bytes()?;
        let net = Self::network_byte(network);
        let (_sk, pk) = darkfi_lightwalletd::unifomr::clue_keypair_from_wallet(&secret, net)?;
        Ok(darkfi_lightwalletd::unifomr::serialize_public_key(&pk))
    }

    /// Collect recipient pubkeys for OMR: default first, then others, capped at 16.
    pub fn recipient_pubkeys_for_omr(&self) -> Result<Vec<[u8; 32]>, Box<dyn Error>> {
        use darkfi_sdk::crypto::{PublicKey, SecretKey};

        let rows = self.db.get_all_address_keys()?;
        if rows.is_empty() {
            return Err("No wallet addresses found".into());
        }

        let mut default_pk: Option<[u8; 32]> = None;
        let mut others: Vec<[u8; 32]> = Vec::new();

        for (_addr_str, secret_bytes, is_default) in rows {
            if secret_bytes.len() < 32 {
                continue;
            }
            let mut sk_arr = [0u8; 32];
            sk_arr.copy_from_slice(&secret_bytes[..32]);
            let Ok(sk) = SecretKey::from_bytes(sk_arr) else {
                continue;
            };
            let pk = PublicKey::from_secret(sk).to_bytes();
            if is_default {
                default_pk = Some(pk);
            } else if !others.iter().any(|e| e == &pk) {
                others.push(pk);
            }
        }

        let mut out = Vec::new();
        if let Some(pk) = default_pk {
            out.push(pk);
        }
        for pk in others {
            if !out.iter().any(|e| e == &pk) {
                out.push(pk);
            }
        }
        // Fallback: if no is_default row, use first derived pubkey.
        if out.is_empty() {
            out.push(self.default_pubkey_bytes()?);
        }
        if out.len() > Self::MAX_OMR_DETECT_PUBKEYS {
            tracing::warn!(
                "Wallet has {} addresses; OMR queries only the first {} (default-first)",
                out.len(),
                Self::MAX_OMR_DETECT_PUBKEYS
            );
            out.truncate(Self::MAX_OMR_DETECT_PUBKEYS);
        }
        Ok(out)
    }

    /// First wallet secret key bytes (32) used for UnifOMR KDF.
    pub fn wallet_secret_bytes(&self) -> Result<[u8; 32], Box<dyn Error>> {
        let secret_bytes = self
            .db
            .get_all_secrets()?
            .into_iter()
            .next()
            .ok_or("No wallet secrets found")?;
        if secret_bytes.len() < 32 {
            return Err("Wallet secret too short".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret_bytes[..32]);
        Ok(arr)
    }

    /// Default address public key bytes (32 bytes).
    pub fn default_pubkey_bytes(&self) -> Result<[u8; 32], Box<dyn Error>> {
        use darkfi_sdk::crypto::{PublicKey, SecretKey};

        let secret_bytes = self.wallet_secret_bytes()?;
        let sk = SecretKey::from_bytes(secret_bytes)
            .map_err(|e| -> Box<dyn Error> { format!("Invalid secret key: {e:?}").into() })?;
        Ok(PublicKey::from_secret(sk).to_bytes())
    }

    /// Return the 32-byte master secret (seed hash) for OMR clue derivation.
    ///
    /// This is the Blake3 hash of the wallet's secret key bytes. Hard-fails
    /// if `seed_hash` is missing (S6 — no zero-key fallback).
    #[cfg(test)]
    pub fn master_secret(&self) -> Result<[u8; 32], Box<dyn Error>> {
        let v = self
            .db
            .get_meta("seed_hash")?
            .ok_or("Wallet seed_hash missing — recreate or re-import wallet")?;
        if v.len() < 32 {
            return Err("Wallet seed_hash too short (need 32 bytes)".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v[..32]);
        Ok(arr)
    }

    /// Generate a new address for this wallet.
    pub fn generate_address(&self) -> Result<String, Box<dyn Error>> {
        let seed_hash = self
            .db
            .get_meta("seed_hash")?
            .ok_or("Wallet seed hash not found")?;

        // Derive a unique sub-key for this address index
        let addrs = self.db.list_addresses()?;
        let index = addrs.len() as u32;
        let mut derivation_input = seed_hash.clone();
        derivation_input.extend_from_slice(&index.to_le_bytes());

        let base_bytes = blake3::derive_key("moonshine-address-key-v2", &derivation_input);

        // Try counter-XOR approach (same as mnemonic key derivation)
        // to find a valid pallas scalar
        let mut secret_key = None;
        for counter in 0u8..=255 {
            let mut bytes = base_bytes;
            bytes[31] ^= counter;
            if let Ok(key) = SecretKey::from_bytes(bytes) {
                secret_key = Some((key, bytes));
                break;
            }
        }

        let (sk, secret_bytes) =
            secret_key.ok_or("Failed to derive valid address key after 256 attempts")?;
        let public_key = darkfi_sdk::crypto::PublicKey::from_secret(sk);
        let addr = Address::Standard(StandardAddress::from_public(
            self.stored_network(),
            public_key,
        ));
        let public_hex = addr.to_string();

        self.db.insert_address(&public_hex, &secret_bytes)?;
        println!("New address: {}", public_hex);
        Ok(public_hex)
    }

    /// Get wallet database path.
    pub fn db_path(name: &str) -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{}/.config/moonshine/wallets/{}.db", home, name)
    }

    /// Delete a wallet database.
    pub fn delete(name: &str) -> Result<(), Box<dyn Error>> {
        let db_path = Self::db_path(name);
        if Path::new(&db_path).exists() {
            std::fs::remove_file(&db_path)?;
            println!("Wallet '{}' deleted.", name);
        } else {
            println!("Wallet '{}' not found.", name);
        }
        Ok(())
    }

    /// List all wallet databases.
    pub fn list_wallets() -> Result<Vec<String>, Box<dyn Error>> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let wallets_dir = format!("{}/.config/moonshine/wallets", home);
        let mut names = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&wallets_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".db") {
                        names.push(name.trim_end_matches(".db").to_string());
                    }
                }
            }
        }
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unifomr_detection_key_derivation() {
        let words: Vec<String> = vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let sk = crate::mnemonic::secret_key_from_mnemonic(&words).unwrap();
        let secret_bytes = sk.inner().to_repr();

        let db = WalletDb::in_memory().unwrap();
        let seed_hash = blake3::hash(b"test-seed").as_bytes().to_vec();
        db.set_meta("seed_hash", &seed_hash).unwrap();
        db.insert_address("addr0", secret_bytes.as_ref()).unwrap();
        db.set_default_address("addr0").unwrap();

        let wallet = Wallet {
            name: "test".to_string(),
            db,
        };

        let dk = wallet.derive_unifomr_detection_key("testnet").unwrap();
        assert!(!dk.is_empty(), "UnifOMR detection key must be non-empty");
        let pk = wallet.unifomr_clue_public_key("testnet").unwrap();
        assert!(!pk.is_empty(), "UnifOMR clue public key must be non-empty");
    }

    #[test]
    fn test_multi_pubkey_omr_order() {
        use darkfi_sdk::crypto::PublicKey;

        let words: Vec<String> = vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let sk0 = crate::mnemonic::secret_key_from_mnemonic(&words).unwrap();
        let secret0 = sk0.inner().to_repr();

        let db = WalletDb::in_memory().unwrap();
        let seed_hash = blake3::hash(b"test-seed-multi").as_bytes().to_vec();
        db.set_meta("seed_hash", &seed_hash).unwrap();
        db.insert_address("addr0", secret0.as_ref()).unwrap();
        db.set_default_address("addr0").unwrap();

        let wallet = Wallet {
            name: "test-multi".to_string(),
            db,
        };
        let _addr1 = wallet.generate_address().unwrap();

        let pubkeys = wallet.recipient_pubkeys_for_omr().unwrap();
        assert!(
            pubkeys.len() >= 2,
            "expected default + generated address, got {}",
            pubkeys.len()
        );
        assert_eq!(
            pubkeys[0],
            PublicKey::from_secret(sk0).to_bytes(),
            "default pubkey must be first"
        );
    }

    #[test]
    fn test_network_byte_mapping() {
        assert_eq!(Wallet::network_byte("mainnet"), 0x00);
        assert_eq!(Wallet::network_byte("Mainnet"), 0x00);
        assert_eq!(Wallet::network_byte("testnet"), 0x01);
        assert_eq!(Wallet::network_byte("other"), 0x01);
    }

    #[test]
    fn test_master_secret_missing_fails() {
        let db = WalletDb::in_memory().unwrap();
        let wallet = Wallet {
            name: "nosseed".to_string(),
            db,
        };
        assert!(wallet.master_secret().is_err());
    }

    #[test]
    fn test_generate_address_unique() {
        let db = WalletDb::in_memory().unwrap();
        let seed_hash = blake3::hash(b"test-seed").as_bytes().to_vec();
        db.set_meta("seed_hash", &seed_hash).unwrap();
        db.insert_address("addr0", &[0]).unwrap();

        let wallet = Wallet {
            name: "test".to_string(),
            db,
        };

        let addr1 = wallet.generate_address().unwrap();
        let addr2 = wallet.generate_address().unwrap();
        assert_ne!(addr1, addr2, "Addresses must be unique");
    }
}
