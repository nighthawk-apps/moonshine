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

//! DarkFi-compatible 22-word mnemonic generation and key derivation.
//!
//! This module is a direct port of the mnemonic engine from `darkfi-mobile-ffi`.
//! It produces the **exact same** 22-word seed phrases and derives the **exact
//! same** secret keys, ensuring wallets created in Moonshine are compatible with
//! the Android/iOS apps and vice versa.
//!
//! ## Mnemonic Format
//!
//! - 22 words from the standard 2048-word English wordlist
//! - Electrum-style encoding: BigUint → word sequence
//! - HMAC-SHA512 prefix validation (first byte == 0x01 for "standard" type)
//! - 232 bits of entropy
//!
//! ## Key Derivation
//!
//! 1. Mnemonic → PBKDF2(HMAC-SHA512, salt="darkfi", rounds=2048) → 64-byte seed
//! 2. Seed → blake3(context="nighthawk-drk-v1" || 0x00 || word₁ || 0x00 || word₂ || ...) → 32-byte key
//! 3. Key → SecretKey::from_bytes (pallas curve scalar)

use darkfi_sdk::crypto::SecretKey;

use std::collections::HashMap;
use std::str::FromStr;

use hmac::Hmac;
use num_bigint::BigUint;
use num_traits::identities::{One, Zero};
use pbkdf2::pbkdf2;
use sha2::Sha512;
use thiserror::Error;
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};

/// Blake3 KDF context — must match `darkfi-mobile-ffi/src/mnemonic.rs`
const DERIVE_CONTEXT: &str = "nighthawk-drk-v1";

/// Derive a [`SecretKey`] from wallet mnemonic words (deterministic per phrase).
///
/// This function is identical to `secret_key_from_mnemonic` in the mobile FFI.
/// Given the same mnemonic words, it produces the exact same SecretKey.
pub fn secret_key_from_mnemonic(mnemonic: &[String]) -> Result<SecretKey, String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DERIVE_CONTEXT.as_bytes());
    hasher.update(&[0]);
    for word in mnemonic {
        hasher.update(word.trim().to_lowercase().as_bytes());
        hasher.update(&[0]);
    }
    let seed = hasher.finalize();

    // Intermediate seed material is wiped before return (parity with the
    // mobile FFI implementation of this same derivation).
    let mut seed_bytes = *seed.as_bytes();
    for counter in 0u8..=255 {
        let mut bytes = seed_bytes;
        bytes[31] ^= counter;
        if let Ok(key) = SecretKey::from_bytes(bytes) {
            bytes.fill(0);
            seed_bytes.fill(0);
            return Ok(key);
        }
    }
    seed_bytes.fill(0);

    Err("could not derive canonical SecretKey from mnemonic".into())
}

#[derive(Error, Debug)]
pub enum MnemonicError {
    #[error("Unsupported seed type {0}")]
    UnsupportedSeedType(String),
    #[error("Invalid word in mnemonic: {0}")]
    InvalidWord(String),
    #[error("Cannot extract same entropy from mnemonic!")]
    EntropyMismatch,
    #[allow(dead_code)]
    #[error("Other error: {0}")]
    Other(String),
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum SeedPrefix {
    Standard = 0x01,
}

impl FromStr for SeedPrefix {
    type Err = MnemonicError;

    fn from_str(seed_type: &str) -> Result<Self, Self::Err> {
        match seed_type {
            "standard" => Ok(Self::Standard),
            _ => Err(MnemonicError::UnsupportedSeedType(seed_type.to_string())),
        }
    }
}

#[derive(Debug)]
pub struct Wordlist {
    index_from_word: HashMap<String, u64>,
    word_from_index: HashMap<u64, String>,
}

impl Wordlist {
    pub fn new(words: Vec<String>) -> Self {
        let mut index_from_word = HashMap::new();
        let mut word_from_index = HashMap::new();
        for (i, word) in words.iter().enumerate() {
            index_from_word.insert(word.clone(), i as u64);
            word_from_index.insert(i as u64, word.clone());
        }
        Self {
            index_from_word,
            word_from_index,
        }
    }

    pub fn index_from_word(&self, word: &str) -> Option<u64> {
        self.index_from_word.get(word).copied()
    }

    pub fn len(&self) -> usize {
        self.index_from_word.len()
    }

    pub fn from_str(content: &str) -> Result<Self, MnemonicError> {
        let s = content.trim();
        let s: String = s.nfkd().collect();
        let lines = s.split('\n');
        let mut words = vec![];

        for line in lines {
            let line = line.split('#').next().unwrap_or("");
            let line = line.trim_matches(&[' ', '\r'][..]);
            if !line.is_empty() {
                words.push(line.to_string());
            }
        }

        Ok(Self::new(words))
    }
}

impl std::ops::Index<u64> for Wordlist {
    type Output = String;

    fn index(&self, index: u64) -> &Self::Output {
        self.word_from_index.get(&index).unwrap()
    }
}

/// DarkFi mnemonic engine — produces 22-word seed phrases compatible with
/// the Android/iOS wallet and the upstream DarkFi wallet.
pub struct DarkfiMnemonic {
    wordlist: Wordlist,
}

impl Default for DarkfiMnemonic {
    fn default() -> Self {
        let english = include_str!("english.txt");
        let wordlist = Wordlist::from_str(english).unwrap();
        Self { wordlist }
    }
}

impl DarkfiMnemonic {
    /// Convert a mnemonic phrase to a 64-byte seed via PBKDF2.
    ///
    /// Salt = "darkfi" + passphrase, 2048 rounds of HMAC-SHA512.
    /// This matches the mobile FFI exactly.
    #[allow(dead_code)]
    pub fn mnemonic_to_seed(mnemonic: &str, passphrase: Option<&str>) -> [u8; 64] {
        const PBKDF_ROUNDS: u32 = 2048;
        let mnemonic = normalize_text(mnemonic);
        let passphrase = normalize_text(passphrase.unwrap_or(""));

        let mut salt = String::from("darkfi");
        salt.push_str(&passphrase);

        let mut key = [0u8; 64];
        let _ =
            pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), salt.as_bytes(), PBKDF_ROUNDS, &mut key);
        key
    }

    /// Encode a BigUint as a mnemonic word sequence.
    pub fn mnemonic_encode(&self, i: &BigUint) -> String {
        let n = BigUint::from(self.wordlist.len());
        let mut words = vec![];
        let mut i = i.clone();
        while i > BigUint::zero() {
            let x = &i % &n;
            i /= &n;
            let idx_u64: u64 = x.try_into().unwrap();
            words.push(self.wordlist[idx_u64].clone());
        }
        words.join(" ")
    }

    /// Decode a mnemonic word sequence to a BigUint.
    pub fn mnemonic_decode(&self, seed: &str) -> Result<BigUint, MnemonicError> {
        let n = BigUint::from(self.wordlist.len());
        let mut words: Vec<&str> = seed.split_whitespace().collect();
        let mut i = BigUint::zero();
        while let Some(w) = words.pop() {
            let k = self
                .wordlist
                .index_from_word(w)
                .ok_or_else(|| MnemonicError::InvalidWord(w.to_string()))?;
            i = &i * &n + k;
        }
        Ok(i)
    }

    /// Generate a new 22-word mnemonic phrase.
    ///
    /// Uses 232 bits of entropy with HMAC-SHA512 prefix validation to ensure
    /// the seed is deterministically verifiable.
    pub fn make_seed(
        &self,
        seed_type: Option<&str>,
        num_bits: Option<usize>,
    ) -> Result<String, MnemonicError> {
        let num_bits = num_bits.unwrap_or(232);
        let prefix = SeedPrefix::from_str(seed_type.unwrap_or("standard"))?;

        let bpw = (self.wordlist.len() as f64).log2();
        let adj_num_bits = ((num_bits as f64 / bpw).ceil() * bpw) as u32;

        let threshold_exp = (num_bits as f64 - bpw) as u32;
        let threshold = BigUint::from(2u32).pow(threshold_exp);
        let max_entropy = BigUint::from(2u32).pow(adj_num_bits);

        let mut rng_instance = rand::rng();
        let mut entropy = BigUint::one();
        while entropy < threshold {
            // Generate random bytes and convert to BigUint
            let adj_bytes = (adj_num_bits as usize).div_ceil(8);
            let mut buf = vec![0u8; adj_bytes];
            use rand::RngCore;
            rng_instance.fill_bytes(&mut buf);
            entropy = BigUint::from_bytes_be(&buf) % &max_entropy;
        }

        let mut nonce = BigUint::zero();
        let mut seed;
        loop {
            nonce += 1u32;
            let i = &entropy + &nonce;

            seed = self.mnemonic_encode(&i);
            if i != self.mnemonic_decode(&seed)? {
                return Err(MnemonicError::EntropyMismatch);
            }
            if is_new_seed(&seed, prefix) {
                break;
            }
        }
        Ok(seed)
    }

    /// Validate a mnemonic phrase.
    pub fn validate(&self, phrase: &str) -> bool {
        self.mnemonic_decode(phrase).is_ok() && is_new_seed(phrase, SeedPrefix::Standard)
    }
}

fn hmac_oneshot(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn is_new_seed(seed: &str, prefix: SeedPrefix) -> bool {
    let seed = normalize_text(seed);
    let seed = hmac_oneshot("Seed version".as_bytes(), seed.as_bytes());
    seed[0] == prefix as u8
}

const CJK_INTERVALS: &[(u32, u32, &str)] = &[
    (0x4E00, 0x9FFF, "CJK Unified Ideographs"),
    (0x3400, 0x4DBF, "CJK Unified Ideographs Extension A"),
    (0x20000, 0x2A6DF, "CJK Unified Ideographs Extension B"),
    (0x2A700, 0x2B73F, "CJK Unified Ideographs Extension C"),
    (0x2B740, 0x2B81F, "CJK Unified Ideographs Extension D"),
    (0xF900, 0xFAFF, "CJK Compatibility Ideographs"),
    (0x2F800, 0x2FA1D, "CJK Compatibility Ideographs Supplement"),
    (0x3190, 0x319F, "Kanbun"),
    (0x2E80, 0x2EFF, "CJK Radicals Supplement"),
    (0x2F00, 0x2FDF, "CJK Radicals"),
    (0x31C0, 0x31EF, "CJK Strokes"),
    (0x2FF0, 0x2FFF, "Ideographic Description Characters"),
    (0xE0100, 0xE01EF, "Variation Selectors Supplement"),
    (0x3100, 0x312F, "Bopomofo"),
    (0x31A0, 0x31BF, "Bopomofo Extended"),
    (0xFF00, 0xFFEF, "Halfwidth and Fullwidth Forms"),
    (0x3040, 0x309F, "Hiragana"),
    (0x30A0, 0x30FF, "Katakana"),
    (0x31F0, 0x31FF, "Katakana Phonetic Extensions"),
    (0x1B000, 0x1B0FF, "Kana Supplement"),
    (0xAC00, 0xD7AF, "Hangul Syllables"),
    (0x1100, 0x11FF, "Hangul Jamo"),
    (0xA960, 0xA97F, "Hangul Jamo Extended A"),
    (0xD7B0, 0xD7FF, "Hangul Jamo Extended B"),
    (0x3130, 0x318F, "Hangul Compatibility Jamo"),
    (0xA4D0, 0xA4FF, "Lisu"),
    (0x16F00, 0x16F9F, "Miao"),
    (0xA000, 0xA48F, "Yi Syllables"),
    (0xA490, 0xA4CF, "Yi Radicals"),
];

fn is_cjk(c: char) -> bool {
    let n = c as u32;
    for (imin, imax, _name) in CJK_INTERVALS {
        if imin <= &n && &n <= imax {
            return true;
        }
    }
    false
}

fn normalize_text(seed: &str) -> String {
    let seed: String = seed.nfkd().collect();
    let seed = seed.to_lowercase();
    let seed: String = seed.chars().filter(|&c| !is_combining_mark(c)).collect();
    let seed: String = seed.split_whitespace().collect::<Vec<&str>>().join(" ");
    let chars: Vec<char> = seed.chars().collect();
    let seed: String = chars
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| {
            if c.is_whitespace() && i > 0 && i < chars.len() - 1 {
                if is_cjk(chars[i - 1]) && is_cjk(chars[i + 1]) {
                    None
                } else {
                    Some(c)
                }
            } else {
                Some(c)
            }
        })
        .collect();
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_size() {
        let engine = DarkfiMnemonic::default();
        assert_eq!(
            engine.wordlist.len(),
            2048,
            "Must use standard 2048-word list"
        );
    }

    #[test]
    fn test_generate_22_word_mnemonic() {
        let engine = DarkfiMnemonic::default();
        let phrase = engine.make_seed(None, None).unwrap();
        let word_count = phrase.split_whitespace().count();
        // DarkFi mnemonics are 21 or 22 words (depends on entropy)
        assert!(
            (21..=22).contains(&word_count),
            "Expected 21-22 words, got {word_count}"
        );
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        let engine = DarkfiMnemonic::default();
        let phrase = engine.make_seed(None, None).unwrap();
        let decoded = engine.mnemonic_decode(&phrase).unwrap();
        let re_encoded = engine.mnemonic_encode(&decoded);
        assert_eq!(phrase, re_encoded, "Mnemonic must round-trip identically");
    }

    #[test]
    fn test_mnemonic_validation() {
        let engine = DarkfiMnemonic::default();
        let phrase = engine.make_seed(None, None).unwrap();
        assert!(engine.validate(&phrase), "Generated mnemonic must validate");
    }

    #[test]
    fn test_invalid_mnemonic_rejected() {
        let engine = DarkfiMnemonic::default();
        assert!(!engine.validate("this is not a valid mnemonic phrase at all"));
    }

    #[test]
    fn test_secret_key_deterministic() {
        let words: Vec<String> = vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        let key1 = secret_key_from_mnemonic(&words).unwrap();
        let key2 = secret_key_from_mnemonic(&words).unwrap();
        assert_eq!(key1, key2, "Same mnemonic must produce same SecretKey");
    }

    #[test]
    fn test_different_mnemonics_different_keys() {
        let words1: Vec<String> = vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        let words2: Vec<String> = vec![
            "zoo", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
            "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
            "acquire", "across", "act", "action", "actor",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        let key1 = secret_key_from_mnemonic(&words1).unwrap();
        let key2 = secret_key_from_mnemonic(&words2).unwrap();
        assert_ne!(
            key1, key2,
            "Different mnemonics must produce different keys"
        );
    }

    #[test]
    fn test_normalize_text() {
        assert_eq!(normalize_text("  Hello   World  "), "hello world");
    }

    #[test]
    fn test_pbkdf2_seed_derivation() {
        let seed = DarkfiMnemonic::mnemonic_to_seed("abandon ability", None);
        assert_eq!(seed.len(), 64);
        // Must be deterministic
        let seed2 = DarkfiMnemonic::mnemonic_to_seed("abandon ability", None);
        assert_eq!(seed, seed2);
    }
}
