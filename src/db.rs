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

//! Local SQLite wallet database for Moonshine.
//!
//! Stores wallet metadata, derived keys, discovered notes (coins),
//! transaction history, and sync progress.
//!
//! Address `secret_key` BLOBs are wrapped at rest with [`crate::secret_wrap`]
//! (S14) — never stored as raw plaintext. The DB itself is SQLCipher-encrypted
//! with a passphrase from `MOONSHINE_WALLET_PASS` or `{path}.pass` (0600).

use rusqlite::{params, Connection, Result as SqlResult};
use std::path::Path;
use zeroize::Zeroize;

/// Local wallet database backed by SQLCipher.
pub struct WalletDb {
    conn: Connection,
    /// Key for wrapping address secrets at rest (S14).
    wrap_key: [u8; 32],
}

impl Drop for WalletDb {
    fn drop(&mut self) {
        self.wrap_key.zeroize();
    }
}

/// `(height, tx_hash, kind, bulla)` from `dao_calls`.
pub type DaoCallRow = (u32, Vec<u8>, u32, Vec<u8>);
/// `(height, tx_hash, kind, bulla, payload)` from `dao_calls`.
pub type DaoCallFullRow = (u32, Vec<u8>, u32, Vec<u8>, Vec<u8>);
/// `(token_id, mint_authority, token_blind, alias, is_frozen, freeze_height)`.
pub type TokenMintRow = (String, Vec<u8>, Vec<u8>, Option<String>, bool, Option<u32>);
/// `(token_id, mint_authority, token_blind, is_frozen)`.
pub type TokenMintLookup = (String, Vec<u8>, Vec<u8>, bool);
/// `(name, bulla, tx_hash)` from `dao_records`.
pub type DaoRecordRow = (String, Option<String>, Option<String>);

impl WalletDb {
    /// Open or create the wallet database at the given path.
    pub fn open(path: &str) -> SqlResult<Self> {
        let passphrase = crate::secret_wrap::load_or_create_passphrase(path)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                crate::secret_wrap::ensure_dir_0700(parent)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            }
        }
        let conn = Connection::open(path)?;
        crate::secret_wrap::set_file_mode_0600(Path::new(path))
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        // SQLCipher: unlock / encrypt the database with the wallet passphrase.
        conn.pragma_update(None, "key", passphrase.as_str())?;
        let mut db = Self {
            conn,
            wrap_key: [0u8; 32],
        };
        db.initialize()?;
        let _ = crate::secret_wrap::set_file_mode_0600(Path::new(&format!("{path}-wal")));
        let _ = crate::secret_wrap::set_file_mode_0600(Path::new(&format!("{path}-shm")));
        // The wrap key lives inside the encrypted DB. A legacy `{path}.wrapkey`
        // file is imported once, then removed so the key is not sitting beside
        // the ciphertext. Legacy unsalted / MSK1 meta keys are upgraded in place.
        if let Some(stored) = db.get_meta(crate::secret_wrap::META_WRAP_KEY)? {
            let salt = db.get_meta(crate::secret_wrap::META_PASS_SALT)?;
            let kdf_meta = db.get_meta(crate::secret_wrap::META_PASS_KDF)?;
            let (wrap_key, needs_rekey, kdf_used) = crate::secret_wrap::unwrap_meta_wrap_key(
                &stored,
                &passphrase,
                salt.as_deref(),
                kdf_meta.as_deref(),
            )
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            if needs_rekey {
                let new_salt = crate::secret_wrap::random_pass_salt();
                // Keep the KDF that opened this wallet. Existing auto-generated
                // hex keys stay on blake3; do not switch them to argon2id.
                crate::secret_wrap::store_wrap_key_in_meta(
                    |k, v| db.set_meta(k, v).map_err(|e| e.to_string()),
                    &wrap_key,
                    &passphrase,
                    &new_salt,
                    kdf_used,
                )
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                let stored2 = db
                    .get_meta(crate::secret_wrap::META_WRAP_KEY)?
                    .ok_or_else(|| {
                        rusqlite::Error::ToSqlConversionFailure(
                            "wrap key missing after MSK2 re-key".into(),
                        )
                    })?;
                let salt2 = db.get_meta(crate::secret_wrap::META_PASS_SALT)?;
                let kdf_meta2 = db.get_meta(crate::secret_wrap::META_PASS_KDF)?;
                let (mut check, still_legacy, _) = crate::secret_wrap::unwrap_meta_wrap_key(
                    &stored2,
                    &passphrase,
                    salt2.as_deref(),
                    kdf_meta2.as_deref(),
                )
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if check != wrap_key || still_legacy {
                    check.zeroize();
                    return Err(rusqlite::Error::ToSqlConversionFailure(
                        "wrap key MSK2 re-key round-trip mismatch".into(),
                    ));
                }
                check.zeroize();
            }
            db.wrap_key = wrap_key;
            db.migrate_secrets_to_v2()?;
            crate::secret_wrap::delete_legacy_wrap_key(path);
            return Ok(db);
        }
        let mut wrap_key = match crate::secret_wrap::read_legacy_wrap_key(path)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?
        {
            Some(key) => key,
            None => crate::secret_wrap::random_wrap_key(),
        };
        let pass_salt = crate::secret_wrap::random_pass_salt();
        // `load_or_create_passphrase` only returns a user-supplied passphrase
        // (`MOONSHINE_WALLET_PASS` or `{db}.pass`), including 64 hex characters.
        // New wallets record argon2id. Older 64-hex wallets stay on the blake3
        // heuristic until `pass_kdf` is written.
        let kdf = crate::secret_wrap::PassKdf::Argon2id;
        crate::secret_wrap::store_wrap_key_in_meta(
            |k, v| db.set_meta(k, v).map_err(|e| e.to_string()),
            &wrap_key,
            &passphrase,
            &pass_salt,
            kdf,
        )
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        // Confirm the meta copy unwraps before deleting the sidecar.
        let stored = db
            .get_meta(crate::secret_wrap::META_WRAP_KEY)?
            .ok_or_else(|| {
                rusqlite::Error::ToSqlConversionFailure(
                    "wrap key missing from wallet_meta after store".into(),
                )
            })?;
        let stored_salt = db.get_meta(crate::secret_wrap::META_PASS_SALT)?;
        let stored_kdf = db.get_meta(crate::secret_wrap::META_PASS_KDF)?;
        let (mut check, still_legacy, _) = crate::secret_wrap::unwrap_meta_wrap_key(
            &stored,
            &passphrase,
            stored_salt.as_deref(),
            stored_kdf.as_deref(),
        )
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        if check != wrap_key || still_legacy {
            wrap_key.zeroize();
            check.zeroize();
            return Err(rusqlite::Error::ToSqlConversionFailure(
                "wrap key round-trip mismatch".into(),
            ));
        }
        db.wrap_key = wrap_key;
        wrap_key.zeroize();
        check.zeroize();
        db.migrate_secrets_to_v2()?;
        crate::secret_wrap::delete_legacy_wrap_key(path);
        Ok(db)
    }

    /// Open an in-memory database for testing.
    #[cfg(test)]
    pub fn in_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "key", crate::secret_wrap::test_passphrase())?;
        let db = Self {
            conn,
            wrap_key: crate::secret_wrap::test_wrap_key(),
        };
        db.initialize()?;
        Ok(db)
    }

    /// Create all tables if they don't exist.
    fn initialize(&self) -> SqlResult<()> {
        // S14: overwrite deleted pages; use WAL for crash-safe writes.
        self.conn.execute_batch(
            "
            PRAGMA secure_delete = ON;
            PRAGMA journal_mode = WAL;
            ",
        )?;
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS wallet_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key TEXT NOT NULL UNIQUE,
                secret_key BLOB NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_hash TEXT NOT NULL,
                output_index INTEGER NOT NULL,
                value_raw INTEGER NOT NULL,
                token_id TEXT NOT NULL,
                serial_number BLOB NOT NULL,
                nullifier BLOB,
                block_height INTEGER NOT NULL,
                spent INTEGER NOT NULL DEFAULT 0,
                memo TEXT,
                coin_blind BLOB,
                value_blind BLOB,
                token_blind BLOB,
                spend_hook INTEGER,
                spend_hook_bytes BLOB,
                user_data BLOB,
                leaf_position INTEGER,
                commitment BLOB,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(tx_hash, output_index)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                hash TEXT PRIMARY KEY,
                block_height INTEGER NOT NULL,
                direction TEXT NOT NULL, -- 'incoming' or 'outgoing'
                value_raw INTEGER NOT NULL,
                token_id TEXT NOT NULL,
                counterparty TEXT,
                memo TEXT,
                kind TEXT NOT NULL DEFAULT 'transfer',
                timestamp TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                last_synced_height INTEGER NOT NULL DEFAULT 0,
                birthday_height INTEGER NOT NULL DEFAULT 0,
                last_sync_timestamp TEXT
            );

            INSERT OR IGNORE INTO sync_state (id, last_synced_height, birthday_height)
            VALUES (1, 0, 0);

            CREATE TABLE IF NOT EXISTS dao_calls (
                height INTEGER NOT NULL,
                tx_hash BLOB NOT NULL,
                kind INTEGER NOT NULL,
                bulla BLOB NOT NULL,
                payload BLOB NOT NULL,
                PRIMARY KEY (height, tx_hash, kind, bulla)
            );

            CREATE TABLE IF NOT EXISTS func_events (
                height INTEGER NOT NULL,
                tx_hash BLOB NOT NULL,
                func_code INTEGER NOT NULL,
                PRIMARY KEY (height, tx_hash, func_code)
            );

            CREATE TABLE IF NOT EXISTS token_mints (
                token_id TEXT PRIMARY KEY,
                mint_authority BLOB NOT NULL,
                token_blind BLOB NOT NULL,
                alias TEXT,
                is_frozen INTEGER NOT NULL DEFAULT 0,
                freeze_height INTEGER
            );

            CREATE TABLE IF NOT EXISTS dao_records (
                name TEXT PRIMARY KEY,
                params_toml TEXT NOT NULL,
                bulla TEXT,
                tx_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS deploy_auths (
                contract_id TEXT PRIMARY KEY,
                secret_key BLOB NOT NULL,
                is_locked INTEGER NOT NULL DEFAULT 0,
                lock_height INTEGER
            );

            CREATE TABLE IF NOT EXISTS dao_proposals (
                proposal_bulla TEXT PRIMARY KEY,
                dao_bulla TEXT NOT NULL,
                proposal_bytes BLOB NOT NULL,
                coin_attrs_bytes BLOB,
                mint_height INTEGER,
                tx_hash TEXT,
                exec_height INTEGER,
                exec_tx_hash TEXT
            );
        ",
        )?;
        self.migrate_notes_columns()?;
        Ok(())
    }

    /// One-time atomic upgrade of legacy `MSK1` or plaintext secret columns to `MSK2`
    /// (`XChaCha20Poly1305`). Safe to call repeatedly (idempotent when already `MSK2`).
    pub fn migrate_secrets_to_v2(&self) -> SqlResult<usize> {
        let mut upgraded = 0usize;
        let tx = self.conn.unchecked_transaction()?;

        // 1. addresses.secret_key
        {
            let mut stmt = tx.prepare("SELECT id, secret_key FROM addresses")?;
            let rows: Vec<(i64, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (id, stored) in rows {
                let (mut plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE addresses SET secret_key = ?1 WHERE id = ?2",
                        params![wrapped, id],
                    )?;
                    upgraded += 1;
                }
                plain.zeroize();
            }
        }

        // 2. notes.owner_secret
        {
            let mut stmt =
                tx.prepare("SELECT id, owner_secret FROM notes WHERE owner_secret IS NOT NULL")?;
            let rows: Vec<(i64, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (id, stored) in rows {
                let (mut plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE notes SET owner_secret = ?1 WHERE id = ?2",
                        params![wrapped, id],
                    )?;
                    upgraded += 1;
                }
                plain.zeroize();
            }
        }

        // 3. wallet_meta['derivation_seed']
        {
            let mut stmt =
                tx.prepare("SELECT value FROM wallet_meta WHERE key = 'derivation_seed'")?;
            let existing: Option<Vec<u8>> = stmt.query_map([], |r| r.get(0))?.next().transpose()?;
            drop(stmt);
            if let Some(stored) = existing {
                let (mut plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE wallet_meta SET value = ?1 WHERE key = 'derivation_seed'",
                        params![wrapped],
                    )?;
                    upgraded += 1;
                }
                plain.zeroize();
            }
        }

        // 4. token_mints (mint_authority + token_blind)
        {
            let mut stmt =
                tx.prepare("SELECT token_id, mint_authority, token_blind FROM token_mints")?;
            let rows: Vec<(String, Vec<u8>, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (tid, auth_stored, blind_stored) in rows {
                let (mut auth_plain, auth_rw) =
                    crate::secret_wrap::unwrap_secret_for_migration(&auth_stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                let (mut blind_plain, blind_rw) =
                    crate::secret_wrap::unwrap_secret_for_migration(&blind_stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if auth_rw || blind_rw {
                    let auth_w = crate::secret_wrap::wrap_secret(&auth_plain, &self.wrap_key);
                    let blind_w = crate::secret_wrap::wrap_secret(&blind_plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE token_mints SET mint_authority = ?1, token_blind = ?2 WHERE token_id = ?3",
                        params![auth_w, blind_w, tid],
                    )?;
                    upgraded += 1;
                }
                auth_plain.zeroize();
                blind_plain.zeroize();
            }
        }

        // 5. deploy_auths.secret_key
        {
            let mut stmt = tx.prepare("SELECT contract_id, secret_key FROM deploy_auths")?;
            let rows: Vec<(String, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (cid, stored) in rows {
                let (mut plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE deploy_auths SET secret_key = ?1 WHERE contract_id = ?2",
                        params![wrapped, cid],
                    )?;
                    upgraded += 1;
                }
                plain.zeroize();
            }
        }

        // 6. dao_records.params_toml
        {
            let mut stmt = tx.prepare("SELECT name, params_toml FROM dao_records")?;
            let rows: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (name, stored) in rows {
                let (plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_text_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret_text(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE dao_records SET params_toml = ?1 WHERE name = ?2",
                        params![wrapped, name],
                    )?;
                    upgraded += 1;
                }
            }
        }

        tx.commit()?;
        Ok(upgraded)
    }

    /// Recompute each unspent note's commitment from note attributes + owner
    /// key (`CoinAttributes::to_coin`). Compact-block `output.coin` must match
    /// this; overwriting commitments with unrelated coins in the same block
    /// makes spend proofs use a Merkle root that is not on chain (Money 0x5).
    ///
    /// Returns `(checked, updated)`.
    #[allow(dead_code)]
    pub fn recompute_note_commitments(&self) -> SqlResult<(u32, u32)> {
        use darkfi_money_contract::model::{CoinAttributes, TokenId};
        use darkfi_sdk::crypto::{FuncId, PublicKey, SecretKey};
        use darkfi_sdk::pasta::pallas;
        use darkfi_serial::Decodable;

        let mut stmt = self.conn.prepare(
            "SELECT id, value_raw, token_id, coin_blind, spend_hook, spend_hook_bytes, user_data, \
             commitment, owner_secret FROM notes \
             WHERE spent = 0 AND owner_secret IS NOT NULL AND coin_blind IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })?;

        let mut checked = 0u32;
        let mut updated = 0u32;
        let mut updates: Vec<(i64, Vec<u8>)> = Vec::new();
        for row in rows {
            let (
                id,
                value_raw,
                tok_hex,
                coin_blind,
                hook_i,
                hook_bytes,
                user_data,
                old_commit,
                owner_stored,
            ) = row?;
            let hook = hook_i.unwrap_or(0) as u8;
            let Ok(owner) = crate::secret_wrap::unwrap_secret(&owner_stored, &self.wrap_key) else {
                continue;
            };
            if owner.len() < 32 || coin_blind.len() != 32 {
                continue;
            }
            let tok_bytes = match hex::decode(&tok_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => continue,
            };
            let mut tok_arr = [0u8; 32];
            tok_arr.copy_from_slice(&tok_bytes);
            let Ok(token_id) = TokenId::from_bytes(tok_arr) else {
                continue;
            };
            let mut sk_arr = [0u8; 32];
            sk_arr.copy_from_slice(&owner[..32]);
            let Ok(sk) = SecretKey::from_bytes(sk_arr) else {
                continue;
            };
            let mut cb_arr = [0u8; 32];
            cb_arr.copy_from_slice(&coin_blind);
            let Ok(coin_blind_f) = pallas::Base::decode(&mut std::io::Cursor::new(cb_arr)) else {
                continue;
            };
            let ud = user_data.unwrap_or_else(|| vec![0u8; 32]);
            if ud.len() != 32 {
                continue;
            }
            let mut ud_arr = [0u8; 32];
            ud_arr.copy_from_slice(&ud);
            let Ok(user_data_f) = pallas::Base::decode(&mut std::io::Cursor::new(ud_arr)) else {
                continue;
            };
            let mut hook_arr = [0u8; 32];
            match hook_bytes {
                Some(b) if b.len() == 32 => hook_arr.copy_from_slice(&b),
                _ => hook_arr[0] = hook,
            }
            let Ok(spend_hook) = FuncId::from_bytes(hook_arr) else {
                continue;
            };
            let derived = CoinAttributes {
                public_key: PublicKey::from_secret(sk),
                value: value_raw as u64,
                token_id,
                spend_hook,
                user_data: user_data_f,
                blind: darkfi_sdk::crypto::Blind(coin_blind_f),
            }
            .to_coin();
            let derived_bytes = derived.to_bytes().to_vec();
            checked += 1;
            if old_commit.as_deref() != Some(derived_bytes.as_slice()) {
                updates.push((id, derived_bytes));
                updated += 1;
            }
        }
        drop(stmt);
        for (id, bytes) in updates {
            self.conn.execute(
                "UPDATE notes SET commitment = ?1, leaf_position = NULL WHERE id = ?2",
                params![bytes, id],
            )?;
        }
        Ok((checked, updated))
    }

    pub fn update_leaf_position(&self, commitment: &[u8], leaf_position: u32) -> SqlResult<usize> {
        self.conn.execute(
            "UPDATE notes SET leaf_position = ?1 WHERE commitment = ?2 AND spent = 0",
            params![leaf_position, commitment],
        )
    }

    /// Return all 32-byte commitment blobs for unspent owned notes.
    /// Unlike `list_unspent_full`, this does NOT require `leaf_position` to be set,
    /// which is important during sync when notes are discovered before tree positions
    /// are assigned.
    pub fn list_owned_commitments(&self) -> SqlResult<Vec<Vec<u8>>> {
        let mut stmt = self.conn.prepare(
            "SELECT commitment FROM notes WHERE spent = 0 \
             AND commitment IS NOT NULL AND length(commitment) = 32",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect()
    }

    /// `(tx_hash, output_index, block_height)` for unspent notes.
    pub fn list_unspent_note_locs(&self) -> SqlResult<Vec<(String, u32, u32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT tx_hash, output_index, block_height FROM notes WHERE spent = 0 ORDER BY block_height",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, u32>(2)?,
            ))
        })?;
        rows.collect()
    }

    /// Overwrite a note's on-chain coin commitment (clears leaf_position).
    #[allow(dead_code)]
    pub fn set_note_commitment(
        &self,
        tx_hash: &str,
        output_index: u32,
        commitment: &[u8],
    ) -> SqlResult<usize> {
        self.conn.execute(
            "UPDATE notes SET commitment = ?1, leaf_position = NULL \
             WHERE tx_hash = ?2 AND output_index = ?3 AND spent = 0",
            params![commitment, tx_hash, output_index],
        )
    }

    pub fn set_spend_hook_bytes(
        &self,
        tx_hash: &str,
        output_index: u32,
        spend_hook_bytes: &[u8],
    ) -> SqlResult<usize> {
        self.conn.execute(
            "UPDATE notes SET spend_hook_bytes = ?1 \
             WHERE tx_hash = ?2 AND output_index = ?3 AND spent = 0",
            params![spend_hook_bytes, tx_hash, output_index],
        )
    }

    /// Refresh spend fields from a re-decrypted MoneyNote (plus on-chain coin).
    #[allow(clippy::too_many_arguments)]
    pub fn update_note_spend_fields(
        &self,
        tx_hash: &str,
        output_index: u32,
        value_raw: i64,
        token_id: &str,
        coin_blind: &[u8],
        value_blind: &[u8],
        token_blind: &[u8],
        spend_hook: u8,
        spend_hook_bytes: &[u8],
        user_data: &[u8],
        commitment: &[u8],
        owner_secret: &[u8],
    ) -> SqlResult<usize> {
        let wrapped_owner = crate::secret_wrap::wrap_secret(owner_secret, &self.wrap_key);
        self.conn.execute(
            "UPDATE notes SET value_raw = ?1, token_id = ?2, coin_blind = ?3, \
             value_blind = ?4, token_blind = ?5, spend_hook = ?6, spend_hook_bytes = ?7, \
             user_data = ?8, commitment = ?9, owner_secret = ?10, leaf_position = NULL \
             WHERE tx_hash = ?11 AND output_index = ?12 AND spent = 0",
            params![
                value_raw,
                token_id,
                coin_blind,
                value_blind,
                token_blind,
                spend_hook,
                spend_hook_bytes,
                user_data,
                commitment,
                wrapped_owner,
                tx_hash,
                output_index,
            ],
        )
    }

    /// Ensure migrated columns exist on older wallet DBs.
    pub fn insert_dao_call(
        &self,
        height: u32,
        tx_hash: &[u8],
        kind: u32,
        bulla: &[u8],
        payload: &[u8],
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO dao_calls (height, tx_hash, kind, bulla, payload) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![height, tx_hash, kind, bulla, payload],
        )?;
        Ok(())
    }

    pub fn insert_func_event(&self, height: u32, tx_hash: &[u8], func_code: u32) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO func_events (height, tx_hash, func_code) VALUES (?1, ?2, ?3)",
            rusqlite::params![height, tx_hash, func_code],
        )?;
        Ok(())
    }

    /// Synced compact DAO calls (most recent first).
    pub fn list_dao_calls(&self, limit: u32) -> SqlResult<Vec<DaoCallRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, tx_hash, kind, bulla FROM dao_calls \
             ORDER BY height DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        rows.collect()
    }

    /// Synced Money/DAO/deploy func markers (most recent first).
    pub fn list_func_events(&self, limit: u32) -> SqlResult<Vec<(u32, Vec<u8>, u32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, tx_hash, func_code FROM func_events \
             ORDER BY height DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
            ))
        })?;
        rows.collect()
    }

    pub fn insert_token_mint(
        &self,
        token_id: &str,
        mint_authority: &[u8],
        token_blind: &[u8],
        alias: Option<&str>,
    ) -> SqlResult<()> {
        let wrapped_auth = crate::secret_wrap::wrap_secret(mint_authority, &self.wrap_key);
        let wrapped_blind = crate::secret_wrap::wrap_secret(token_blind, &self.wrap_key);
        self.conn.execute(
            "INSERT INTO token_mints (token_id, mint_authority, token_blind, alias, is_frozen) \
             VALUES (?1, ?2, ?3, ?4, 0) \
             ON CONFLICT(token_id) DO UPDATE SET \
               mint_authority = excluded.mint_authority, \
               token_blind = excluded.token_blind, \
               alias = COALESCE(excluded.alias, token_mints.alias)",
            rusqlite::params![token_id, wrapped_auth, wrapped_blind, alias],
        )?;
        Ok(())
    }

    pub fn list_token_mints(&self) -> SqlResult<Vec<TokenMintRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT token_id, mint_authority, token_blind, alias, is_frozen, freeze_height \
             FROM token_mints ORDER BY alias IS NULL, alias, token_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)? != 0,
                row.get::<_, Option<u32>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (tid, auth_stored, blind_stored, alias, frozen, fh) = r?;
            let auth = crate::secret_wrap::unwrap_secret(&auth_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            let blind = crate::secret_wrap::unwrap_secret(&blind_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push((tid, auth, blind, alias, frozen, fh));
        }
        Ok(out)
    }

    pub fn get_token_mint(&self, token_or_alias: &str) -> SqlResult<Option<TokenMintLookup>> {
        let mut stmt = self.conn.prepare(
            "SELECT token_id, mint_authority, token_blind, is_frozen FROM token_mints \
             WHERE token_id = ?1 OR alias = ?1 \
             ORDER BY is_frozen ASC, token_id ASC \
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map([token_or_alias], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)? != 0,
            ))
        })?;
        match rows.next() {
            Some(Ok((tid, auth_stored, blind_stored, frozen))) => {
                let auth = crate::secret_wrap::unwrap_secret(&auth_stored, &self.wrap_key)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                let blind = crate::secret_wrap::unwrap_secret(&blind_stored, &self.wrap_key)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                Ok(Some((tid, auth, blind, frozen)))
            }
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub fn set_token_frozen(&self, token_id: &str, height: Option<u32>) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE token_mints SET is_frozen = 1, freeze_height = ?2 WHERE token_id = ?1",
            rusqlite::params![token_id, height],
        )?;
        Ok(())
    }

    pub fn upsert_dao_record(
        &self,
        name: &str,
        params_toml: &str,
        bulla: Option<&str>,
        tx_hash: Option<&str>,
    ) -> SqlResult<()> {
        let wrapped_toml = crate::secret_wrap::wrap_secret_text(params_toml, &self.wrap_key);
        self.conn.execute(
            "INSERT INTO dao_records (name, params_toml, bulla, tx_hash) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET
               params_toml = excluded.params_toml,
               bulla = COALESCE(excluded.bulla, dao_records.bulla),
               tx_hash = COALESCE(excluded.tx_hash, dao_records.tx_hash)",
            rusqlite::params![name, wrapped_toml, bulla, tx_hash],
        )?;
        Ok(())
    }

    pub fn list_dao_records(&self) -> SqlResult<Vec<DaoRecordRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, bulla, tx_hash FROM dao_records ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        rows.collect()
    }

    pub fn get_dao_toml(&self, name: &str) -> SqlResult<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT params_toml FROM dao_records WHERE name = ?1")?;
        let mut rows = stmt.query_map([name], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(Ok(stored)) => {
                let plain = crate::secret_wrap::unwrap_secret_text(&stored, &self.wrap_key)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                Ok(Some(plain))
            }
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub fn insert_deploy_auth(&self, contract_id: &str, secret_key: &[u8]) -> SqlResult<()> {
        let wrapped = crate::secret_wrap::wrap_secret(secret_key, &self.wrap_key);
        self.conn.execute(
            "INSERT INTO deploy_auths (contract_id, secret_key, is_locked) \
             VALUES (?1, ?2, 0) \
             ON CONFLICT(contract_id) DO UPDATE SET \
               secret_key = excluded.secret_key",
            rusqlite::params![contract_id, wrapped],
        )?;
        Ok(())
    }

    pub fn list_deploy_auths(&self) -> SqlResult<Vec<(String, bool, Option<u32>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT contract_id, is_locked, lock_height FROM deploy_auths ORDER BY contract_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? != 0,
                row.get::<_, Option<u32>>(2)?,
            ))
        })?;
        rows.collect()
    }

    pub fn get_deploy_auth(&self, contract_id: &str) -> SqlResult<Option<(Vec<u8>, bool)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret_key, is_locked FROM deploy_auths WHERE contract_id = ?1")?;
        let mut rows = stmt.query_map([contract_id], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)? != 0))
        })?;
        match rows.next() {
            Some(Ok((stored, locked))) => {
                let plain = crate::secret_wrap::unwrap_secret(&stored, &self.wrap_key)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                Ok(Some((plain, locked)))
            }
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub fn set_deploy_locked(&self, contract_id: &str, height: Option<u32>) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE deploy_auths SET is_locked = 1, lock_height = ?2 WHERE contract_id = ?1",
            rusqlite::params![contract_id, height],
        )?;
        Ok(())
    }

    fn migrate_notes_columns(&self) -> SqlResult<()> {
        let _ = self
            .conn
            .execute("ALTER TABLE notes ADD COLUMN owner_secret BLOB", []);
        let _ = self
            .conn
            .execute("ALTER TABLE notes ADD COLUMN spend_hook_bytes BLOB", []);
        // Height at which the nullifier was observed. Absent on rows spent
        // before this column existed; those stay spent across a reorg.
        let _ = self
            .conn
            .execute("ALTER TABLE notes ADD COLUMN spent_height INTEGER", []);
        // Height of the wallet tip when a broadcast reserved the note. Cleared
        // once the nullifier is seen on chain. Sync drops the reservation if
        // the chain moves on without that nullifier (mempool GC).
        let _ = self
            .conn
            .execute("ALTER TABLE notes ADD COLUMN reserved_height INTEGER", []);
        let _ = self.conn.execute(
            "ALTER TABLE transactions ADD COLUMN kind TEXT NOT NULL DEFAULT 'transfer'",
            [],
        );
        Ok(())
    }

    /// Rows changed by the last statement. `INSERT OR IGNORE` that skipped is 0.
    pub fn changed(&self) -> bool {
        self.conn.changes() > 0
    }

    /// Hex encoding of the native DRK token id (what sync stores).
    pub fn dark_token_id_hex() -> String {
        hex::encode(darkfi_money_contract::model::DARK_TOKEN_ID.to_bytes())
    }

    /// True if `token` is DRK display name or the on-wire hex token id.
    pub fn is_drk_token(token: &str) -> bool {
        token.eq_ignore_ascii_case("DRK") || token.eq_ignore_ascii_case(&Self::dark_token_id_hex())
    }

    /// Unspent notes with full fields for spend construction.
    /// Returns `(tx_hash, output_index, value, token_id, coin_blind, value_blind,
    /// token_blind, spend_hook_bytes, user_data, leaf_position, commitment, owner_secret)`.
    #[allow(clippy::type_complexity)]
    pub fn list_unspent_full(
        &self,
    ) -> SqlResult<
        Vec<(
            String,
            u32,
            i64,
            String,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            u32,
            Vec<u8>,
            Vec<u8>,
        )>,
    > {
        let is_unhooked = Self::sql_note_unhooked("");
        let query = format!(
            "SELECT tx_hash, output_index, value_raw, token_id, coin_blind, value_blind, token_blind, \
             spend_hook, spend_hook_bytes, user_data, leaf_position, commitment, owner_secret \
             FROM notes WHERE spent = 0 AND leaf_position IS NOT NULL \
             AND commitment IS NOT NULL AND length(commitment) = 32 \
             AND owner_secret IS NOT NULL AND {is_unhooked} \
             ORDER BY block_height"
        );
        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            let hook_i: u8 = row.get::<_, Option<u8>>(7)?.unwrap_or(0);
            let hook_bytes: Option<Vec<u8>> = row.get(8)?;
            let spend_hook = match hook_bytes {
                Some(b) if b.len() == 32 => b,
                _ => {
                    let mut b = vec![0u8; 32];
                    b[0] = hook_i;
                    b
                }
            };
            let owner_stored: Vec<u8> = row.get(12)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                spend_hook,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, u32>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                owner_stored,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (tx, idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner_stored) = row?;
            let owner = crate::secret_wrap::unwrap_secret(&owner_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push((
                tx, idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner,
            ));
        }
        Ok(out)
    }

    // =========================================================================
    // Wallet Metadata
    // =========================================================================

    /// Set when the Money Merkle tree includes height-0 coins after the dummy
    /// ZERO leaf. Birthday rescan used to append only post-birthday coins onto
    /// a fresh dummy tree, so spend proofs published a root the contract never
    /// stored (Money `Custom(5)` / `TransferMerkleRootNotFound`).
    const META_MERKLE_FROM_GENESIS: &'static str = "merkle_from_genesis";

    pub fn merkle_from_genesis(&self) -> bool {
        matches!(self.get_meta(Self::META_MERKLE_FROM_GENESIS), Ok(Some(v)) if v == b"1")
    }

    pub fn set_merkle_from_genesis(&self, complete: bool) -> SqlResult<()> {
        if complete {
            self.set_meta(Self::META_MERKLE_FROM_GENESIS, b"1")
        } else {
            self.conn.execute(
                "DELETE FROM wallet_meta WHERE key = ?1",
                params![Self::META_MERKLE_FROM_GENESIS],
            )?;
            Ok(())
        }
    }

    /// Store a sensitive metadata value wrapped at rest (`MSK2`).
    pub fn set_wrapped_meta(&self, key: &str, value: &[u8]) -> SqlResult<()> {
        let wrapped = crate::secret_wrap::wrap_secret(value, &self.wrap_key);
        self.set_meta(key, &wrapped)
    }

    /// Retrieve and unwrap a sensitive metadata value (`MSK2`, fail-closed).
    pub fn get_wrapped_meta(&self, key: &str) -> SqlResult<Option<Vec<u8>>> {
        let Some(stored) = self.get_meta(key)? else {
            return Ok(None);
        };
        let plain = crate::secret_wrap::unwrap_secret(&stored, &self.wrap_key)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        Ok(Some(plain))
    }

    /// Store a key-value pair in wallet metadata.
    pub fn set_meta(&self, key: &str, value: &[u8]) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Retrieve a metadata value by key.
    pub fn get_meta(&self, key: &str) -> SqlResult<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM wallet_meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            let val: Vec<u8> = row.get(0)?;
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    // =========================================================================
    // Addresses
    // =========================================================================

    /// Insert a new address. The secret is wrapped at rest (S14).
    pub fn insert_address(&self, public_key: &str, secret_key: &[u8]) -> SqlResult<i64> {
        let wrapped = crate::secret_wrap::wrap_secret(secret_key, &self.wrap_key);
        self.conn.execute(
            "INSERT INTO addresses (public_key, secret_key) VALUES (?1, ?2)",
            params![public_key, wrapped],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Set the default address.
    pub fn set_default_address(&self, public_key: &str) -> SqlResult<()> {
        self.conn
            .execute("UPDATE addresses SET is_default = 0", [])?;
        self.conn.execute(
            "UPDATE addresses SET is_default = 1 WHERE public_key = ?1",
            params![public_key],
        )?;
        Ok(())
    }

    /// Get the default address.
    pub fn get_default_address(&self) -> SqlResult<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key FROM addresses WHERE is_default = 1 LIMIT 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let pk: String = row.get(0)?;
            Ok(Some(pk))
        } else {
            Ok(None)
        }
    }

    /// List all addresses.
    pub fn list_addresses(&self) -> SqlResult<Vec<(String, bool)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key, is_default FROM addresses ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
        })?;
        rows.collect()
    }

    /// Retrieve all address secret keys for trial decryption (default address first).
    pub fn get_all_secrets(&self) -> SqlResult<Vec<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret_key FROM addresses ORDER BY is_default DESC, id ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let stored = row?;
            let plain = crate::secret_wrap::unwrap_secret(&stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push(plain);
        }
        Ok(out)
    }

    /// All wallet address secrets (default first) plus deduplicated DAO treasury `notes_secret` keys
    /// for trial decryption across every sync / rebuild path.
    pub fn get_all_trial_decrypt_secrets(&self) -> SqlResult<Vec<Vec<u8>>> {
        let mut secrets = self.get_all_secrets()?;
        let dao_secrets = self.get_all_dao_notes_secrets().unwrap_or_default();
        for ds in dao_secrets {
            if !secrets.iter().any(|sk| sk == &ds) {
                secrets.push(ds);
            }
        }
        Ok(secrets)
    }

    /// Retrieve addresses with secrets for multi-pubkey OMR (S17).
    /// Returns `(public_key_str, secret_key_bytes, is_default)` ordered by id.
    pub fn get_all_address_keys(&self) -> SqlResult<Vec<(String, Vec<u8>, bool)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key, secret_key, is_default FROM addresses ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (pk, stored, is_default) = row?;
            let plain = crate::secret_wrap::unwrap_secret(&stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push((pk, plain, is_default));
        }
        Ok(out)
    }

    // =========================================================================
    // Notes (Coins)
    // =========================================================================

    #[allow(clippy::too_many_arguments)]
    pub fn insert_note(
        &self,
        tx_hash: &str,
        output_index: u32,
        value_raw: i64,
        token_id: &str,
        serial_number: &[u8],
        block_height: u32,
        memo: Option<&str>,
        coin_blind: Option<&[u8]>,
        value_blind: Option<&[u8]>,
        token_blind: Option<&[u8]>,
        spend_hook: Option<u8>,
        user_data: Option<&[u8]>,
        leaf_position: Option<u32>,
        commitment: Option<&[u8]>,
        nullifier: Option<&[u8]>,
        owner_secret: Option<&[u8]>,
    ) -> SqlResult<i64> {
        let wrapped_owner =
            owner_secret.map(|s| crate::secret_wrap::wrap_secret(s, &self.wrap_key));
        self.conn.execute(
            "INSERT OR IGNORE INTO notes (tx_hash, output_index, value_raw, token_id, serial_number, nullifier, block_height, memo, coin_blind, value_blind, token_blind, spend_hook, user_data, leaf_position, commitment, owner_secret)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                tx_hash,
                output_index,
                value_raw,
                token_id,
                serial_number,
                nullifier,
                block_height,
                memo,
                coin_blind,
                value_blind,
                token_blind,
                spend_hook,
                user_data,
                leaf_position,
                commitment,
                wrapped_owner,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Mark a note as spent when its **nullifier** appears on-chain.
    ///
    /// Release builds call [`Self::mark_note_spent_at`]. This wrapper stays for tests.
    #[allow(dead_code)]
    pub fn mark_note_spent(&self, nullifier: &[u8]) -> SqlResult<usize> {
        self.mark_note_spent_at(nullifier, None)
    }

    /// Mark a note spent, recording the block height of the nullifier.
    ///
    /// A later sync that learns the height fills `spent_height` on a row that
    /// was reserved at broadcast time with a null height. Reorg recovery
    /// unspends only rows whose `spent_height` is above the fork.
    pub fn mark_note_spent_at(
        &self,
        nullifier: &[u8],
        spent_height: Option<u32>,
    ) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1, \
             spent_height = CASE WHEN ?2 IS NULL THEN spent_height ELSE COALESCE(spent_height, ?2) END, \
             reserved_height = CASE WHEN ?2 IS NULL THEN reserved_height ELSE NULL END \
             WHERE nullifier = ?1 \
             AND (spent = 0 OR (?2 IS NOT NULL AND spent_height IS NULL))",
            params![nullifier, spent_height],
        )?;
        Ok(rows)
    }

    /// Blocks after a broadcast reservation before sync may spend the note again.
    /// Matches the mempool window in which an unconfirmed tx can still land.
    pub const RESERVATION_GRACE_BLOCKS: u32 = 8;

    /// Reserve a note at `height` so the next send cannot reuse it before the
    /// nullifier appears. `spent_height` stays null until the chain confirms it.
    pub fn reserve_note(&self, nullifier: &[u8], height: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1, reserved_height = COALESCE(reserved_height, ?2) \
             WHERE nullifier = ?1 AND spent = 0",
            params![nullifier, height],
        )?;
        Ok(rows)
    }

    /// Same reservation, keyed by the on-chain coin commitment.
    pub fn reserve_note_by_commitment(&self, commitment: &[u8], height: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1, reserved_height = COALESCE(reserved_height, ?2) \
             WHERE commitment = ?1 AND spent = 0",
            params![commitment, height],
        )?;
        Ok(rows)
    }

    /// Unspend broadcast reservations the chain has moved past without a nullifier.
    /// Confirmed spends (`spent_height` set) are left alone.
    pub fn release_stale_reservations(&self, tip: u32, grace: u32) -> SqlResult<usize> {
        if tip <= grace {
            return Ok(0);
        }
        let oldest_kept = tip - grace;
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 0, reserved_height = NULL \
             WHERE spent = 1 AND spent_height IS NULL AND reserved_height IS NOT NULL \
             AND reserved_height < ?1",
            params![oldest_kept],
        )?;
        Ok(rows)
    }

    /// Mark a note spent by on-chain coin commitment (32-byte leaf).
    /// Used right after a successful broadcast so the next send cannot
    /// republish the same nullifier before `GetNullifiers` sees it.
    ///
    /// Callers reserve by commitment via [`Self::reserve_note_by_commitment`].
    /// This wrapper stays for tests and for a height-less spend.
    #[allow(dead_code)]
    pub fn mark_note_spent_by_commitment(&self, commitment: &[u8]) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1 WHERE commitment = ?1 AND spent = 0",
            params![commitment],
        )?;
        Ok(rows)
    }

    /// Mark a note spent by wallet locator (`tx_hash` prefix + output index).
    #[allow(dead_code)]
    pub fn mark_note_spent_by_loc(&self, tx_hash: &str, output_index: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1 WHERE spent = 0 AND output_index = ?1 \
             AND (tx_hash = ?2 OR tx_hash LIKE ?3)",
            params![output_index, tx_hash, format!("{tx_hash}%")],
        )?;
        Ok(rows)
    }

    /// Rewrite unspent `nullifier` columns as `poseidon(owner_secret, coin)`.
    ///
    /// Older rows were inserted with a missing or stale nullifier, so
    /// `GetNullifiers` never marked them spent and send republished an
    /// already-revealed nullifier (`-32110` / DuplicateNullifier).
    pub fn recompute_owned_nullifiers(&self) -> SqlResult<u32> {
        use darkfi_money_contract::model::Coin;
        use darkfi_sdk::crypto::pasta_prelude::PrimeField;
        use darkfi_sdk::crypto::{poseidon_hash, SecretKey};

        let mut stmt = self.conn.prepare(
            "SELECT id, commitment, owner_secret FROM notes \
             WHERE spent = 0 AND commitment IS NOT NULL AND length(commitment) = 32 \
             AND owner_secret IS NOT NULL",
        )?;
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<SqlResult<_>>()?;
        drop(stmt);

        let mut n = 0u32;
        for (id, commitment, owner_stored) in rows {
            let owner = crate::secret_wrap::unwrap_secret(&owner_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            if owner.len() < 32 || commitment.len() != 32 {
                continue;
            }
            let mut sk_arr = [0u8; 32];
            sk_arr.copy_from_slice(&owner[..32]);
            let Ok(sk) = SecretKey::from_bytes(sk_arr) else {
                continue;
            };
            let mut coin_arr = [0u8; 32];
            coin_arr.copy_from_slice(&commitment);
            let Ok(coin) = Coin::from_bytes(coin_arr) else {
                continue;
            };
            let nf = poseidon_hash([sk.inner(), coin.inner()]).to_repr();
            self.conn.execute(
                "UPDATE notes SET nullifier = ?1 WHERE id = ?2",
                params![nf.as_slice(), id],
            )?;
            n += 1;
        }
        Ok(n)
    }

    /// SQL predicate: note has no spend hook.
    ///
    /// Compact-block sync stores `FuncId::none()` as a 32-byte zero blob. Older
    /// filters only accepted NULL/empty `spend_hook_bytes`, which hid spendable
    /// DRK (balance 0 while `coins list` still showed the note).
    fn sql_note_unhooked(alias: &str) -> String {
        let p = if alias.is_empty() {
            String::new()
        } else {
            format!("{alias}.")
        };
        format!(
            "({p}spend_hook IS NULL OR {p}spend_hook = 0) AND \
             ({p}spend_hook_bytes IS NULL OR length({p}spend_hook_bytes) = 0 OR \
              {p}spend_hook_bytes = zeroblob(length({p}spend_hook_bytes)))"
        )
    }

    /// Hex form of a token id. Accepts `TokenId` base58 or the 32-byte hex
    /// stored on synced notes. Aliases are resolved by the caller first.
    pub fn token_id_hex(token_id: &str) -> Option<String> {
        use std::str::FromStr;

        use darkfi_money_contract::model::TokenId;

        if let Ok(id) = TokenId::from_str(token_id) {
            return Some(hex::encode(id.to_bytes()));
        }
        let bytes = hex::decode(token_id).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        let id = TokenId::from_bytes(arr).ok()?;
        Some(hex::encode(id.to_bytes()))
    }

    /// Confirmed balance for a token. `"DRK"` matches the native DarkFi token
    /// hex id (and older rows stored as the literal `DRK`). Excludes contract-hooked coins.
    ///
    /// Custom tokens match both the mint-authority base58 id and the hex id
    /// written by sync.
    pub fn confirmed_balance(&self, token_id: &str) -> SqlResult<i64> {
        let is_unhooked = Self::sql_note_unhooked("");
        if Self::is_drk_token(token_id) {
            let hex = Self::dark_token_id_hex();
            let mut stmt = self.conn.prepare(&format!(
                "SELECT COALESCE(SUM(value_raw), 0) FROM notes \
                 WHERE spent = 0 AND (token_id = ?1 OR lower(token_id) = 'drk') AND {is_unhooked}"
            ))?;
            let balance: i64 = stmt.query_row(params![hex], |row| row.get(0))?;
            Ok(balance)
        } else {
            let resolved = self.resolve_token_id(token_id)?;
            let hex_key = Self::token_id_hex(&resolved).unwrap_or_else(|| resolved.clone());
            let mut stmt = self.conn.prepare(&format!(
                "SELECT COALESCE(SUM(value_raw), 0) FROM notes \
                 WHERE (token_id = ?1 OR token_id = ?2 OR token_id = ?3) \
                 AND spent = 0 AND {is_unhooked}"
            ))?;
            let balance: i64 =
                stmt.query_row(params![token_id, resolved, hex_key], |row| row.get(0))?;
            Ok(balance)
        }
    }

    /// List confirmed token balances across all unspent, unhooked notes in the wallet.
    /// Returns `(token_id, alias, balance)` with native DRK first if present.
    pub fn list_token_balances(&self) -> SqlResult<Vec<(String, Option<String>, i64)>> {
        let is_unhooked = Self::sql_note_unhooked("n");
        let query = format!(
            "SELECT n.token_id, SUM(n.value_raw) as total \
             FROM notes n \
             WHERE n.spent = 0 AND {is_unhooked} \
             GROUP BY n.token_id \
             HAVING total > 0"
        );
        // Map both Base58 token_mints.token_id and 64-char hex notes.token_id to alias.
        let mut alias_by_id: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (mint_tid, _, _, alias, _, _) in self.list_token_mints()? {
            if let Some(a) = alias {
                alias_by_id
                    .entry(mint_tid.clone())
                    .or_insert_with(|| a.clone());
                if let Some(hex_id) = Self::token_id_hex(&mint_tid) {
                    alias_by_id.entry(hex_id).or_insert(a);
                }
            }
        }
        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            let token_id: String = row.get(0)?;
            let total: i64 = row.get(1)?;
            Ok((token_id, total))
        })?;
        let mut list = Vec::new();
        for r in rows {
            let (token_id, total) = r?;
            let alias = alias_by_id
                .get(&token_id)
                .or_else(|| Self::token_id_hex(&token_id).and_then(|h| alias_by_id.get(&h)))
                .cloned();
            list.push((token_id, alias, total));
        }
        list.sort_by(|a, b| {
            let a_is_drk = Self::is_drk_token(&a.0);
            let b_is_drk = Self::is_drk_token(&b.0);
            match (a_is_drk, b_is_drk) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.0.cmp(&b.0),
            }
        });
        Ok(list)
    }

    /// Resolve a token display name or alias (e.g. "ANON", "DRK") to its 32-byte hex ID.
    ///
    /// When several mint authorities share an alias, prefer a still-mintable row so
    /// `token mint E2E` does not hit a previously frozen authority with the same name.
    pub fn resolve_token_id(&self, token_or_alias: &str) -> SqlResult<String> {
        if Self::is_drk_token(token_or_alias) {
            return Ok(Self::dark_token_id_hex());
        }
        let mut stmt = self.conn.prepare(
            "SELECT token_id FROM token_mints \
             WHERE alias = ?1 OR token_id = ?1 \
             ORDER BY is_frozen ASC, token_id ASC \
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map([token_or_alias], |r| r.get::<_, String>(0))?;
        if let Some(Ok(tid)) = rows.next() {
            return Ok(tid);
        }
        Ok(token_or_alias.to_string())
    }

    /// Unspent coins held by a DAO treasury matching BOTH spend_hook and user_data (bulla).
    pub fn list_unspent_for_dao(
        &self,
        dao_spend_hook: &[u8],
        dao_bulla: &[u8],
    ) -> SqlResult<Vec<(String, u32, i64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT tx_hash, output_index, value_raw, token_id FROM notes \
             WHERE spent = 0 AND spend_hook_bytes = ?1 AND user_data = ?2 \
             ORDER BY block_height",
        )?;
        let rows = stmt.query_map(params![dao_spend_hook, dao_bulla], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect()
    }

    /// Retrieve notes secrets from all stored DAO records so SyncEngine can trial-decrypt treasury notes.
    pub fn get_all_dao_notes_secrets(&self) -> SqlResult<Vec<Vec<u8>>> {
        use darkfi_sdk::crypto::pasta_prelude::PrimeField;
        let mut stmt = self.conn.prepare("SELECT params_toml FROM dao_records")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut secrets = Vec::new();
        for r in rows {
            let stored = r?;
            let toml_str = crate::secret_wrap::unwrap_secret_text(&stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            if let Ok(value) = toml::from_str::<toml::Value>(&toml_str) {
                if let Some(table) = value.as_table() {
                    let sec = table
                        .get("notes_secret")
                        .or_else(|| table.get("notes_secret_key"))
                        .and_then(|v| v.as_str());
                    if let Some(raw) = sec {
                        if let Ok(sk) = crate::dao_ops::sk_from_b58(raw) {
                            secrets.push(sk.inner().to_repr().to_vec());
                        } else if let Ok(bytes) = bs58::decode(raw).into_vec() {
                            if bytes.len() >= 32 {
                                secrets.push(bytes[..32].to_vec());
                            }
                        } else if let Ok(bytes) = hex::decode(raw.trim_start_matches("0x")) {
                            if bytes.len() >= 32 {
                                secrets.push(bytes[..32].to_vec());
                            }
                        }
                    }
                }
            }
        }
        Ok(secrets)
    }

    /// Unspent DAO treasury coins with full spend fields (matching BOTH spend_hook and user_data).
    #[allow(clippy::type_complexity)]
    pub fn list_unspent_dao_full(
        &self,
        dao_spend_hook: &[u8],
        dao_bulla: &[u8],
    ) -> SqlResult<
        Vec<(
            String,
            u32,
            i64,
            String,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            u32,
            Vec<u8>,
            Vec<u8>,
        )>,
    > {
        let mut stmt = self.conn.prepare(
            "SELECT tx_hash, output_index, value_raw, token_id, coin_blind, value_blind, token_blind, \
             spend_hook_bytes, user_data, leaf_position, commitment, owner_secret \
             FROM notes WHERE spent = 0 AND spend_hook_bytes = ?1 AND user_data = ?2 \
             AND leaf_position IS NOT NULL AND commitment IS NOT NULL AND length(commitment) = 32 \
             AND owner_secret IS NOT NULL \
             ORDER BY block_height",
        )?;
        let rows = stmt.query_map(params![dao_spend_hook, dao_bulla], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, u32>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (tx, idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner_stored) = row?;
            let owner = crate::secret_wrap::unwrap_secret(&owner_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push((
                tx, idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner,
            ));
        }
        Ok(out)
    }

    /// Persist a DAO proposal (locally created or decrypted from `dao_calls`).
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_dao_proposal(
        &self,
        proposal_bulla: &str,
        dao_bulla: &str,
        proposal_bytes: &[u8],
        coin_attrs_bytes: Option<&[u8]>,
        mint_height: Option<u32>,
        tx_hash: Option<&str>,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO dao_proposals \
             (proposal_bulla, dao_bulla, proposal_bytes, coin_attrs_bytes, mint_height, tx_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(proposal_bulla) DO UPDATE SET \
               coin_attrs_bytes = COALESCE(excluded.coin_attrs_bytes, dao_proposals.coin_attrs_bytes), \
               mint_height = COALESCE(excluded.mint_height, dao_proposals.mint_height), \
               tx_hash = COALESCE(excluded.tx_hash, dao_proposals.tx_hash)",
            params![
                proposal_bulla,
                dao_bulla,
                proposal_bytes,
                coin_attrs_bytes,
                mint_height,
                tx_hash
            ],
        )?;
        Ok(())
    }

    /// Look up a stored DAO proposal by Base58 `proposal_bulla`.
    #[allow(clippy::type_complexity)]
    pub fn get_dao_proposal(
        &self,
        proposal_bulla: &str,
    ) -> SqlResult<
        Option<(
            String,
            String,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<u32>,
            Option<String>,
            Option<u32>,
            Option<String>,
        )>,
    > {
        let mut stmt = self.conn.prepare(
            "SELECT proposal_bulla, dao_bulla, proposal_bytes, coin_attrs_bytes, \
             mint_height, tx_hash, exec_height, exec_tx_hash \
             FROM dao_proposals WHERE proposal_bulla = ?1",
        )?;
        let mut rows = stmt.query_map([proposal_bulla], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })?;
        match rows.next() {
            Some(Ok(v)) => Ok(Some(v)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Mark a stored DAO proposal as executed.
    pub fn set_dao_proposal_executed(
        &self,
        proposal_bulla: &str,
        exec_height: Option<u32>,
        exec_tx_hash: Option<&str>,
    ) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE dao_proposals SET \
             exec_height = COALESCE(?2, exec_height), \
             exec_tx_hash = COALESCE(?3, exec_tx_hash) \
             WHERE proposal_bulla = ?1",
            params![proposal_bulla, exec_height, exec_tx_hash],
        )?;
        Ok(())
    }

    /// All synced compact DAO calls in ascending height order (no arbitrary limit).
    pub fn list_all_dao_calls_asc(&self) -> SqlResult<Vec<DaoCallFullRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, tx_hash, kind, bulla, payload FROM dao_calls \
             ORDER BY height ASC, rowid ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        rows.collect()
    }

    /// Synced compact DAO calls including payload (ordered by height ascending for tree/replay).
    pub fn list_dao_calls_full(&self, limit: u32) -> SqlResult<Vec<DaoCallFullRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, tx_hash, kind, bulla, payload FROM dao_calls \
             ORDER BY height ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        rows.collect()
    }

    const META_LAST_SYNCED_HASH: &'static str = "last_synced_hash";
    const META_SYNCED_BLOCK_ANCHORS: &'static str = "synced_block_anchors";
    const MAX_BLOCK_ANCHORS: usize = 128;

    /// Record a canonical `(height, hash)` anchor for reorg continuity checks.
    pub fn record_synced_block_hash(&self, height: u32, hash: &[u8]) -> SqlResult<()> {
        if hash.len() != 32 {
            return Ok(());
        }
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(hash);

        let mut anchors = self.get_synced_block_anchors()?;
        anchors.retain(|(h, _)| *h != height);
        anchors.push((height, hash_arr));
        anchors.sort_by_key(|(h, _)| *h);
        if anchors.len() > Self::MAX_BLOCK_ANCHORS {
            let drop_n = anchors.len() - Self::MAX_BLOCK_ANCHORS;
            anchors.drain(..drop_n);
        }

        let mut encoded = Vec::with_capacity(anchors.len() * 36);
        for (h, bh) in &anchors {
            encoded.extend_from_slice(&h.to_le_bytes());
            encoded.extend_from_slice(bh);
        }
        self.set_meta(Self::META_SYNCED_BLOCK_ANCHORS, &encoded)?;

        // Update `last_synced_hash` if this height is >= previously recorded one.
        let update_last = match self.get_last_synced_hash()? {
            Some((prev_h, _)) => height >= prev_h,
            None => true,
        };
        if update_last {
            let mut last = Vec::with_capacity(36);
            last.extend_from_slice(&height.to_le_bytes());
            last.extend_from_slice(&hash_arr);
            self.set_meta(Self::META_LAST_SYNCED_HASH, &last)?;
        }
        Ok(())
    }

    /// Return the latest recorded `(height, hash)` pair, if any.
    pub fn get_last_synced_hash(&self) -> SqlResult<Option<(u32, [u8; 32])>> {
        let Some(bytes) = self.get_meta(Self::META_LAST_SYNCED_HASH)? else {
            return Ok(None);
        };
        if bytes.len() != 36 {
            return Ok(None);
        }
        let h = u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4]));
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[4..36]);
        Ok(Some((h, arr)))
    }

    /// Return stored `(height, hash)` anchors in ascending height order.
    pub fn get_synced_block_anchors(&self) -> SqlResult<Vec<(u32, [u8; 32])>> {
        let Some(bytes) = self.get_meta(Self::META_SYNCED_BLOCK_ANCHORS)? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(bytes.len() / 36);
        for chunk in bytes.as_chunks::<36>().0 {
            let h = u32::from_le_bytes(chunk[..4].try_into().unwrap_or([0; 4]));
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&chunk[4..36]);
            out.push((h, arr));
        }
        out.sort_by_key(|(h, _)| *h);
        Ok(out)
    }

    /// Clear notes/tx history and Merkle tree, then rewind sync height (rescan).
    pub fn reset_for_rescan(&self, height: u32) -> SqlResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM notes", [])?;
        tx.execute("DELETE FROM transactions", [])?;
        tx.execute(
            "DELETE FROM wallet_meta WHERE key IN \
             ('tree_state', 'tree_applied_height', ?1, 'trial_synced_height', ?2, ?3)",
            params![
                Self::META_MERKLE_FROM_GENESIS,
                Self::META_LAST_SYNCED_HASH,
                Self::META_SYNCED_BLOCK_ANCHORS
            ],
        )?;
        tx.execute(
            "UPDATE sync_state SET last_synced_height = ?1, last_sync_timestamp = datetime('now') WHERE id = 1",
            params![height],
        )?;
        tx.execute("DELETE FROM dao_calls", [])?;
        tx.execute("DELETE FROM func_events", [])?;
        tx.execute(
            "DELETE FROM dao_proposals WHERE coin_attrs_bytes IS NULL",
            [],
        )?;
        tx.execute(
            "UPDATE dao_proposals SET mint_height = NULL, tx_hash = NULL, exec_height = NULL, exec_tx_hash = NULL",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Invalidate notes and transactions above a given height (reorg recovery).
    ///
    /// Runs inside an atomic SQLite transaction. Preserves confirmed data below
    /// the fork point while clearing the Merkle frontier (`tree_state`,
    /// `tree_applied_height`, `merkle_from_genesis`, and unspent `leaf_position`)
    /// so the next sync rebuilds a consistent Money tree without corrupting roots.
    pub fn invalidate_above_height(&self, height: u32) -> SqlResult<(u32, u32)> {
        // Snapshot anchors before opening the transaction so we can prune above `height`.
        let mut anchors = self.get_synced_block_anchors()?;
        anchors.retain(|(h, _)| *h <= height);
        let prev_trial = self.get_meta("trial_synced_height")?;

        let tx = self.conn.unchecked_transaction()?;
        let notes_deleted =
            tx.execute("DELETE FROM notes WHERE block_height > ?1", params![height])?;
        let txs_deleted = tx.execute(
            "DELETE FROM transactions WHERE block_height > ?1",
            params![height],
        )?;
        // Unspend only notes whose nullifier was in a block above the fork.
        // `block_height` is the note's creation height, not its spend height.
        // Rows with a null `spent_height` (legacy, or reserved at broadcast)
        // stay spent so a reorg cannot resurrect historically spent coins.
        tx.execute(
            "UPDATE notes SET spent = 0, spent_height = NULL \
             WHERE spent = 1 AND spent_height IS NOT NULL AND spent_height > ?1",
            params![height],
        )?;
        // Clear cached leaf positions on surviving unspent notes because the
        // Merkle frontier is dropped below and will be rebuilt on next sync.
        tx.execute("UPDATE notes SET leaf_position = NULL WHERE spent = 0", [])?;
        // The Merkle frontier included the orphaned blocks. Drop tree_state,
        // tree_applied_height, and merkle_from_genesis together so ensure_genesis_merkle
        // rebuilds cleanly from genesis instead of appending onto an empty/stale tree.
        tx.execute(
            "DELETE FROM wallet_meta WHERE key IN ('tree_state', 'tree_applied_height', ?1)",
            params![Self::META_MERKLE_FROM_GENESIS],
        )?;
        if anchors.is_empty() {
            tx.execute(
                "DELETE FROM wallet_meta WHERE key IN (?1, ?2)",
                params![Self::META_LAST_SYNCED_HASH, Self::META_SYNCED_BLOCK_ANCHORS],
            )?;
        } else {
            let mut encoded = Vec::with_capacity(anchors.len() * 36);
            for (h, bh) in &anchors {
                encoded.extend_from_slice(&h.to_le_bytes());
                encoded.extend_from_slice(bh);
            }
            tx.execute(
                "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES (?1, ?2)",
                params![Self::META_SYNCED_BLOCK_ANCHORS, encoded],
            )?;
            if let Some((last_h, last_bh)) = anchors.last() {
                let mut last = Vec::with_capacity(36);
                last.extend_from_slice(&last_h.to_le_bytes());
                last.extend_from_slice(last_bh);
                tx.execute(
                    "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES (?1, ?2)",
                    params![Self::META_LAST_SYNCED_HASH, last],
                )?;
            }
        }
        if let Some(bytes) = prev_trial {
            if bytes.len() == 4 {
                let current = u32::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 4]));
                if current > height {
                    tx.execute(
                        "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES ('trial_synced_height', ?1)",
                        params![height.to_le_bytes().as_slice()],
                    )?;
                }
            }
        }
        tx.execute(
            "UPDATE sync_state SET last_synced_height = ?1, last_sync_timestamp = datetime('now') WHERE id = 1",
            params![height],
        )?;
        tx.execute("DELETE FROM dao_calls WHERE height > ?1", params![height])?;
        tx.execute("DELETE FROM func_events WHERE height > ?1", params![height])?;
        tx.execute(
            "UPDATE dao_proposals SET exec_height = NULL, exec_tx_hash = NULL WHERE exec_height > ?1",
            params![height],
        )?;
        tx.execute(
            "DELETE FROM dao_proposals WHERE mint_height > ?1 AND coin_attrs_bytes IS NULL",
            params![height],
        )?;
        tx.execute(
            "UPDATE dao_proposals SET mint_height = NULL, tx_hash = NULL WHERE mint_height > ?1 AND coin_attrs_bytes IS NOT NULL",
            params![height],
        )?;
        tx.commit()?;
        Ok((notes_deleted as u32, txs_deleted as u32))
    }

    pub fn delete_meta(&self, key: &str) -> SqlResult<()> {
        self.conn
            .execute("DELETE FROM wallet_meta WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// List unspent, unhooked wallet notes (excludes contract-hooked / DAO treasury notes).
    pub fn list_unspent(&self) -> SqlResult<Vec<(String, u32, i64, String)>> {
        let is_unhooked = Self::sql_note_unhooked("");
        let query = format!(
            "SELECT tx_hash, output_index, value_raw, token_id FROM notes \
             WHERE spent = 0 AND {is_unhooked} ORDER BY block_height"
        );
        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect()
    }

    // =========================================================================
    // Sync State
    // =========================================================================

    /// Get current sync state.
    pub fn get_sync_state(&self) -> SqlResult<(u32, u32)> {
        let mut stmt = self
            .conn
            .prepare("SELECT last_synced_height, birthday_height FROM sync_state WHERE id = 1")?;
        stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
    }

    /// Update sync progress.
    pub fn set_sync_height(&self, height: u32) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE sync_state SET last_synced_height = ?1, last_sync_timestamp = datetime('now') WHERE id = 1",
            params![height],
        )?;
        Ok(())
    }

    /// Set birthday height.
    pub fn set_birthday_height(&self, height: u32) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE sync_state SET birthday_height = ?1 WHERE id = 1",
            params![height],
        )?;
        Ok(())
    }

    // =========================================================================
    // Transactions
    // =========================================================================

    /// Promote a mempool (height 0) row once the compact block is scanned.
    pub fn confirm_transaction(&self, hash: &str, height: u32) -> SqlResult<usize> {
        if height == 0 {
            return Ok(0);
        }
        self.conn.execute(
            "UPDATE transactions SET block_height = ?1 WHERE hash = ?2 AND block_height = 0",
            params![height, hash],
        )
    }

    /// True if a note with `(tx_hash, commitment)` is already stored in `notes`.
    pub fn note_exists_by_commitment(&self, tx_hash: &str, commitment: &[u8]) -> SqlResult<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM notes WHERE tx_hash = ?1 AND commitment = ?2 LIMIT 1")?;
        let mut rows = stmt.query(params![tx_hash, commitment])?;
        Ok(rows.next()?.is_some())
    }

    /// Resolve a non-colliding `output_index` for `(tx_hash, preferred_idx, commitment)`.
    ///
    /// If `(tx_hash, preferred_idx)` is unoccupied (or occupied by the same commitment),
    /// returns `preferred_idx`. If occupied by a *different* commitment (e.g. a synthetic
    /// `idx = 0` from `GetCompactOutputsByFunc` colliding with a `FeeV1` output in the
    /// same transaction), returns `MAX(output_index) + 1` for `tx_hash`.
    pub fn resolve_note_output_index(
        &self,
        tx_hash: &str,
        preferred_idx: u32,
        commitment: Option<&[u8]>,
    ) -> SqlResult<u32> {
        let existing: Option<Option<Vec<u8>>> = {
            let mut stmt = self.conn.prepare(
                "SELECT commitment FROM notes WHERE tx_hash = ?1 AND output_index = ?2 LIMIT 1",
            )?;
            let mut rows = stmt.query(params![tx_hash, preferred_idx])?;
            if let Some(row) = rows.next()? {
                Some(row.get::<_, Option<Vec<u8>>>(0)?)
            } else {
                None
            }
        };
        let Some(existing_commitment) = existing else {
            return Ok(preferred_idx);
        };
        if let (Some(want), Some(have)) = (commitment, existing_commitment.as_deref()) {
            if want == have {
                return Ok(preferred_idx);
            }
            let max_idx: u32 = self.conn.query_row(
                "SELECT COALESCE(MAX(output_index), 0) FROM notes WHERE tx_hash = ?1",
                params![tx_hash],
                |row| row.get(0),
            )?;
            return Ok(max_idx.saturating_add(1));
        }
        Ok(preferred_idx)
    }

    /// Record or update an incoming transaction by summing ALL notes belonging to
    /// `(hash, token_id)` in `notes`.
    ///
    /// - Multi-output incoming txs (e.g. `--half-split`, batch payouts) reflect the
    ///   exact summed total rather than collapsing to output 0.
    /// - Idempotent across rescans (derives total directly from deduplicated `notes`).
    /// - Never overwrites an `"outgoing"` row (only confirms its `block_height`).
    pub fn upsert_incoming_transaction(
        &self,
        hash: &str,
        block_height: u32,
        fallback_value: i64,
        token_id: &str,
        memo: Option<&str>,
    ) -> SqlResult<()> {
        let summed: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(value_raw), 0) FROM notes WHERE tx_hash = ?1 AND token_id = ?2",
            params![hash, token_id],
            |row| row.get(0),
        )?;
        let total = if summed > 0 { summed } else { fallback_value };
        self.conn.execute(
            "INSERT INTO transactions (hash, block_height, direction, value_raw, token_id, counterparty, memo, kind)
             VALUES (?1, ?2, 'incoming', ?3, ?4, NULL, ?5, 'receive')
             ON CONFLICT(hash) DO UPDATE SET
               block_height = CASE
                 WHEN transactions.block_height = 0 AND excluded.block_height > 0 THEN excluded.block_height
                 ELSE transactions.block_height
               END,
               value_raw = CASE
                 WHEN transactions.direction = 'incoming' AND transactions.token_id = excluded.token_id THEN excluded.value_raw
                 ELSE transactions.value_raw
               END,
               memo = CASE
                 WHEN transactions.direction = 'incoming' AND (transactions.memo IS NULL OR transactions.memo = '') THEN excluded.memo
                 ELSE transactions.memo
               END",
            params![hash, block_height, total, token_id, memo],
        )?;
        Ok(())
    }

    /// Insert a transaction record.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_transaction(
        &self,
        hash: &str,
        block_height: u32,
        direction: &str,
        value_raw: i64,
        token_id: &str,
        counterparty: Option<&str>,
        memo: Option<&str>,
    ) -> SqlResult<()> {
        self.insert_typed(
            hash,
            block_height,
            direction,
            kind_from_direction(direction),
            value_raw,
            token_id,
            counterparty,
            memo,
        )
    }

    /// Insert a history row with an explicit kind (`send`, `token-mint`, `burn`, …).
    #[allow(clippy::too_many_arguments)]
    pub fn insert_typed(
        &self,
        hash: &str,
        block_height: u32,
        direction: &str,
        kind: &str,
        value_raw: i64,
        token_id: &str,
        counterparty: Option<&str>,
        memo: Option<&str>,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO transactions (hash, block_height, direction, value_raw, token_id, counterparty, memo, kind)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(hash) DO UPDATE SET
               block_height = excluded.block_height
             WHERE transactions.block_height = 0 AND excluded.block_height > 0",
            params![
                hash,
                block_height,
                direction,
                value_raw,
                token_id,
                counterparty,
                memo,
                kind
            ],
        )?;
        Ok(())
    }

    /// List transactions, most recent first.
    pub fn list_transactions(&self, limit: u32) -> SqlResult<Vec<TransactionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, block_height, direction, value_raw, token_id, counterparty, memo, timestamp, kind
             FROM transactions ORDER BY block_height DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(TransactionRow {
                hash: row.get(0)?,
                block_height: row.get(1)?,
                direction: row.get(2)?,
                value_raw: row.get(3)?,
                token_id: row.get(4)?,
                counterparty: row.get(5)?,
                memo: row.get(6)?,
                timestamp: row.get(7)?,
                kind: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    /// Get a single transaction by hash.
    pub fn get_transaction(&self, hash: &str) -> SqlResult<Option<TransactionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, block_height, direction, value_raw, token_id, counterparty, memo, timestamp, kind
             FROM transactions WHERE hash = ?1",
        )?;
        let mut rows = stmt.query(params![hash])?;
        if let Some(row) = rows.next()? {
            Ok(Some(TransactionRow {
                hash: row.get(0)?,
                block_height: row.get(1)?,
                direction: row.get(2)?,
                value_raw: row.get(3)?,
                token_id: row.get(4)?,
                counterparty: row.get(5)?,
                memo: row.get(6)?,
                timestamp: row.get(7)?,
                kind: row.get(8)?,
            }))
        } else {
            Ok(None)
        }
    }

    // =========================================================================
    // Pruning
    // =========================================================================

    /// Prune confirmed spent notes whose spend height is below `height` (data minimization).
    /// Unconfirmed reservations (`spent_height IS NULL`) and recently spent old coins are preserved.
    pub fn prune_spent_below(&self, height: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "DELETE FROM notes WHERE spent = 1 AND spent_height IS NOT NULL AND spent_height < ?1",
            params![height],
        )?;
        Ok(rows)
    }

    /// Vacuum the database to reclaim disk space.
    pub fn vacuum(&self) -> SqlResult<()> {
        self.conn.execute_batch("VACUUM")?;
        Ok(())
    }
}

/// A row from the `transactions` table.
#[derive(Debug, Clone)]
pub struct TransactionRow {
    pub hash: String,
    pub block_height: u32,
    pub direction: String,
    pub value_raw: i64,
    pub token_id: String,
    pub counterparty: Option<String>,
    pub memo: Option<String>,
    pub timestamp: String,
    pub kind: String,
}

fn kind_from_direction(direction: &str) -> &str {
    match direction {
        "incoming" => "receive",
        "outgoing" => "send",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_initialize() {
        let db = WalletDb::in_memory().unwrap();
        let (height, birthday) = db.get_sync_state().unwrap();
        assert_eq!(height, 0);
        assert_eq!(birthday, 0);
    }

    #[test]
    fn test_secret_not_stored_plaintext() {
        let db = WalletDb::in_memory().unwrap();
        let secret = [0xABu8; 32];
        db.insert_address("pk", &secret).unwrap();
        let stored: Vec<u8> = db
            .conn
            .query_row(
                "SELECT secret_key FROM addresses WHERE public_key = ?1",
                params!["pk"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            stored.starts_with(b"MSK2"),
            "secret_key must be wrapped (MSK2), got {:?}",
            &stored[..stored.len().min(8)]
        );
        assert_ne!(stored, secret.to_vec());
        // Round-trip via public API still yields plaintext.
        let secrets = db.get_all_secrets().unwrap();
        assert_eq!(secrets, vec![secret.to_vec()]);
    }

    #[test]
    fn test_all_sensitive_secrets_wrapped_at_rest_and_legacy_migrates() {
        let db = WalletDb::in_memory().unwrap();
        let wrap_key = db.wrap_key;

        // 1. Fresh inserts wrap derivation_seed, token_mints, deploy_auths, dao_records with MSK2.
        db.set_wrapped_meta("derivation_seed", &[0x55u8; 32])
            .unwrap();
        let raw_seed: Vec<u8> = db
            .conn
            .query_row(
                "SELECT value FROM wallet_meta WHERE key = 'derivation_seed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(raw_seed.starts_with(b"MSK2"));
        assert_eq!(
            db.get_wrapped_meta("derivation_seed").unwrap().unwrap(),
            vec![0x55u8; 32]
        );

        db.insert_token_mint("tok1", &[0x11u8; 32], &[0x22u8; 32], Some("T1"))
            .unwrap();
        let (raw_auth, raw_blind): (Vec<u8>, Vec<u8>) = db
            .conn
            .query_row(
                "SELECT mint_authority, token_blind FROM token_mints WHERE token_id = 'tok1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(raw_auth.starts_with(b"MSK2"));
        assert!(raw_blind.starts_with(b"MSK2"));

        db.insert_deploy_auth("cid1", &[0x33u8; 32]).unwrap();
        let raw_deploy: Vec<u8> = db
            .conn
            .query_row(
                "SELECT secret_key FROM deploy_auths WHERE contract_id = 'cid1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(raw_deploy.starts_with(b"MSK2"));

        db.upsert_dao_record("d1", "notes_secret_key = \"supersecret\"", None, None)
            .unwrap();
        let raw_dao: String = db
            .conn
            .query_row(
                "SELECT params_toml FROM dao_records WHERE name = 'd1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(raw_dao.starts_with("MSK2:"));
        assert!(!raw_dao.contains("supersecret"));
        assert_eq!(
            db.get_dao_toml("d1").unwrap().unwrap(),
            "notes_secret_key = \"supersecret\""
        );

        // 2. Simulate legacy MSK1 & plaintext rows directly in SQLite -> fail closed before migration.
        let legacy_addr_v1 = crate::secret_wrap::wrap_secret_legacy_v1(&[0x77u8; 32], &wrap_key);
        db.conn
            .execute(
                "INSERT INTO addresses (public_key, secret_key) VALUES ('legacy_pk', ?1)",
                params![legacy_addr_v1],
            )
            .unwrap();
        db.conn
            .execute(
                "UPDATE wallet_meta SET value = ?1 WHERE key = 'derivation_seed'",
                params![vec![0x66u8; 32]],
            )
            .unwrap();
        db.conn
            .execute(
                "UPDATE token_mints SET mint_authority = ?1, token_blind = ?2 WHERE token_id = 'tok1'",
                params![vec![0x88u8; 32], vec![0x99u8; 32]],
            )
            .unwrap();
        db.conn
            .execute(
                "UPDATE deploy_auths SET secret_key = ?1 WHERE contract_id = 'cid1'",
                params![vec![0xAAu8; 32]],
            )
            .unwrap();
        db.conn
            .execute(
                "UPDATE dao_records SET params_toml = 'legacy_plain = true' WHERE name = 'd1'",
                [],
            )
            .unwrap();

        // Fail-closed runtime reads refuse unmigrated MSK1/plaintext!
        assert!(db.get_all_secrets().is_err());
        assert!(db.get_wrapped_meta("derivation_seed").is_err());
        assert!(db.get_token_mint("tok1").is_err());
        assert!(db.get_deploy_auth("cid1").is_err());
        assert!(db.get_dao_toml("d1").is_err());

        // One-time migration upgrades all 5 rows to MSK2!
        let count = db.migrate_secrets_to_v2().unwrap();
        assert_eq!(count, 5);
        assert_eq!(
            db.migrate_secrets_to_v2().unwrap(),
            0,
            "migration must be idempotent"
        );

        assert_eq!(db.get_all_secrets().unwrap(), vec![vec![0x77u8; 32]]);
        assert_eq!(
            db.get_wrapped_meta("derivation_seed").unwrap().unwrap(),
            vec![0x66u8; 32]
        );
        let (_, auth, blind, _) = db.get_token_mint("tok1").unwrap().unwrap();
        assert_eq!(auth, vec![0x88u8; 32]);
        assert_eq!(blind, vec![0x99u8; 32]);
        assert_eq!(
            db.get_deploy_auth("cid1").unwrap().unwrap().0,
            vec![0xAAu8; 32]
        );
        assert_eq!(
            db.get_dao_toml("d1").unwrap().unwrap(),
            "legacy_plain = true"
        );
    }

    #[test]
    fn test_multi_output_incoming_tx_sums_and_avoids_synthetic_idx_collision() {
        let db = WalletDb::in_memory().unwrap();
        let tok = WalletDb::dark_token_id_hex();
        let c0 = [0x10u8; 32];
        let c1 = [0x20u8; 32];

        // First output at idx=0
        let idx0 = db
            .resolve_note_output_index("tx_multi", 0, Some(&c0))
            .unwrap();
        assert_eq!(idx0, 0);
        db.insert_note(
            "tx_multi",
            idx0,
            500,
            &tok,
            &[1],
            100,
            Some("split"),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&c0),
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.upsert_incoming_transaction("tx_multi", 100, 500, &tok, Some("split"))
            .unwrap();
        assert_eq!(
            db.get_transaction("tx_multi").unwrap().unwrap().value_raw,
            500
        );

        // Second output with synthetic idx=0 but DIFFERENT commitment c1 -> gets idx=1, no collision!
        assert!(!db.note_exists_by_commitment("tx_multi", &c1).unwrap());
        let idx1 = db
            .resolve_note_output_index("tx_multi", 0, Some(&c1))
            .unwrap();
        assert_eq!(idx1, 1);
        db.insert_note(
            "tx_multi",
            idx1,
            700,
            &tok,
            &[2],
            100,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&c1),
            Some(&[2]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.upsert_incoming_transaction("tx_multi", 100, 700, &tok, None)
            .unwrap();

        let tx_row = db.get_transaction("tx_multi").unwrap().unwrap();
        assert_eq!(
            tx_row.value_raw, 1200,
            "multi-output incoming tx must sum all outputs"
        );
        assert_eq!(tx_row.memo.as_deref(), Some("split"));

        // Re-scanning is idempotent (no double-counting).
        assert!(db.note_exists_by_commitment("tx_multi", &c0).unwrap());
        db.upsert_incoming_transaction("tx_multi", 100, 500, &tok, Some("split"))
            .unwrap();
        assert_eq!(
            db.get_transaction("tx_multi").unwrap().unwrap().value_raw,
            1200
        );
    }

    #[test]
    fn test_insert_and_list_addresses() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_address("addr1_public_key_hex", &[1, 2, 3])
            .unwrap();
        db.insert_address("addr2_public_key_hex", &[4, 5, 6])
            .unwrap();
        db.set_default_address("addr1_public_key_hex").unwrap();

        let addrs = db.list_addresses().unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].0, "addr1_public_key_hex");
        assert!(addrs[0].1); // is_default

        let def = db.get_default_address().unwrap();
        assert_eq!(def, Some("addr1_public_key_hex".to_string()));
    }

    #[test]
    fn test_insert_note_and_balance() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_note(
            "txhash1",
            0,
            1000,
            "DRK",
            &[1, 2, 3, 4],
            100,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[1, 2, 3, 4]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.insert_note(
            "txhash2",
            0,
            500,
            "DRK",
            &[5, 6, 7, 8],
            101,
            Some("test memo"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[5, 6, 7, 8]),
            Some(&[9u8; 32]),
        )
        .unwrap();

        let balance = db.confirmed_balance("DRK").unwrap();
        assert_eq!(balance, 1500);

        let unspent = db.list_unspent().unwrap();
        assert_eq!(unspent.len(), 2);
    }

    #[test]
    fn test_mark_spent_reduces_balance() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_note(
            "tx1",
            0,
            1000,
            "DRK",
            &[1, 2, 3, 4],
            100,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[1, 2, 3, 4]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.insert_note(
            "tx2",
            0,
            500,
            "DRK",
            &[5, 6, 7, 8],
            101,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[5, 6, 7, 8]),
            Some(&[9u8; 32]),
        )
        .unwrap();

        db.mark_note_spent(&[1, 2, 3, 4]).unwrap();

        let balance = db.confirmed_balance("DRK").unwrap();
        assert_eq!(balance, 500);
    }

    #[test]
    fn test_release_stale_reservations_keeps_confirmed_spends() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_note(
            "reserved",
            0,
            1000,
            "DRK",
            &[1],
            10,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.insert_note(
            "confirmed",
            0,
            2000,
            "DRK",
            &[2],
            11,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[2]),
            Some(&[8u8; 32]),
        )
        .unwrap();
        assert_eq!(db.reserve_note(&[1], 100).unwrap(), 1);
        assert_eq!(db.mark_note_spent_at(&[2], Some(100)).unwrap(), 1);
        // Still inside the grace window.
        assert_eq!(db.release_stale_reservations(107, 8).unwrap(), 0);
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);
        // Chain moved on; the unconfirmed reservation is spendable again.
        assert_eq!(db.release_stale_reservations(109, 8).unwrap(), 1);
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 1000);
        // Confirmed spend stays spent.
        assert_eq!(db.release_stale_reservations(200, 8).unwrap(), 0);
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 1000);
    }

    #[test]
    fn test_mark_spent_by_commitment_and_loc() {
        let db = WalletDb::in_memory().unwrap();
        let commit_a = [0xAAu8; 32];
        let commit_b = [0xBBu8; 32];
        db.insert_note(
            "aabbccdd1111",
            0,
            1000,
            "DRK",
            &[1, 2, 3, 4],
            100,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&commit_a),
            Some(&[1, 2, 3, 4]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.insert_note(
            "ccddeeff2222",
            1,
            500,
            "DRK",
            &[5, 6, 7, 8],
            101,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&commit_b),
            Some(&[5, 6, 7, 8]),
            Some(&[9u8; 32]),
        )
        .unwrap();

        assert_eq!(db.mark_note_spent_by_commitment(&commit_a).unwrap(), 1);
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 500);
        assert_eq!(db.mark_note_spent_by_loc("ccddeeff", 1).unwrap(), 1);
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);
        assert_eq!(db.list_unspent().unwrap().len(), 0);
    }

    #[test]
    fn test_sync_state_update() {
        let db = WalletDb::in_memory().unwrap();
        db.set_sync_height(42).unwrap();
        db.set_birthday_height(10).unwrap();

        let (height, birthday) = db.get_sync_state().unwrap();
        assert_eq!(height, 42);
        assert_eq!(birthday, 10);
    }

    #[test]
    fn test_prune_spent_notes() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_note(
            "tx1",
            0,
            100,
            "DRK",
            &[1],
            50,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.insert_note(
            "tx2",
            0,
            200,
            "DRK",
            &[2],
            60,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[2]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.mark_note_spent_at(&[1], Some(52)).unwrap();

        let pruned = db.prune_spent_below(55).unwrap();
        assert_eq!(pruned, 1);

        // Unspent note still there
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 200);
    }

    #[test]
    fn test_prune_spent_below_preserves_reserved_and_recently_spent_old_coins() {
        let db = WalletDb::in_memory().unwrap();
        // Old coin (height 10) reserved at broadcast (spent_height IS NULL).
        db.insert_note(
            "tx_reserved",
            0,
            100,
            "DRK",
            &[1],
            10,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.reserve_note(&[1], 1000).unwrap();

        // Old coin (height 10) spent recently at height 950.
        db.insert_note(
            "tx_recent",
            0,
            200,
            "DRK",
            &[2],
            10,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[2]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.mark_note_spent_at(&[2], Some(950)).unwrap();

        // Old coin (height 10) spent long ago at height 100.
        db.insert_note(
            "tx_old",
            0,
            300,
            "DRK",
            &[3],
            10,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[3]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.mark_note_spent_at(&[3], Some(100)).unwrap();

        let pruned = db.prune_spent_below(500).unwrap();
        assert_eq!(pruned, 1, "only tx_old spent at 100 should be pruned");

        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM notes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            count, 2,
            "reserved and recently spent old coins must remain"
        );
    }

    #[test]
    fn test_metadata_roundtrip() {
        let db = WalletDb::in_memory().unwrap();
        db.set_meta("seed_hash", &[0xDE, 0xAD]).unwrap();
        let val = db.get_meta("seed_hash").unwrap();
        assert_eq!(val, Some(vec![0xDE, 0xAD]));

        assert_eq!(db.get_meta("nonexistent").unwrap(), None);
    }

    #[test]
    fn test_duplicate_note_ignored() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_note(
            "tx1",
            0,
            100,
            "DRK",
            &[1],
            50,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        // Same tx_hash + output_index should be ignored (INSERT OR IGNORE)
        db.insert_note(
            "tx1",
            0,
            999,
            "DRK",
            &[1],
            50,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();

        let balance = db.confirmed_balance("DRK").unwrap();
        assert_eq!(balance, 100); // Not 999
    }

    #[test]
    fn test_invalidate_above_height_removes_notes() {
        let db = WalletDb::in_memory().unwrap();
        for (h, ser) in [(100u32, &[10u8][..]), (200, &[20u8]), (300, &[30u8])] {
            db.insert_note(
                &format!("tx_{h}"),
                0,
                1000,
                "DRK",
                ser,
                h,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(ser),
                Some(&[9u8; 32]),
            )
            .unwrap();
        }
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 3000);

        let (notes_del, _) = db.invalidate_above_height(150).unwrap();
        assert_eq!(notes_del, 2);
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 1000);
        let (sync_h, _) = db.get_sync_state().unwrap();
        assert_eq!(sync_h, 150);
    }

    #[test]
    fn test_invalidate_above_height_unspends_coins() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_note(
            "tx_lo",
            0,
            500,
            "DRK",
            &[1],
            100,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.insert_note(
            "tx_hi",
            0,
            300,
            "DRK",
            &[2],
            200,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[2]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        // Spent in a block that the rewind keeps (height 80).
        db.mark_note_spent_at(&[1], Some(80)).unwrap();
        // Spent in a block the rewind orphans (height 200).
        db.mark_note_spent_at(&[2], Some(200)).unwrap();
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);

        db.invalidate_above_height(150).unwrap();
        // The height-200 note is deleted. The height-100 note was spent at 80,
        // which is still canonical, so it stays spent.
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);

        db.insert_note(
            "tx_reorg_spend",
            0,
            700,
            "DRK",
            &[3],
            120,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[3]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.mark_note_spent_at(&[3], Some(180)).unwrap();
        db.invalidate_above_height(150).unwrap();
        // Spend was above the fork, so the coin is unspent again.
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 700);
    }

    #[test]
    fn test_invalidate_above_height_removes_transactions() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_transaction("hash_100", 100, "incoming", 1000, "DRK", None, None)
            .unwrap();
        db.insert_transaction("hash_200", 200, "outgoing", 500, "DRK", None, None)
            .unwrap();
        db.insert_transaction("hash_300", 300, "incoming", 200, "DRK", None, None)
            .unwrap();

        let (_, txs_del) = db.invalidate_above_height(150).unwrap();
        assert_eq!(txs_del, 2);

        let remaining = db.list_transactions(100).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].hash, "hash_100");
    }

    #[test]
    fn test_insert_transaction_promotes_mempool_height() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_transaction(
            "685d3b0f",
            0,
            "outgoing",
            1_000_000,
            "DRK",
            None,
            Some("e2e"),
        )
        .unwrap();
        db.insert_transaction("685d3b0f", 62369, "incoming", 4_000_000, "DRK", None, None)
            .unwrap();
        let tx = db.get_transaction("685d3b0f").unwrap().expect("row");
        assert_eq!(tx.block_height, 62369);
        assert_eq!(tx.direction, "outgoing");
        assert_eq!(tx.memo.as_deref(), Some("e2e"));

        db.insert_transaction("aabbccdd", 0, "outgoing", 1, "DRK", None, None)
            .unwrap();
        assert_eq!(db.confirm_transaction("aabbccdd", 61675).unwrap(), 1);
        assert_eq!(
            db.get_transaction("aabbccdd")
                .unwrap()
                .unwrap()
                .block_height,
            61675
        );
    }

    #[test]
    fn test_reset_for_rescan_wipes_everything() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_note(
            "tx1",
            0,
            1000,
            "DRK",
            &[1],
            100,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.insert_transaction("hash1", 100, "incoming", 1000, "DRK", None, None)
            .unwrap();
        db.set_meta("tree_state", &[0xFF; 64]).unwrap();
        db.set_sync_height(100).unwrap();

        db.set_meta("trial_synced_height", &500u32.to_le_bytes())
            .unwrap();
        db.reset_for_rescan(0).unwrap();

        assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);
        assert_eq!(db.get_meta("trial_synced_height").unwrap(), None);
        assert!(db.list_transactions(100).unwrap().is_empty());
        assert_eq!(db.get_meta("tree_state").unwrap(), None);
        assert!(!db.merkle_from_genesis());
        let (h, _) = db.get_sync_state().unwrap();
        assert_eq!(h, 0);
    }

    #[test]
    fn test_merkle_from_genesis_flag_roundtrip() {
        let db = WalletDb::in_memory().unwrap();
        assert!(!db.merkle_from_genesis());
        db.set_merkle_from_genesis(true).unwrap();
        assert!(db.merkle_from_genesis());
        db.set_meta("tree_state", &[0xFF; 8]).unwrap();
        db.reset_for_rescan(52999).unwrap();
        assert!(!db.merkle_from_genesis());
        assert_eq!(db.get_meta("tree_state").unwrap(), None);
    }

    #[test]
    fn test_invalidate_clears_merkle_state_and_clamps_trial_cursor() {
        let db = WalletDb::in_memory().unwrap();
        db.set_meta("tree_state", &[0xAA; 16]).unwrap();
        db.set_merkle_from_genesis(true).unwrap();
        db.set_meta("trial_synced_height", &6_000u32.to_le_bytes())
            .unwrap();
        db.set_meta("tree_applied_height", &6_000u32.to_le_bytes())
            .unwrap();
        db.record_synced_block_hash(90, &[0x11; 32]).unwrap();
        db.record_synced_block_hash(120, &[0x22; 32]).unwrap();
        db.insert_note(
            "tx_keep",
            0,
            500,
            "DRK",
            &[7],
            50,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(42),
            Some(&[8u8; 32]),
            Some(&[7]),
            Some(&[9u8; 32]),
        )
        .unwrap();

        db.invalidate_above_height(100).unwrap();
        assert_eq!(db.get_meta("tree_state").unwrap(), None);
        assert_eq!(db.get_meta("tree_applied_height").unwrap(), None);
        assert!(!db.merkle_from_genesis());
        assert_eq!(
            db.get_meta("trial_synced_height").unwrap().unwrap(),
            100u32.to_le_bytes()
        );
        assert_eq!(db.get_last_synced_hash().unwrap(), Some((90, [0x11; 32])));
        let leaf_pos: Option<u32> = db
            .conn
            .query_row(
                "SELECT leaf_position FROM notes WHERE tx_hash = 'tx_keep'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(leaf_pos, None, "leaf_position must be cleared on reorg");
    }

    #[test]
    fn test_list_unspent_for_dao_requires_both_hook_and_bulla() {
        let db = WalletDb::in_memory().unwrap();
        let hook_dao = [0xA1u8; 32];
        let hook_other = [0xB2u8; 32];
        let bulla_a = [0x11u8; 32];
        let bulla_b = [0x22u8; 32];

        // DAO A treasury coin (matches hook_dao + bulla_a).
        db.insert_note(
            "tx_dao_a",
            0,
            1000,
            "DRK",
            &[1],
            10,
            None,
            None,
            None,
            None,
            Some(hook_dao[0]),
            Some(&bulla_a),
            Some(1),
            Some(&[1u8; 32]),
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.set_spend_hook_bytes("tx_dao_a", 0, &hook_dao).unwrap();

        // DAO B treasury coin (same hook_dao, different bulla_b).
        db.insert_note(
            "tx_dao_b",
            0,
            2000,
            "DRK",
            &[2],
            11,
            None,
            None,
            None,
            None,
            Some(hook_dao[0]),
            Some(&bulla_b),
            Some(2),
            Some(&[2u8; 32]),
            Some(&[2]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.set_spend_hook_bytes("tx_dao_b", 0, &hook_dao).unwrap();

        // Unrelated hooked coin sharing bulla_a but different spend_hook.
        db.insert_note(
            "tx_other_hook",
            0,
            3000,
            "DRK",
            &[3],
            12,
            None,
            None,
            None,
            None,
            Some(hook_other[0]),
            Some(&bulla_a),
            Some(3),
            Some(&[3u8; 32]),
            Some(&[3]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        db.set_spend_hook_bytes("tx_other_hook", 0, &hook_other)
            .unwrap();

        let dao_a_coins = db.list_unspent_for_dao(&hook_dao, &bulla_a).unwrap();
        assert_eq!(dao_a_coins.len(), 1);
        assert_eq!(dao_a_coins[0].0, "tx_dao_a");
        assert_eq!(dao_a_coins[0].2, 1000);

        let dao_b_coins = db.list_unspent_for_dao(&hook_dao, &bulla_b).unwrap();
        assert_eq!(dao_b_coins.len(), 1);
        assert_eq!(dao_b_coins[0].0, "tx_dao_b");
        assert_eq!(dao_b_coins[0].2, 2000);

        // Hooked DAO coins must never appear in ordinary spendable queries.
        assert!(db.list_unspent().unwrap().is_empty());
        assert!(db.list_unspent_full().unwrap().is_empty());
    }

    #[test]
    fn test_list_token_balances_resolves_alias_across_hex_and_base58() {
        use darkfi_money_contract::model::TokenId;
        use std::str::FromStr;

        let db = WalletDb::in_memory().unwrap();
        let b58_id = "DkKtPmBw2LKCpo5KXq5RKR7Cp3V4pTzVchtJ4kJaPjpK";
        let id = TokenId::from_str(b58_id).unwrap();
        let hex_id = hex::encode(id.to_bytes());

        db.insert_token_mint(b58_id, &[1u8; 32], &[2u8; 32], Some("ANON"))
            .unwrap();
        db.insert_note(
            "tx_tok",
            0,
            555_000,
            &hex_id,
            &[1],
            50,
            None,
            None,
            None,
            None,
            Some(0),
            None,
            Some(1),
            Some(&[7u8; 32]),
            Some(&[1]),
            Some(&[9u8; 32]),
        )
        .unwrap();

        let balances = db.list_token_balances().unwrap();
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[0].0, hex_id);
        assert_eq!(balances[0].1.as_deref(), Some("ANON"));
        assert_eq!(balances[0].2, 555_000);
    }

    #[test]
    fn test_reimport_preserves_freeze_and_lock_state_and_prefers_unfrozen() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_token_mint("tok_a", &[1u8; 32], &[2u8; 32], Some("SHARED"))
            .unwrap();
        db.set_token_frozen("tok_a", Some(123)).unwrap();
        // Re-importing must preserve is_frozen and freeze_height.
        db.insert_token_mint("tok_a", &[1u8; 32], &[2u8; 32], None)
            .unwrap();
        let rows = db.list_token_mints().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].3.as_deref(), Some("SHARED"));
        assert!(rows[0].4, "is_frozen must be preserved on re-import");
        assert_eq!(rows[0].5, Some(123), "freeze_height must be preserved");

        // Second mint sharing alias "SHARED" (unfrozen) must win get_token_mint.
        db.insert_token_mint("tok_b", &[3u8; 32], &[4u8; 32], Some("SHARED"))
            .unwrap();
        let picked = db.get_token_mint("SHARED").unwrap().unwrap();
        assert_eq!(picked.0, "tok_b");
        assert!(!picked.3);

        // Same preservation check for deploy_auths.
        db.insert_deploy_auth("cid_1", &[5u8; 32]).unwrap();
        db.set_deploy_locked("cid_1", Some(456)).unwrap();
        db.insert_deploy_auth("cid_1", &[5u8; 32]).unwrap();
        let auths = db.list_deploy_auths().unwrap();
        assert_eq!(auths, vec![("cid_1".to_string(), true, Some(456))]);
    }

    #[test]
    fn test_get_all_secrets_orders_default_first() {
        let db = WalletDb::in_memory().unwrap();
        db.insert_address("addr_first", &[1u8; 32]).unwrap();
        db.insert_address("addr_second", &[2u8; 32]).unwrap();
        db.set_default_address("addr_second").unwrap();
        let secrets = db.get_all_secrets().unwrap();
        assert_eq!(secrets[0], vec![2u8; 32]);
        assert_eq!(secrets[1], vec![1u8; 32]);
    }

    #[test]
    fn test_invalidate_empty_db_succeeds() {
        let db = WalletDb::in_memory().unwrap();
        let (notes, txs) = db.invalidate_above_height(0).unwrap();
        assert_eq!(notes, 0);
        assert_eq!(txs, 0);
    }

    #[test]
    fn test_zeroblob_spend_hook_bytes_count_as_unhooked() {
        let db = WalletDb::in_memory().unwrap();
        let drk = WalletDb::dark_token_id_hex();
        db.insert_note(
            "tx-zero-hook",
            0,
            2_000_000_000,
            &drk,
            &[1, 2, 3, 4],
            50,
            None,
            None,
            None,
            None,
            Some(0),
            None,
            Some(1),
            Some(&[7u8; 32]),
            Some(&[1, 2, 3, 4]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        // Compact sync stores FuncId::none() as 32 zero bytes, not NULL/empty.
        db.set_spend_hook_bytes("tx-zero-hook", 0, &[0u8; 32])
            .unwrap();
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 2_000_000_000);
        let listed = db.list_token_balances().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(WalletDb::is_drk_token(&listed[0].0));
        assert_eq!(listed[0].2, 2_000_000_000);
    }

    #[test]
    fn confirmed_balance_matches_base58_token_id_to_hex_note() {
        use std::str::FromStr;

        use darkfi_money_contract::model::TokenId;

        let db = WalletDb::in_memory().unwrap();
        let id = TokenId::from_str("DkKtPmBw2LKCpo5KXq5RKR7Cp3V4pTzVchtJ4kJaPjpK").unwrap();
        let hex_id = hex::encode(id.to_bytes());
        assert_eq!(
            WalletDb::token_id_hex("DkKtPmBw2LKCpo5KXq5RKR7Cp3V4pTzVchtJ4kJaPjpK").as_deref(),
            Some(hex_id.as_str())
        );
        db.insert_note(
            "tx-omr2",
            0,
            100_000_000,
            &hex_id,
            &[1, 2, 3, 4],
            50,
            None,
            None,
            None,
            None,
            Some(0),
            None,
            Some(1),
            Some(&[7u8; 32]),
            Some(&[1, 2, 3, 4]),
            Some(&[9u8; 32]),
        )
        .unwrap();
        assert_eq!(
            db.confirmed_balance("DkKtPmBw2LKCpo5KXq5RKR7Cp3V4pTzVchtJ4kJaPjpK")
                .unwrap(),
            100_000_000
        );
    }
}
