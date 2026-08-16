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

/// Local wallet database backed by SQLCipher.
pub struct WalletDb {
    conn: Connection,
    /// Key for wrapping address secrets at rest (S14).
    wrap_key: [u8; 32],
}

impl WalletDb {
    /// Open or create the wallet database at the given path.
    pub fn open(path: &str) -> SqlResult<Self> {
        let passphrase = crate::secret_wrap::load_or_create_passphrase(path)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        let wrap_key = crate::secret_wrap::load_or_create_wrap_key(path)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        let conn = Connection::open(path)?;
        // SQLCipher: unlock / encrypt the database with the wallet passphrase.
        conn.pragma_update(None, "key", &passphrase)?;
        let db = Self { conn, wrap_key };
        db.initialize()?;
        // Persist wrap key inside encrypted wallet_meta (passphrase-wrapped).
        if db.get_meta(crate::secret_wrap::META_WRAP_KEY)?.is_none() {
            crate::secret_wrap::store_wrap_key_in_meta(
                |k, v| db.set_meta(k, v).map_err(|e| e.to_string()),
                &db.wrap_key,
                &passphrase,
            )
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        }
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
        ",
        )?;
        self.migrate_notes_columns()?;
        Ok(())
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

    /// Ensure migrated columns exist on older wallet DBs.
    fn migrate_notes_columns(&self) -> SqlResult<()> {
        let _ = self
            .conn
            .execute("ALTER TABLE notes ADD COLUMN owner_secret BLOB", []);
        Ok(())
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
    /// token_blind, spend_hook, user_data, leaf_position, commitment, owner_secret)`.
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
            u8,
            Vec<u8>,
            u32,
            Vec<u8>,
            Vec<u8>,
        )>,
    > {
        let mut stmt = self.conn.prepare(
            "SELECT tx_hash, output_index, value_raw, token_id, coin_blind, value_blind, token_blind, \
             spend_hook, user_data, leaf_position, commitment, owner_secret \
             FROM notes WHERE spent = 0 AND leaf_position IS NOT NULL \
             AND commitment IS NOT NULL AND length(commitment) = 32 \
             AND owner_secret IS NOT NULL \
             ORDER BY block_height",
        )?;
        let rows = stmt.query_map([], |row| {
            let owner_stored: Vec<u8> = row.get(11)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, u8>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, u32>(9)?,
                row.get::<_, Vec<u8>>(10)?,
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

    /// Retrieve all address secret keys for trial decryption.
    pub fn get_all_secrets(&self) -> SqlResult<Vec<Vec<u8>>> {
        let mut stmt = self.conn.prepare("SELECT secret_key FROM addresses")?;
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
    pub fn mark_note_spent(&self, nullifier: &[u8]) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1 WHERE nullifier = ?1 AND spent = 0",
            params![nullifier],
        )?;
        Ok(rows)
    }

    /// Confirmed balance for a token. `"DRK"` matches the native DarkFi token
    /// hex id (and older rows stored as the literal `DRK`).
    pub fn confirmed_balance(&self, token_id: &str) -> SqlResult<i64> {
        if Self::is_drk_token(token_id) {
            let hex = Self::dark_token_id_hex();
            let mut stmt = self.conn.prepare(
                "SELECT COALESCE(SUM(value_raw), 0) FROM notes \
                 WHERE spent = 0 AND (token_id = ?1 OR lower(token_id) = 'drk')",
            )?;
            let balance: i64 = stmt.query_row(params![hex], |row| row.get(0))?;
            Ok(balance)
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT COALESCE(SUM(value_raw), 0) FROM notes WHERE token_id = ?1 AND spent = 0",
            )?;
            let balance: i64 = stmt.query_row(params![token_id], |row| row.get(0))?;
            Ok(balance)
        }
    }

    /// Clear notes/tx history and Merkle tree, then rewind sync height (rescan).
    pub fn reset_for_rescan(&self, height: u32) -> SqlResult<()> {
        self.conn.execute("DELETE FROM notes", [])?;
        self.conn.execute("DELETE FROM transactions", [])?;
        self.conn
            .execute("DELETE FROM wallet_meta WHERE key = 'tree_state'", [])?;
        self.set_sync_height(height)?;
        Ok(())
    }

    /// Invalidate notes and transactions above a given height (reorg recovery).
    ///
    /// Unlike `reset_for_rescan` which wipes everything, this preserves data
    /// from confirmed blocks below the fork point.
    pub fn invalidate_above_height(&self, height: u32) -> SqlResult<(u32, u32)> {
        let notes_deleted = self
            .conn
            .execute("DELETE FROM notes WHERE block_height > ?1", params![height])?;
        let txs_deleted = self.conn.execute(
            "DELETE FROM transactions WHERE block_height > ?1",
            params![height],
        )?;
        // Re-compute spent status: notes that were marked spent by now-orphaned
        // transactions need to be un-spent.
        self.conn.execute(
            "UPDATE notes SET spent = 0 WHERE spent = 1 AND block_height <= ?1",
            params![height],
        )?;
        self.set_sync_height(height)?;
        Ok((notes_deleted as u32, txs_deleted as u32))
    }

    /// List unspent notes.
    pub fn list_unspent(&self) -> SqlResult<Vec<(String, u32, i64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT tx_hash, output_index, value_raw, token_id FROM notes WHERE spent = 0 ORDER BY block_height",
        )?;
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
        self.conn.execute(
            "INSERT OR IGNORE INTO transactions (hash, block_height, direction, value_raw, token_id, counterparty, memo)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![hash, block_height, direction, value_raw, token_id, counterparty, memo],
        )?;
        Ok(())
    }

    /// List transactions, most recent first.
    pub fn list_transactions(&self, limit: u32) -> SqlResult<Vec<TransactionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, block_height, direction, value_raw, token_id, counterparty, memo, timestamp
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
            })
        })?;
        rows.collect()
    }

    /// Get a single transaction by hash.
    pub fn get_transaction(&self, hash: &str) -> SqlResult<Option<TransactionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, block_height, direction, value_raw, token_id, counterparty, memo, timestamp
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
            }))
        } else {
            Ok(None)
        }
    }

    // =========================================================================
    // Pruning
    // =========================================================================

    /// Prune spent notes below a given height (data minimization).
    pub fn prune_spent_below(&self, height: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "DELETE FROM notes WHERE spent = 1 AND block_height < ?1",
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
            stored.starts_with(b"MSK1"),
            "secret_key must be wrapped (MSK1), got {:?}",
            &stored[..stored.len().min(8)]
        );
        assert_ne!(stored, secret.to_vec());
        // Round-trip via public API still yields plaintext.
        let secrets = db.get_all_secrets().unwrap();
        assert_eq!(secrets, vec![secret.to_vec()]);
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
        db.mark_note_spent(&[1]).unwrap();

        let pruned = db.prune_spent_below(55).unwrap();
        assert_eq!(pruned, 1);

        // Unspent note still there
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 200);
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
        db.mark_note_spent(&[1]).unwrap();
        db.mark_note_spent(&[2]).unwrap();
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);

        db.invalidate_above_height(150).unwrap();
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 500);
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

        db.reset_for_rescan(0).unwrap();

        assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);
        assert!(db.list_transactions(100).unwrap().is_empty());
        assert_eq!(db.get_meta("tree_state").unwrap(), None);
        let (h, _) = db.get_sync_state().unwrap();
        assert_eq!(h, 0);
    }

    #[test]
    fn test_invalidate_empty_db_succeeds() {
        let db = WalletDb::in_memory().unwrap();
        let (notes, txs) = db.invalidate_above_height(0).unwrap();
        assert_eq!(notes, 0);
        assert_eq!(txs, 0);
    }
}
