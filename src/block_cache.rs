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

//! Local compact block cache for padded trial decryption.
//!
//! Moonshine stores short-lived CompactBlock protobufs while a sync window
//! is applied, matching the Nighthawk UniFFI (`darkfi-mobile-ffi`) cache:
//! `NHC1` + XChaCha20-Poly1305 under the wallet passphrase, then delete the
//! height as soon as trial decrypt has written notes / DAO / func events.
//!
//! This is a light-wallet cache only — not a darkfid block store.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use rusqlite::{params, Connection, Result as SqlResult};
use std::path::Path;

/// Same magic and key context as `darkfi-mobile-ffi` `MobileBlockCache`.
const CACHE_MAGIC: &[u8] = b"NHC1";
const NONCE_LEN: usize = 24;
const CACHE_KEY_CONTEXT: &str = "nighthawk compact-block-cache v1";

fn cache_key_for_wallet_db(wallet_db: &str) -> Option<[u8; 32]> {
    let pass = crate::secret_wrap::load_or_create_passphrase(wallet_db).ok()?;
    Some(blake3::derive_key(CACHE_KEY_CONTEXT, pass.as_bytes()))
}

fn wrap_blob(key: Option<&[u8; 32]>, plaintext: &[u8]) -> SqlResult<Vec<u8>> {
    let Some(key) = key else {
        return Ok(plaintext.to_vec());
    };
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| sql_err(e.to_string()))?;
    let mut out = Vec::with_capacity(CACHE_MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(CACHE_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unwrap_blob(key: Option<&[u8; 32]>, data: &[u8]) -> SqlResult<Vec<u8>> {
    if !data.starts_with(CACHE_MAGIC) {
        return Ok(data.to_vec());
    }
    let Some(key) = key else {
        return Err(sql_err(
            "encrypted compact-block cache requires wallet key".into(),
        ));
    };
    if data.len() <= CACHE_MAGIC.len() + NONCE_LEN {
        return Err(sql_err("truncated encrypted compact block".into()));
    }
    let nonce = &data[CACHE_MAGIC.len()..CACHE_MAGIC.len() + NONCE_LEN];
    let ct = &data[CACHE_MAGIC.len() + NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| sql_err("compact-block cache decrypt failed".into()))
}

fn sql_err(err: String) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(err)))
}

/// Compact-block rows use the Nighthawk UniFFI cache format (`NHC1` + the
/// wallet passphrase). Detection keys stay in the same SQLite file.
pub struct BlockCache {
    conn: Connection,
    key: Option<[u8; 32]>,
}

impl BlockCache {
    /// Open or create the block cache database.
    pub fn open(path: &str) -> SqlResult<Self> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS compact_blocks (
                height INTEGER PRIMARY KEY,
                data BLOB NOT NULL,
                cached_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS cache_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS detection_keys (
                key_id BLOB PRIMARY KEY,
                det_key BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            ",
        )?;
        let wallet_db = path.strip_suffix(".blocks.db").unwrap_or(path);
        Ok(Self {
            conn,
            key: cache_key_for_wallet_db(wallet_db),
        })
    }

    /// Open an in-memory cache for testing.
    #[cfg(test)]
    pub fn in_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS compact_blocks (
                height INTEGER PRIMARY KEY,
                data BLOB NOT NULL,
                cached_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS cache_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS detection_keys (
                key_id BLOB PRIMARY KEY,
                det_key BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            ",
        )?;
        Ok(Self { conn, key: None })
    }

    /// Insert a compact block (serialized protobuf).
    pub fn insert_block(&self, height: u32, data: &[u8]) -> SqlResult<()> {
        let stored = wrap_blob(self.key.as_ref(), data)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO compact_blocks (height, data) VALUES (?1, ?2)",
            params![height, stored],
        )?;
        Ok(())
    }

    /// Get a single cached block by height.
    pub fn get_block(&self, height: u32) -> SqlResult<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM compact_blocks WHERE height = ?1")?;
        let mut rows = stmt.query(params![height])?;
        if let Some(row) = rows.next()? {
            let data: Vec<u8> = row.get(0)?;
            unwrap_blob(self.key.as_ref(), &data).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Get all cached blocks in a height range (inclusive).
    #[cfg(test)]
    pub fn get_range(&self, start: u32, end: u32) -> SqlResult<Vec<(u32, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, data FROM compact_blocks WHERE height >= ?1 AND height <= ?2 ORDER BY height",
        )?;
        let rows = stmt.query_map(params![start, end], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.collect()
    }

    /// Get the highest cached block height, or 0 if cache is empty.
    #[cfg(test)]
    pub fn highest_cached(&self) -> SqlResult<u32> {
        let mut stmt = self
            .conn
            .prepare("SELECT COALESCE(MAX(height), 0) FROM compact_blocks")?;
        stmt.query_row([], |row| row.get(0))
    }

    /// Get the lowest cached block height, or None if cache is empty.
    #[cfg(test)]
    pub fn lowest_cached(&self) -> SqlResult<Option<u32>> {
        let mut stmt = self
            .conn
            .prepare("SELECT MIN(height) FROM compact_blocks")?;
        stmt.query_row([], |row| row.get(0))
    }

    /// Count of cached blocks.
    #[cfg(test)]
    pub fn count(&self) -> SqlResult<u32> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM compact_blocks")?;
        stmt.query_row([], |row| row.get(0))
    }

    /// Approximate cache size in bytes.
    #[cfg(test)]
    pub fn size_bytes(&self) -> SqlResult<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT COALESCE(SUM(LENGTH(data)), 0) FROM compact_blocks")?;
        stmt.query_row([], |row| row.get(0))
    }

    /// Drop one compact block after trial decrypt has applied it.
    pub fn delete_height(&self, height: u32) -> SqlResult<usize> {
        let n = self.conn.execute(
            "DELETE FROM compact_blocks WHERE height = ?1",
            params![height],
        )?;
        Ok(n)
    }

    /// Delete every compact block at or below a height that has been processed.
    pub fn prune_scanned(&self, scanned_height: u32) -> SqlResult<usize> {
        let n = self.conn.execute(
            "DELETE FROM compact_blocks WHERE height <= ?1",
            params![scanned_height],
        )?;
        Ok(n)
    }

    /// Drop cached blocks above a fork height (reorg).
    pub fn delete_above(&self, height: u32) -> SqlResult<usize> {
        let n = self.conn.execute(
            "DELETE FROM compact_blocks WHERE height > ?1",
            params![height],
        )?;
        Ok(n)
    }

    /// Prune blocks below a given height.
    #[allow(dead_code)]
    pub fn prune_below(&self, height: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "DELETE FROM compact_blocks WHERE height < ?1",
            params![height],
        )?;
        Ok(rows)
    }

    /// Delete compact blocks that sync has already processed.
    ///
    /// The Nighthawk cache does not keep a retention window. Once a height is
    /// applied, the protobuf is gone.
    pub fn prune_for_sync_height(&self, sync_height: u32) -> SqlResult<usize> {
        self.prune_scanned(sync_height)
    }

    /// Check if a contiguous range [start, end] is fully cached.
    #[cfg(test)]
    pub fn is_range_cached(&self, start: u32, end: u32) -> SqlResult<bool> {
        let expected = end - start + 1;
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM compact_blocks WHERE height >= ?1 AND height <= ?2")?;
        let actual: u32 = stmt.query_row(params![start, end], |row| row.get(0))?;
        Ok(actual == expected)
    }

    /// Get a cached UnifOMR detection key by opaque id (BLAKE3 of
    /// wallet-secret + network, computed by the caller).
    ///
    /// Detection keys are ~38MB of BFV ciphertexts that take seconds to
    /// build; they are deterministic-keyed to the wallet but re-randomized
    /// per build, and any previously built key remains valid. Caching them
    /// locally is safe: the same bytes are sent to lightwalletd anyway, and
    /// they reveal nothing about the wallet secret.
    pub fn get_detection_key(&self, key_id: &[u8]) -> SqlResult<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT det_key FROM detection_keys WHERE key_id = ?1")?;
        let mut rows = stmt.query(params![key_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Store a UnifOMR detection key under an opaque id.
    pub fn put_detection_key(&self, key_id: &[u8], det_key: &[u8]) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO detection_keys (key_id, det_key) VALUES (?1, ?2)",
            params![key_id, det_key],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let cache = BlockCache::in_memory().unwrap();
        cache.insert_block(100, b"block100").unwrap();
        cache.insert_block(101, b"block101").unwrap();

        assert_eq!(cache.get_block(100).unwrap(), Some(b"block100".to_vec()));
        assert_eq!(cache.get_block(101).unwrap(), Some(b"block101".to_vec()));
        assert_eq!(cache.get_block(102).unwrap(), None);
    }

    #[test]
    fn test_get_range() {
        let cache = BlockCache::in_memory().unwrap();
        for h in 100..110 {
            cache.insert_block(h, format!("b{}", h).as_bytes()).unwrap();
        }
        let range = cache.get_range(102, 105).unwrap();
        assert_eq!(range.len(), 4);
        assert_eq!(range[0].0, 102);
        assert_eq!(range[3].0, 105);
    }

    #[test]
    fn test_prune() {
        let cache = BlockCache::in_memory().unwrap();
        for h in 100..200 {
            cache.insert_block(h, b"data").unwrap();
        }
        assert_eq!(cache.count().unwrap(), 100);

        let pruned = cache.prune_below(150).unwrap();
        assert_eq!(pruned, 50);
        assert_eq!(cache.count().unwrap(), 50);
        assert_eq!(cache.lowest_cached().unwrap(), Some(150));
    }

    #[test]
    fn test_is_range_cached() {
        let cache = BlockCache::in_memory().unwrap();
        for h in 100..110 {
            cache.insert_block(h, b"data").unwrap();
        }
        assert!(cache.is_range_cached(100, 109).unwrap());
        assert!(!cache.is_range_cached(100, 110).unwrap()); // 110 missing
    }

    #[test]
    fn test_highest_cached() {
        let cache = BlockCache::in_memory().unwrap();
        assert_eq!(cache.highest_cached().unwrap(), 0);
        cache.insert_block(42, b"data").unwrap();
        assert_eq!(cache.highest_cached().unwrap(), 42);
    }

    #[test]
    fn processed_block_is_removed_from_nighthawk_cache() {
        let dir = std::env::temp_dir().join(format!(
            "moonshine-nighthawk-cache-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.blocks.db");
        std::fs::write(dir.join("wallet.pass"), "e2e-localnet\n").unwrap();
        let cache = BlockCache::open(path.to_str().unwrap()).unwrap();
        cache.insert_block(7, b"compact").unwrap();
        assert_eq!(
            cache.get_block(7).unwrap().as_deref(),
            Some(&b"compact"[..])
        );
        let raw: Vec<u8> = cache
            .conn
            .query_row(
                "SELECT data FROM compact_blocks WHERE height = 7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(raw.starts_with(b"NHC1"));
        assert_eq!(cache.delete_height(7).unwrap(), 1);
        assert_eq!(cache.get_block(7).unwrap(), None);
        assert_eq!(cache.prune_scanned(9).unwrap(), 0);
        drop(cache);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_size_bytes() {
        let cache = BlockCache::in_memory().unwrap();
        cache.insert_block(1, &[0u8; 100]).unwrap();
        cache.insert_block(2, &[0u8; 200]).unwrap();
        assert_eq!(cache.size_bytes().unwrap(), 300);
    }
}
