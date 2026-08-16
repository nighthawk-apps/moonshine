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

//! Local compact block cache for trial decryption fallback.
//!
//! When OMR is unavailable or fails, the wallet falls back to downloading
//! all compact blocks and performing trial decryption. This cache stores
//! serialized CompactBlock protobufs locally so they don't need to be
//! re-downloaded on app restart or resync.
//!
//! Blocks are pruned after successful sync past a retention window to
//! prevent unbounded storage growth on mobile devices.

use rusqlite::{params, Connection, Result as SqlResult};
use std::path::Path;

/// Default retention: keep cached blocks for this many blocks past sync tip.
/// Older blocks are pruned to save disk space.
pub const DEFAULT_BLOCK_RETENTION: u32 = 2000;

/// SQLite-backed compact block cache.
pub struct BlockCache {
    conn: Connection,
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
        Ok(Self { conn })
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
        Ok(Self { conn })
    }

    /// Insert a compact block (serialized protobuf).
    pub fn insert_block(&self, height: u32, data: &[u8]) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO compact_blocks (height, data) VALUES (?1, ?2)",
            params![height, data],
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
            Ok(Some(data))
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

    /// Prune blocks below a given height.
    pub fn prune_below(&self, height: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "DELETE FROM compact_blocks WHERE height < ?1",
            params![height],
        )?;
        Ok(rows)
    }

    /// Prune blocks older than retention window relative to sync height.
    pub fn prune_for_sync_height(&self, sync_height: u32) -> SqlResult<usize> {
        if sync_height <= DEFAULT_BLOCK_RETENTION {
            return Ok(0);
        }
        self.prune_below(sync_height - DEFAULT_BLOCK_RETENTION)
    }

    /// Check if a contiguous range [start, end] is fully cached.
    #[cfg(test)]
    pub fn is_range_cached(&self, start: u32, end: u32) -> SqlResult<bool> {
        let expected = (end - start + 1) as u32;
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
    fn test_size_bytes() {
        let cache = BlockCache::in_memory().unwrap();
        cache.insert_block(1, &[0u8; 100]).unwrap();
        cache.insert_block(2, &[0u8; 200]).unwrap();
        assert_eq!(cache.size_bytes().unwrap(), 300);
    }
}
