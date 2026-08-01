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

//! Database pruning and compaction for Moonshine light wallet.
//!
//! Light wallets should minimize retained state. This module handles:
//! - Pruning spent notes older than a retention window
//! - SQLite VACUUM to reclaim disk space

use crate::db::WalletDb;
use std::error::Error;

/// Default retention window: keep spent notes for 1000 blocks.
/// After this, spent notes are pruned for data minimization.
const DEFAULT_RETENTION_BLOCKS: u32 = 1000;

/// Prune spent notes and compact the database.
pub fn prune_wallet(db: &WalletDb) -> Result<PruneResult, Box<dyn Error>> {
    let (sync_height, _) = db.get_sync_state()?;

    if sync_height <= DEFAULT_RETENTION_BLOCKS {
        println!("Not enough blocks to prune (synced to height {sync_height})");
        return Ok(PruneResult { notes_pruned: 0 });
    }

    let cutoff = sync_height - DEFAULT_RETENTION_BLOCKS;
    let pruned = db.prune_spent_below(cutoff)?;

    if pruned > 0 {
        println!("Pruned {pruned} spent notes below height {cutoff}");
        db.vacuum()?;
        println!("Database vacuumed successfully");
    } else {
        println!("No spent notes to prune");
    }

    Ok(PruneResult {
        notes_pruned: pruned as u32,
    })
}

/// Result of a pruning operation.
#[derive(Debug)]
pub struct PruneResult {
    pub notes_pruned: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prune_wallet_empty() {
        let db = WalletDb::in_memory().unwrap();
        let result = prune_wallet(&db).unwrap();
        assert_eq!(result.notes_pruned, 0);
    }

    #[test]
    fn test_prune_wallet_with_spent() {
        let db = WalletDb::in_memory().unwrap();
        db.set_sync_height(5000).unwrap();

        db.insert_note(
            "tx1",
            0,
            100,
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
            "tx2",
            0,
            200,
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
        db.insert_note(
            "tx3",
            0,
            300,
            "DRK",
            &[3],
            4500,
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

        db.mark_note_spent(&[1]).unwrap();
        db.mark_note_spent(&[2]).unwrap();

        let result = prune_wallet(&db).unwrap();
        assert_eq!(result.notes_pruned, 2);

        // Unspent note at height 4500 should still exist
        assert_eq!(db.confirmed_balance("DRK").unwrap(), 300);
    }
}
