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
    pub(super) conn: Connection,
    /// Key for wrapping address secrets at rest (S14).
    pub(super) wrap_key: [u8; 32],
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

mod queries;
mod schema;
#[cfg(test)]
mod tests;

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

pub(super) fn kind_from_direction(direction: &str) -> &str {
    match direction {
        "incoming" => "receive",
        "outgoing" => "send",
        other => other,
    }
}
