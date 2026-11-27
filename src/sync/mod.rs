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

//! Sync engine for Moonshine light wallet.
//!
//! Moonshine is a **light client**: it fetches compact Money/DAO/auth-token
//! records from `darkfi-lightwalletd` and keeps a local SQLCipher wallet. It
//! does **not** validate the full chain like `darkfid`, and it does **not**
//! pull full blocks over darkfid JSON-RPC the way `drk` does.
//!
//! Default path (padded trial decryption — same semantics as `drk` scan):
//! 1. `GetCompactOutputBodies` over a power-of-2 padded window
//! 2. Trial-decrypt Money notes into the local DB; store compact DAO calls
//!    and auth-token mint/freeze markers for the same window
//! 3. `GetNoteCommitments` — append **all** coins to the Money Merkle tree
//!    from height 0 (dummy ZERO leaf + genesis mints). Note trial-decrypt
//!    may start at the wallet birthday, but the tree must not: skipping
//!    pre-birthday leaves makes spend proofs use a root the contract never
//!    stored (Money `Custom(5)`).
//! 4. `GetNullifiers(scan_start..scan_end)` — mark spent notes
//!
//! Experimental `--unifomr` / `experimental_unifomr` uses sparse UnifOMR +
//! Batch PIR instead. Tip advances only after commitments + nullifiers for
//! the full range succeed (and, in UnifOMR mode, after sparse fetches for
//! every matching height succeed).
//!
//! Privacy mitigations:
//! - Power-of-2 bucket block-range padding (parity with mobile UniFFI)
//! - Jittered sleep between requests (anti-fingerprinting)
//! - Error redaction (strips IPs/URLs from error messages)
//! - TLS + cert pin required for non-localhost HTTPS
//! - Compact blocks in the local cache are encrypted (`NHC1`) and deleted
//!   as soon as trial decrypt applies them

use crate::block_cache::BlockCache;
use crate::client::LightwalletClient;
use crate::db::WalletDb;
use darkfi_sdk::crypto::{MerkleNode, MerkleTree};
use darkfi_sdk::pasta::pallas;

use futures::StreamExt;
use tokio::time::Duration;

mod engine;
mod omr;
#[cfg(test)]
mod tests;
mod trial;

pub use engine::SyncEngine;
pub use omr::*;
pub use trial::*;

/// Maximum blocks to request in a single range RPC.
/// Must stay ≤ lightwalletd `max_range_per_request` (10_000) **after**
/// power-of-2 privacy padding (padding can nearly double the window).
pub const MAX_BLOCKS_PER_REQUEST: u32 = 4096;

/// Server cap for one padded commitment, nullifier, or digest window.
pub(super) const MAX_RANGE_PER_REQUEST: u32 = 10_000;

/// Minimum padding bucket size (blocks) — matches mobile lightwallet_client.
pub(super) const MIN_BUCKET_SIZE: u32 = 1024;

/// Base sleep duration between sync iterations (seconds). CLI polls faster.
pub(super) const POLL_BASE_SECS: u64 = 1;

/// Inclusive LWD height range that must sit after the dummy ZERO leaf before
/// a birthday-clamped note scan. Height 0 holds genesis mint coins; the dummy
/// leaf is not block 0. `None` only when there is no pre-history to backfill.
#[allow(dead_code)] // covered by unit tests; Android FFI has the same helper
pub fn pre_birthday_commitment_range(birthday_height: u32) -> Option<(u32, u32)> {
    if birthday_height == 0 {
        None
    } else {
        Some((0, birthday_height.saturating_sub(1)))
    }
}

pub(super) fn genesis_money_tree() -> MerkleTree {
    // Match darkfid: dummy zero coin at position 0 (dummy inputs).
    let mut tree = MerkleTree::new(u32::MAX as usize);
    tree.append(MerkleNode::from(pallas::Base::from(0u64)));
    let _ = tree.mark();
    tree
}

/// Canonical checkpoint digest: blake3(height LE || tree_data || nullifier_index).
/// Must stay lockstep with blackhawk and darkfi-lightwalletd.
pub fn snapshot_integrity_hash(height: u32, tree_data: &[u8], nullifier_index: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&height.to_le_bytes());
    hasher.update(tree_data);
    hasher.update(nullifier_index);
    *hasher.finalize().as_bytes()
}

/// Shared lightwalletd preflight: checks proto major version (`get_light_info`),
/// TOFU directory attestation pin (when a wallet DB is supplied), and `chain_name`
/// network alignment before any write/spend/rebuild operation.
pub async fn preflight_server_opt(
    client: &mut LightwalletClient,
    db: Option<&WalletDb>,
    server_url: &str,
    network: &str,
) -> Result<crate::client::proto::LightInfo, Box<dyn std::error::Error>> {
    let info = client.get_light_info().await?;
    if let Some(db) = db {
        crate::wallet::check_directory_attest_pin(db, server_url, &info.directory_attest_pubkey)?;
    }
    ensure_chain_matches_network_name(&info.chain_name, network)?;
    Ok(info)
}

/// Shared lightwalletd preflight with wallet DB attestation pinning.
pub async fn preflight_server(
    client: &mut LightwalletClient,
    db: &WalletDb,
    server_url: &str,
    network: &str,
) -> Result<crate::client::proto::LightInfo, Box<dyn std::error::Error>> {
    preflight_server_opt(client, Some(db), server_url, network).await
}

/// Target height when chain tip drops below `last_synced`.
/// Clamped to `tip_height.saturating_sub(1)` (never above `tip_height`) so
/// `tip_height < birthday` can never loop indefinitely.
pub fn reorg_rewind_height(tip_height: u32) -> u32 {
    tip_height.saturating_sub(1)
}
