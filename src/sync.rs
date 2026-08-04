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
//! Sparse OMR sync with lightwalletd:
//! 1. OMR Round 1 (UnifOMR only) → matching heights
//! 2. `GetNoteCommitments(scan_start..scan_end)` — append all coins to Merkle tree
//! 3. `GetNullifiers(scan_start..scan_end)` — mark spent notes
//! 4. Round 2: Batch PIR for matching heights when UnifOMR is available;
//!    else `GetCompactBlocksAtHeights` / N× `GetBlock`
//! 5. Trial-decrypt only those blocks; insert notes + tx history
//!
//! Does **not** call `GetBlockRange` for the full scan window (except
//! `--force-trial`, which opts into full-range trial decrypt without OMR).
//!
//! Tip advances only after commitments + nullifiers for the full range
//! succeed **and** sparse block fetches for all matching heights succeed.
//!
//! Privacy mitigations:
//! - Power-of-2 bucket block-range padding (parity with mobile)
//! - Jittered sleep between requests (anti-fingerprinting)
//! - Error redaction (strips IPs/URLs from error messages)
//! - TLS + cert pin required for non-localhost HTTPS

use crate::block_cache::BlockCache;
use crate::client::LightwalletClient;
use crate::db::WalletDb;
use darkfi_sdk::crypto::MerkleTree;

use futures::StreamExt;
use tokio::time::Duration;

/// Maximum blocks to request in a single range RPC.
/// Must stay ≤ lightwalletd `max_range_per_request` (10_000) **after**
/// power-of-2 privacy padding (padding can nearly double the window).
const MAX_BLOCKS_PER_REQUEST: u32 = 4096;

/// Minimum padding bucket size (blocks) — matches mobile lightwallet_client.
const MIN_BUCKET_SIZE: u32 = 1024;

/// Base sleep duration between sync iterations (seconds). CLI polls faster.
const POLL_BASE_SECS: u64 = 1;

/// Sync engine state.
pub struct SyncEngine {
    pub db: WalletDb,
    pub server_url: String,
    pub secret_keys: Vec<Vec<u8>>,
    /// Hex SHA-256 of leaf cert DER (from config).
    pub tls_pin_sha256: Option<String>,
    /// OMR network byte: mainnet=0x00, else 0x01.
    pub network_byte: u8,
    /// S18: skip OMR and trial-decrypt the full scan window.
    pub force_trial: bool,
    /// Local compact-block cache (beside wallet DB). Optional for tests.
    pub block_cache: Option<BlockCache>,
    /// Route remote lightwalletd traffic through embedded Tor (config `use_tor`).
    pub use_tor: bool,
}

impl SyncEngine {
    /// Create a new sync engine.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: WalletDb,
        server_url: &str,
        secret_keys: Vec<Vec<u8>>,
        tls_pin_sha256: Option<String>,
        network_byte: u8,
        force_trial: bool,
        block_cache: Option<BlockCache>,
        use_tor: bool,
    ) -> Self {
        Self {
            db,
            server_url: server_url.to_string(),
            secret_keys,
            tls_pin_sha256,
            network_byte,
            force_trial,
            block_cache,
            use_tor,
        }
    }

    /// Run a single sparse OMR sync cycle (or force-trial full decrypt).
    pub async fn sync_once(&self) -> Result<SyncResult, Box<dyn std::error::Error>> {
        let mut client = LightwalletClient::new(&self.server_url, self.tls_pin_sha256.clone())
            .with_tor(self.use_tor);

        let info = client.get_light_info().await?;
        ensure_chain_matches_network(&info.chain_name, self.network_byte)?;

        let tip = client.get_chain_tip().await?;
        let tip_height = tip.height;

        let (last_synced, birthday) = self.db.get_sync_state()?;

        // Reorg / tip regression: invalidate notes + txs above fork point, then rewind.
        if tip_height < last_synced {
            let rewind_to = tip_height.saturating_sub(1).max(birthday.saturating_sub(1));
            tracing::warn!(
                "Chain tip {} is below last synced {} — rewinding sync height to {}",
                tip_height,
                last_synced,
                rewind_to
            );
            match self.db.invalidate_above_height(rewind_to) {
                Ok((notes, txs)) => {
                    if notes > 0 || txs > 0 {
                        tracing::warn!(
                            "Reorg recovery: invalidated {} notes, {} transactions above height {}",
                            notes,
                            txs,
                            rewind_to
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to invalidate above {}: {e} — falling back to full rescan",
                        rewind_to
                    );
                    if let Err(reset_err) = self.db.reset_for_rescan(rewind_to) {
                        tracing::error!(
                            "reset_for_rescan also failed: {reset_err} — setting sync height only"
                        );
                        self.db.set_sync_height(rewind_to)?;
                    }
                }
            }
            return Ok(SyncResult {
                blocks_scanned: 0,
                notes_found: 0,
                notes_spent: 0,
                tip_height,
            });
        }

        if last_synced >= tip_height {
            return Ok(SyncResult {
                blocks_scanned: 0,
                notes_found: 0,
                notes_spent: 0,
                tip_height,
            });
        }

        let scan_start = (last_synced + 1).max(birthday);
        let scan_end = tip_height.min(scan_start + MAX_BLOCKS_PER_REQUEST - 1);

        let (padded_start, padded_end) = pad_block_range(scan_start, scan_end, tip_height);

        jittered_sleep(POLL_BASE_SECS).await;

        // Matching heights for trial decrypt (sparse), or full window if force_trial.
        let matching_heights: Vec<u32> = if self.force_trial {
            tracing::warn!("--force-trial: skipping OMR; full-range trial decrypt");
            (scan_start..=scan_end).collect()
        } else {
            match self
                .try_omr_detect(&mut client, padded_start, padded_end)
                .await
            {
                Ok(heights) => {
                    let filtered: Vec<u32> = heights
                        .into_iter()
                        .filter(|h| *h >= scan_start && *h <= scan_end)
                        .collect();
                    tracing::debug!(
                        "OMR detection returned {} matching blocks in range [{}, {}]",
                        filtered.len(),
                        scan_start,
                        scan_end
                    );
                    filtered
                }
                Err(e) => {
                    let redacted = redact_sync_error(&e.to_string());
                    return Err(format!(
                        "OMR detection failed ({}); refusing silent trial-decrypt fallback \
                         (tip not advanced). Use --force-trial to opt in.",
                        redacted
                    )
                    .into());
                }
            }
        };

        // 1) Compact blocks for trial decrypt — run BEFORE Merkle tree construction
        //    so that discovered coins are in the DB when the tree is built (allowing
        //    inline marking of owned positions).
        let mut notes_found = 0u32;
        let mut heights_to_fetch: Vec<u32> = matching_heights.clone();

        if matching_heights.is_empty() && !self.force_trial {
            println!("Falling back to trial decrypt — funds will be visible shortly.");
            tracing::warn!(
                "OMR returned 0 matches in [{scan_start}, {scan_end}] — running supplemental trial decrypt"
            );
            heights_to_fetch = (scan_start..=scan_end).collect();
        } else if !matching_heights.is_empty() && !self.force_trial {
            let extra =
                compute_supplemental_heights(scan_start, scan_end, tip_height, &matching_heights);
            if !extra.is_empty() {
                tracing::debug!("OMR gap trial-decrypt: {} additional heights", extra.len());
                heights_to_fetch.extend(extra);
                heights_to_fetch.sort_unstable();
                heights_to_fetch.dedup();
            }
        }

        if !heights_to_fetch.is_empty() {
            // PIR only for pure OMR match set (privacy); supplements use sparse height RPC.
            let use_pir_only = heights_to_fetch == matching_heights && !matching_heights.is_empty();
            let blocks = if use_pir_only {
                self.fetch_matching_blocks(&mut client, padded_start, padded_end, &heights_to_fetch)
                    .await?
            } else {
                self.fetch_matching_blocks_sparse(&mut client, &heights_to_fetch)
                    .await?
            };
            let got: std::collections::HashSet<u32> = blocks.iter().map(|b| b.height).collect();
            for h in &heights_to_fetch {
                if !got.contains(h) {
                    // Supplemental gaps may miss empty heights; only hard-fail for OMR matches.
                    if matching_heights.contains(h) {
                        return Err(format!(
                            "Missing compact block at matching height {h}; tip not advanced"
                        )
                        .into());
                    }
                }
            }
            for block in &blocks {
                notes_found += self.trial_decrypt_block(block)?;
            }
        }

        // 2) Note commitments → Merkle tree (full scan range).
        //    Runs AFTER trial decrypt so owned coins are in the DB and can be
        //    marked in the tree during append.
        self.apply_note_commitments(&mut client, scan_start, scan_end)
            .await?;

        // 3) Nullifiers → mark spent (full scan range)
        let mut notes_spent = 0u32;
        {
            let mut nf_stream = client.get_nullifiers(scan_start, scan_end).await?;
            while let Some(nf_result) = nf_stream.next().await {
                let nf = nf_result?;
                for nullifier in nf.nullifiers {
                    let marked = self.db.mark_note_spent(&nullifier)?;
                    if marked > 0 {
                        notes_spent += marked as u32;
                    }
                }
            }
        }

        // Tip advance: commitments + nullifiers done; sparse fetches succeeded.
        self.db.set_sync_height(scan_end)?;
        if let Some(cache) = &self.block_cache {
            if let Err(e) = cache.prune_for_sync_height(scan_end) {
                tracing::warn!("block cache prune failed: {e}");
            }
        }

        Ok(SyncResult {
            blocks_scanned: scan_end - scan_start + 1,
            notes_found,
            notes_spent,
            tip_height,
        })
    }

    async fn apply_note_commitments(
        &self,
        client: &mut LightwalletClient,
        scan_start: u32,
        scan_end: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tree_bytes = self.db.get_meta("tree_state")?.unwrap_or_else(|| {
            // Match darkfid's genesis initialization: the on-chain Merkle tree
            // starts with a fake zero coin at position 0 (used for dummy inputs).
            // See darkfi/src/contract/money/src/entrypoint.rs line 195-196.
            let mut genesis_tree = MerkleTree::new(1);
            genesis_tree.append(darkfi_sdk::crypto::MerkleNode::from(
                darkfi_sdk::pasta::pallas::Base::from(0u64),
            ));
            let mut out = Vec::new();
            darkfi_serial::Encodable::encode(&genesis_tree, &mut out).unwrap_or(0);
            out
        });

        let mut tree: MerkleTree =
            darkfi_serial::Decodable::decode(&mut std::io::Cursor::new(&tree_bytes))
                .map_err(|e| format!("Failed to decode MerkleTree: {}", e))?;

        // Collect commitments of all owned unspent notes for marking.
        let owned_commitments: std::collections::HashSet<[u8; 32]> = self
            .db
            .list_owned_commitments()
            .unwrap_or_default()
            .iter()
            .filter_map(|c| {
                if c.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(c);
                    Some(arr)
                } else {
                    None
                }
            })
            .collect();

        let mut nc_stream = client.get_note_commitments(scan_start, scan_end).await?;
        let mut total_marked = 0u64;
        while let Some(nc_result) = nc_stream.next().await {
            let nc = nc_result?;
            for coin in nc.coins {
                if coin.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&coin);
                    let node: darkfi_sdk::crypto::MerkleNode =
                        darkfi_serial::Decodable::decode(&mut std::io::Cursor::new(&arr)).unwrap();
                    tree.append(node);
                    // Get position AFTER append (current_position returns the last appended)
                    let pos: u64 = tree.current_position().map(|p| p.into()).unwrap_or(0);
                    // Mark this leaf if it belongs to an owned coin
                    if owned_commitments.contains(&arr) {
                        tree.mark();
                        total_marked += 1;
                    }
                    self.db.update_leaf_position(&arr, pos as u32).ok();
                }
            }
        }

        if total_marked > 0 {
            eprintln!("[DEBUG] Marked {} owned positions in Merkle tree", total_marked);
        }

        let mut out = Vec::new();
        darkfi_serial::Encodable::encode(&tree, &mut out)
            .map_err(|e| format!("Failed to encode MerkleTree: {}", e))?;
        self.db.set_meta("tree_state", &out)?;
        Ok(())
    }

    /// Mark positions of all unspent owned coins in the Merkle tree so that
    /// `tree.witness(position, depth)` can produce authentication paths for spending.
    /// Note: primary marking now happens inline in `apply_note_commitments`.
    /// This method is called as a safety net for coins discovered in the current
    /// sync batch (which weren't in the DB yet when the tree was built).
    fn mark_owned_positions(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Reload tree and rebuild with marks for newly discovered coins.
        // We re-run apply_note_commitments conceptually, but since the tree is
        // already fully built we need to walk it. BridgeTree::mark() only marks
        // the *current* leaf, so for newly discovered coins we need to rebuild.
        // For efficiency, we just record that a rescan is needed on next sync.
        //
        // For now, we handle this by re-running the note commitment stream on
        // next sync which will pick up the new DB entries.
        tracing::info!("mark_owned_positions: new coins discovered, will be marked on next sync");
        Ok(())
    }

    /// Fetch compact blocks for OMR-matched heights **without revealing which
    /// heights matched**.
    ///
    /// Privacy contract: the server already learned the padded window
    /// `[window_start, window_end]` from the digest request, but must never
    /// learn the exact match set. We therefore use UnifOMR Round-2 batch PIR
    /// when available, and on any PIR failure fall back to streaming the
    /// **entire padded window** (`GetBlockRange`) — which leaks nothing beyond
    /// the window — rather than a sparse per-height fetch of the matches.
    async fn fetch_matching_blocks(
        &self,
        client: &mut LightwalletClient,
        window_start: u32,
        window_end: u32,
        matching_heights: &[u32],
    ) -> Result<Vec<crate::client::proto::CompactBlock>, Box<dyn std::error::Error>> {
        let caps = client.get_omr_capabilities().await?;
        if !self.force_trial && caps.enabled && caps.scheme.contains("unifomr") {
            match self
                .fetch_matching_blocks_pir(client, window_start, window_end, matching_heights)
                .await
            {
                Ok(blocks) => {
                    tracing::debug!(
                        "UnifOMR Round 2: retrieved {} compact blocks via batch PIR",
                        blocks.len()
                    );
                    return Ok(blocks);
                }
                Err(e) => {
                    tracing::warn!(
                        "UnifOMR Round 2 PIR failed ({}); falling back to full-window range fetch \
                         (privacy-preserving — does not reveal matched heights)",
                        redact_sync_error(&e.to_string())
                    );
                }
            }
        }

        // Privacy-preserving fallback: stream the whole padded window. The
        // server only sees the (already-known) window, not the match set.
        self.fetch_window_range(client, window_start, window_end)
            .await
    }

    /// Stream every compact block in `[window_start, window_end]` (the padded
    /// digest window). Reveals only the window — never the OMR match set.
    async fn fetch_window_range(
        &self,
        client: &mut LightwalletClient,
        window_start: u32,
        window_end: u32,
    ) -> Result<Vec<crate::client::proto::CompactBlock>, Box<dyn std::error::Error>> {
        use futures::StreamExt;
        let mut stream = client.get_block_range(window_start, window_end).await?;
        let mut blocks = Vec::new();
        while let Some(block) = stream.next().await {
            blocks.push(block?);
        }
        Ok(blocks)
    }

    async fn fetch_matching_blocks_sparse(
        &self,
        client: &mut LightwalletClient,
        matching_heights: &[u32],
    ) -> Result<Vec<crate::client::proto::CompactBlock>, Box<dyn std::error::Error>> {
        use prost::Message;

        let mut out = Vec::with_capacity(matching_heights.len());
        let mut misses = Vec::new();

        for &h in matching_heights {
            if let Some(cache) = &self.block_cache {
                if let Ok(Some(data)) = cache.get_block(h) {
                    match crate::client::proto::CompactBlock::decode(data.as_slice()) {
                        Ok(block) => {
                            out.push(block);
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!("cached compact block {h} decode failed: {e}");
                        }
                    }
                }
            }
            misses.push(h);
        }

        for chunk in misses.chunks(512) {
            jittered_sleep(1).await;
            let blocks = client.get_compact_blocks_at_heights(chunk).await?;
            if let Some(cache) = &self.block_cache {
                for block in &blocks {
                    let data = block.encode_to_vec();
                    if let Err(e) = cache.insert_block(block.height, &data) {
                        tracing::debug!("block cache insert {} failed: {e}", block.height);
                    }
                }
            }
            out.extend(blocks);
        }

        // Preserve height order for callers that walk chronologically.
        out.sort_by_key(|b| b.height);
        Ok(out)
    }

    /// UnifOMR Round 2: multi-hot BFV PIR over compact-block limbs in the padded window.
    async fn fetch_matching_blocks_pir(
        &self,
        client: &mut LightwalletClient,
        window_start: u32,
        window_end: u32,
        matching_heights: &[u32],
    ) -> Result<Vec<crate::client::proto::CompactBlock>, Box<dyn std::error::Error>> {
        let wallet_secret = self
            .secret_keys
            .first()
            .and_then(|s| s.get(..32))
            .ok_or("No wallet secret available for PIR")?;
        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(wallet_secret);

        let pir_seed =
            darkfi_lightwalletd::pir_server::derive_pir_seed(&secret_arr, self.network_byte)?;
        let pir = darkfi_lightwalletd::pir_server::BatchPirClient::from_seed(pir_seed);

        let window_size = (window_end - window_start + 1) as usize;
        let indices: Vec<usize> = matching_heights
            .iter()
            .map(|h| (*h - window_start) as usize)
            .collect();
        for &idx in &indices {
            if idx >= window_size {
                return Err(format!("PIR index {idx} outside window {window_size}").into());
            }
        }

        let queries = pir.generate_sealpir_queries(&indices, window_size)?;
        let mut limb_cols: Vec<Vec<u64>> = Vec::new();
        let mut needed_limbs: Option<usize> = None;

        for limb_index in 0..darkfi_lightwalletd::pir_server::MAX_PIR_LIMBS {
            let resp = client
                .fetch_pir_batch(queries.clone(), window_start, window_end, limb_index as u32)
                .await?;
            let slots = pir.decrypt_sealpir_stripes(&resp.payload_ciphertexts, window_size)?;
            let mut full = vec![0u64; window_size];
            for &idx in &indices {
                full[idx] = slots.get(idx).copied().unwrap_or(0);
            }
            limb_cols.push(full);
            if limb_index == 0 {
                let mut max_need = 0usize;
                for &idx in &indices {
                    if let Some(n) =
                        darkfi_lightwalletd::pir_server::pir_payload_limb_count(limb_cols[0][idx])
                    {
                        max_need = max_need.max(n);
                    }
                }
                if max_need == 0 {
                    return Err("PIR returned empty payloads for all matching heights".into());
                }
                needed_limbs = Some(max_need);
            }
            if let Some(n) = needed_limbs {
                if limb_cols.len() >= n {
                    limb_cols.truncate(n);
                    break;
                }
            }
        }

        let payloads = darkfi_lightwalletd::pir_server::assemble_payloads(&indices, &limb_cols);
        let mut blocks = Vec::with_capacity(payloads.len());
        for (payload, &height) in payloads.iter().zip(matching_heights.iter()) {
            if payload.is_empty() {
                return Err(format!("PIR returned empty payload for height {height}").into());
            }
            use prost::Message;
            let block = crate::client::proto::CompactBlock::decode(payload.as_slice())
                .map_err(|e| format!("PIR protobuf decode at {height}: {e}"))?;
            if block.height != height {
                return Err(format!(
                    "PIR height mismatch: expected {height}, got {}",
                    block.height
                )
                .into());
            }
            blocks.push(block);
        }
        if let Some(cache) = &self.block_cache {
            use prost::Message;
            for block in &blocks {
                let data = block.encode_to_vec();
                if let Err(e) = cache.insert_block(block.height, &data) {
                    tracing::debug!("block cache insert {} failed: {e}", block.height);
                }
            }
        }
        Ok(blocks)
    }

    fn trial_decrypt_block(
        &self,
        block: &crate::client::proto::CompactBlock,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let mut notes_found = 0u32;
        for tx in &block.txs {
            for (idx, output) in tx.outputs.iter().enumerate() {
                for secret_key in &self.secret_keys {
                    if let Some(note) = trial_decrypt_note(&output.encrypted_note, secret_key) {
                        let tx_hash_hex = hex::encode(&tx.tx_hash);
                        // S5: commitment is output.coin from the compact block
                        let commitment = if output.coin.len() == 32 {
                            Some(output.coin.as_slice())
                        } else {
                            None
                        };
                        // Nullifier = poseidon(secret, coin) — must match LWD nullifier stream.
                        let nullifier_bytes = {
                            use darkfi_money_contract::model::Coin;
                            use darkfi_sdk::crypto::pasta_prelude::PrimeField;
                            use darkfi_sdk::crypto::{poseidon_hash, SecretKey};
                            let mut sk_arr = [0u8; 32];
                            if secret_key.len() < 32 {
                                continue;
                            }
                            sk_arr.copy_from_slice(&secret_key[..32]);
                            let Ok(sk) = SecretKey::from_bytes(sk_arr) else {
                                continue;
                            };
                            let mut coin_arr = [0u8; 32];
                            if output.coin.len() != 32 {
                                continue;
                            }
                            coin_arr.copy_from_slice(&output.coin);
                            let Ok(coin) = Coin::from_bytes(coin_arr) else {
                                continue;
                            };
                            let nf = poseidon_hash([sk.inner(), coin.inner()]);
                            Some(nf.to_repr().to_vec())
                        };
                        self.db.insert_note(
                            &tx_hash_hex,
                            idx as u32,
                            note.value as i64,
                            &hex::encode(&note.token_id),
                            &note.serial,
                            block.height,
                            note.memo.as_deref(),
                            Some(&note.coin_blind),
                            Some(&note.value_blind),
                            Some(&note.token_blind),
                            Some(note.spend_hook),
                            Some(&note.user_data),
                            None,
                            commitment,
                            nullifier_bytes.as_deref(),
                            Some(secret_key.as_slice()),
                        )?;
                        self.db.insert_transaction(
                            &tx_hash_hex,
                            block.height,
                            "incoming",
                            note.value as i64,
                            &hex::encode(&note.token_id),
                            None,
                            note.memo.as_deref(),
                        )?;
                        notes_found += 1;
                        break;
                    }
                }
            }
        }
        Ok(notes_found)
    }

    /// Attempt UnifOMR detection via the server (scheme 0x05 only).
    async fn try_omr_detect(
        &self,
        client: &mut LightwalletClient,
        start: u32,
        end: u32,
    ) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
        let caps = client.get_omr_capabilities().await?;
        if !caps.enabled {
            return Err(format!(
                "server OMR disabled (scheme={}, fpr={})",
                caps.scheme, caps.false_positive_rate
            )
            .into());
        }
        tracing::debug!(
            "server OMR enabled: scheme={}, fpr={}, max_range={}",
            caps.scheme,
            caps.false_positive_rate,
            caps.max_range_per_request
        );

        if !caps.scheme.contains("unifomr") {
            return Err(
                format!("server does not advertise UnifOMR (scheme={})", caps.scheme).into(),
            );
        }

        let max_range = if caps.max_range_per_request == 0 {
            10_000
        } else {
            caps.max_range_per_request
        };
        if end.saturating_sub(start).saturating_add(1) > max_range {
            return Err(format!(
                "UnifOMR window [{start}, {end}] exceeds server max_range_per_request ({max_range})"
            )
            .into());
        }

        let net = self.network_byte;
        const MAX_DETECTION_KEYS: usize = 16;
        // Server cap on the sum of detection_keys lengths per request
        // (lightwalletd MAX_DETECTION_KEYS_TOTAL_BYTES = 160 MiB).  One Param2
        // det-key is ~120 MiB (D=4096, n=1024, 3×40-bit moduli), so
        // multi-address wallets are effectively limited to 1 key per RPC;
        // additional keys must be chunked into separate requests and the
        // per-chunk results unioned.
        const SERVER_DETECTION_KEYS_TOTAL_BUDGET: usize = 160 * 1024 * 1024;

        let mut clients = Vec::new();
        let mut detection_keys = Vec::new();
        for sk in self.secret_keys.iter().take(MAX_DETECTION_KEYS) {
            let Some(bytes) = sk.get(..32) else {
                continue;
            };
            let mut secret_arr = [0u8; 32];
            secret_arr.copy_from_slice(bytes);
            let client_crypto =
                darkfi_lightwalletd::unifomr::UnifOmrClient::from_wallet(&secret_arr, net)?;
            // Detection keys are ~120 MiB (Param2) and take seconds of BFV
            // encryption to build, but any previously built key stays valid (randomness is
            // per-build; the decryption key is derived from the wallet
            // secret). Cache built keys in the local block cache DB, keyed by
            // a domain-separated hash of the wallet secret + network + param
            // version, so repeat `moonshine sync` runs skip the rebuild.
            let cache_id = {
                let mut h = blake3::Hasher::new_derive_key("moonshine detkey-cache v1 param2");
                h.update(&secret_arr);
                h.update(&[net]);
                h.finalize().as_bytes().to_vec()
            };
            let cached = self
                .block_cache
                .as_ref()
                .and_then(|c| c.get_detection_key(&cache_id).ok().flatten());
            let det_key = match cached {
                Some(k) => k,
                None => {
                    let k = client_crypto.build_detection_key(net)?;
                    if let Some(c) = self.block_cache.as_ref() {
                        if let Err(e) = c.put_detection_key(&cache_id, &k) {
                            tracing::debug!("detection key cache write failed: {e}");
                        }
                    }
                    k
                }
            };
            detection_keys.push(det_key);
            clients.push(client_crypto);
        }
        if detection_keys.is_empty() {
            return Err("No wallet secret available for OMR digest decode".into());
        }

        let total_keys = clients.len();
        let mut heights: Vec<u32> = Vec::new();
        let mut chunk_keys: Vec<Vec<u8>> = Vec::new();
        let mut chunk_clients = Vec::new();
        let mut chunk_bytes = 0usize;
        let mut pairs = clients.into_iter().zip(detection_keys).peekable();
        while let Some((client_crypto, det_key)) = pairs.next() {
            chunk_bytes += det_key.len();
            chunk_keys.push(det_key);
            chunk_clients.push(client_crypto);
            let flush = match pairs.peek() {
                Some((_, next_key)) => {
                    chunk_bytes + next_key.len() > SERVER_DETECTION_KEYS_TOTAL_BUDGET
                }
                None => true,
            };
            if flush {
                let digest = client
                    .get_unif_omr_digest(std::mem::take(&mut chunk_keys), start, end)
                    .await?;
                let chunk_heights =
                    decrypt_unif_omr_heights(&chunk_clients, &digest.encrypted_digest, start, end)?;
                heights.extend(chunk_heights);
                chunk_clients.clear();
                chunk_bytes = 0;
            }
        }
        heights.sort_unstable();
        heights.dedup();
        tracing::debug!(
            "UnifOMR Round 1: {} matching heights in [{start}, {end}] ({} detection keys)",
            heights.len(),
            total_keys
        );
        Ok(heights)
    }
}

/// Decrypt UnifOMR Round-1 digest(s) and collect matching heights.
///
/// Single-key responses are unframed. Multi-key responses are length-prefixed
/// frames (one digest per detection key), matching lightwalletd.
fn decrypt_unif_omr_heights(
    clients: &[darkfi_lightwalletd::unifomr::UnifOmrClient],
    encrypted_digest: &[u8],
    start: u32,
    end: u32,
) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;

    if clients.is_empty() {
        return Err("No UnifOMR clients for digest decrypt".into());
    }
    if clients.len() == 1 {
        let slots = clients[0]
            .decrypt_digest_slots(encrypted_digest)
            .map_err(|e| format!("UnifOMR digest decrypt failed: {e}"))?;
        return Ok(
            darkfi_lightwalletd::unifomr::UnifOmrClient::range_check_matches(&slots, start, end),
        );
    }

    let mut heights = BTreeSet::new();
    let mut off = 0usize;
    for (i, client_crypto) in clients.iter().enumerate() {
        if off + 4 > encrypted_digest.len() {
            return Err(format!("truncated multi-key UnifOMR digest at key[{i}]").into());
        }
        let len = u32::from_le_bytes(encrypted_digest[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if off + len > encrypted_digest.len() {
            return Err(format!("truncated UnifOMR digest frame for key[{i}]").into());
        }
        let frame = &encrypted_digest[off..off + len];
        off += len;
        let slots = client_crypto
            .decrypt_digest_slots(frame)
            .map_err(|e| format!("UnifOMR digest decrypt failed for key[{i}]: {e}"))?;
        for h in
            darkfi_lightwalletd::unifomr::UnifOmrClient::range_check_matches(&slots, start, end)
        {
            heights.insert(h);
        }
    }
    Ok(heights.into_iter().collect())
}

/// Pad a block range to a power-of-2 bucket boundary (P6 — mobile parity).
///
/// Rounds the range to the next power-of-2 bucket size (minimum 1024 blocks)
/// and aligns the start to a bucket boundary. End is clamped to `tip`.
///
/// ```text
/// pad_block_range(42000, 42500, tip) → (~41984, min(43007, tip))
/// pad_block_range(100, 100, tip)     → (0, min(1023, tip))
/// ```
pub fn pad_block_range(start: u32, end: u32, tip: u32) -> (u32, u32) {
    let range_size = end.saturating_sub(start).saturating_add(1);
    let bucket = range_size.max(MIN_BUCKET_SIZE).next_power_of_two();

    let aligned_start = (start / bucket) * bucket;
    let mut aligned_end = aligned_start.saturating_add(bucket).saturating_sub(1);

    while aligned_end < end {
        aligned_end = aligned_end.saturating_add(bucket);
    }

    (aligned_start, aligned_end.min(tip))
}

/// Jittered sleep for anti-fingerprinting.
///
/// Sleeps for a base duration ± small jitter using thread_rng.
pub async fn jittered_sleep(base_secs: u64) {
    use rand::Rng;
    let jitter = rand::rng().random_range(0..=(base_secs / 4).max(1));
    let total = base_secs + jitter;
    tokio::time::sleep(Duration::from_secs(total)).await;
}

/// Redact sensitive information from error messages.
pub fn redact_sync_error(msg: &str) -> String {
    let mut result = msg.to_string();

    let ip_re = regex_lite::Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?").unwrap();
    result = ip_re.replace_all(&result, "[redacted-addr]").to_string();

    let url_re = regex_lite::Regex::new(r"(https?|tcp(\+tls)?|grpc)://[^\s]+").unwrap();
    result = url_re.replace_all(&result, "[redacted-url]").to_string();

    result
}

/// Result of a sync cycle.
#[derive(Debug)]
pub struct SyncResult {
    pub blocks_scanned: u32,
    pub notes_found: u32,
    pub notes_spent: u32,
    pub tip_height: u32,
}

/// A decrypted note from trial decryption (blinds extracted; commitment from caller).
pub struct DecryptedNote {
    pub value: u64,
    pub token_id: Vec<u8>,
    pub serial: Vec<u8>,
    pub memo: Option<String>,
    pub coin_blind: Vec<u8>,
    pub value_blind: Vec<u8>,
    pub token_blind: Vec<u8>,
    /// First byte of spend_hook field (matches `insert_note` `Option<u8>`).
    pub spend_hook: u8,
    pub user_data: Vec<u8>,
}

/// Trial decrypt a compact block note using the wallet's secret key.
///
/// Returns blinds / fields from the MoneyNote plaintext. Callers should use
/// `CompactOutput.coin` as the note commitment when inserting (S5).
pub fn trial_decrypt_note(encrypted_note: &[u8], wallet_key: &[u8]) -> Option<DecryptedNote> {
    use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit};
    use darkfi_sdk::crypto::diffie_hellman;
    use darkfi_sdk::crypto::note::AeadEncryptedNote;
    use darkfi_sdk::crypto::SecretKey;
    use darkfi_serial::Decodable;
    use std::io::Cursor;

    const AEAD_TAG_SIZE: usize = 16;

    if encrypted_note.len() < 48 || wallet_key.len() < 32 {
        return None;
    }

    let mut cursor = Cursor::new(encrypted_note);
    let enc_note = match AeadEncryptedNote::decode(&mut cursor) {
        Ok(note) => note,
        Err(_) => return None,
    };

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&wallet_key[..32]);
    let secret = match SecretKey::from_bytes(key_bytes) {
        Ok(sk) => sk,
        Err(_) => return None,
    };

    // Perform raw DH + ChaCha20Poly1305 decryption to get the raw plaintext bytes,
    // instead of using enc_note.decrypt::<D>() which routes through Decodable and
    // would misinterpret the MoneyNote bytes as a length-prefixed Vec<u8>.
    let shared_secret = match diffie_hellman::sapling_ka_agree(&secret, &enc_note.ephem_public) {
        Ok(ss) => ss,
        Err(_) => return None,
    };
    let key = diffie_hellman::kdf_sapling(&shared_secret, &enc_note.ephem_public);

    let ct_len = enc_note.ciphertext.len();
    if ct_len < AEAD_TAG_SIZE {
        return None;
    }
    let mut plaintext = enc_note.ciphertext.clone();

    if ChaCha20Poly1305::new(key.as_ref().into())
        .decrypt_in_place([0u8; 12][..].into(), &[], &mut plaintext)
        .is_err()
    {
        return None;
    }

    // After AEAD decrypt-in-place, plaintext is truncated to ct_len - AEAD_TAG_SIZE
    let plaintext = &plaintext[..];

    // Upstream MoneyNote layout (darkfi-serial encoded fixed fields):
    //   value:       0..8     (u64 LE)
    //   token_id:    8..40    (32 bytes)
    //   spend_hook:  40..72   (32 bytes, FuncId)
    //   user_data:   72..104  (32 bytes, pallas::Base)
    //   coin_blind:  104..136 (32 bytes, BaseBlind)
    //   value_blind: 136..168 (32 bytes, ScalarBlind)
    //   token_blind: 168..200 (32 bytes, BaseBlind)
    //   memo:        200+     (VarInt length + bytes)
    if plaintext.len() < 200 {
        return None;
    }

    let mut value_bytes = [0u8; 8];
    value_bytes.copy_from_slice(&plaintext[0..8]);
    let value = u64::from_le_bytes(value_bytes);

    let token_id = plaintext[8..40].to_vec();

    // spend_hook: first 8 LE bytes of the 32-byte FuncId field
    let mut hook_le = [0u8; 8];
    hook_le.copy_from_slice(&plaintext[40..48]);
    let spend_hook = u64::from_le_bytes(hook_le) as u8;

    let user_data = plaintext[72..104].to_vec();
    let coin_blind = plaintext[104..136].to_vec();
    let value_blind = plaintext[136..168].to_vec();
    let token_blind = plaintext[168..200].to_vec();

    // There is no 'serial' field in upstream MoneyNote; use coin_blind as a substitute
    // for any downstream code that references it (e.g., nullifier derivation).
    let serial = coin_blind.clone();

    let memo = if plaintext.len() > 200 {
        // memo is darkfi-serial encoded: VarInt length + raw bytes.
        // Read the VarInt length prefix, then extract the memo bytes.
        let memo_region = &plaintext[200..];
        // Try to read it as raw bytes (skip VarInt prefix for user display)
        // The memo in PoW rewards contains serialize(&signing_secret_key) which is binary.
        // For user transfers, it may be UTF-8 text.
        // Read VarInt length
        let (memo_len, prefix_size) = if memo_region.is_empty() {
            (0usize, 0usize)
        } else if memo_region[0] < 0xfd {
            (memo_region[0] as usize, 1)
        } else if memo_region[0] == 0xfd && memo_region.len() >= 3 {
            (u16::from_le_bytes([memo_region[1], memo_region[2]]) as usize, 3)
        } else {
            (0, 0)
        };
        if memo_len > 0 && prefix_size + memo_len <= memo_region.len() {
            let raw = &memo_region[prefix_size..prefix_size + memo_len];
            String::from_utf8(raw.to_vec())
                .ok()
                .filter(|s| !s.trim().is_empty())
        } else {
            None
        }
    } else {
        None
    };

    Some(DecryptedNote {
        value,
        token_id,
        serial,
        memo,
        coin_blind,
        value_blind,
        token_blind,
        spend_hook,
        user_data,
    })
}

/// Ensure lightwalletd chain_name matches the wallet network byte.
pub fn ensure_chain_matches_network(
    chain_name: &str,
    network_byte: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let c = chain_name.to_ascii_lowercase();
    let ok = if network_byte == 0x00 {
        c.contains("mainnet") && !c.contains("testnet") && !c.contains("localnet")
    } else {
        c.contains("testnet") || c.contains("localnet")
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "lightwalletd chain_name '{chain_name}' does not match wallet network byte 0x{network_byte:02x}. \
             Use the same darkfi-lightwalletd network for all clients."
        )
        .into())
    }
}

pub fn compute_supplemental_heights(
    scan_start: u32,
    scan_end: u32,
    tip_height: u32,
    matching_heights: &[u32],
) -> Vec<u32> {
    let mut extra: Vec<u32> = Vec::new();
    if matching_heights.is_empty() {
        return extra;
    }
    let first = matching_heights[0];
    if first.saturating_sub(scan_start) > 10 {
        extra.extend(scan_start..first);
    }
    for w in matching_heights.windows(2) {
        let gap_start = w[0] + 1;
        let gap_end = w[1].saturating_sub(1);
        if gap_end >= gap_start && (gap_end - gap_start + 1) > 10 {
            extra.extend(gap_start..=gap_end);
        }
    }
    let last = *matching_heights.last().unwrap();
    if tip_height.min(scan_end).saturating_sub(last) > 10 {
        extra.extend((last + 1)..=scan_end);
    }
    extra
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_matches_testnet() {
        ensure_chain_matches_network("darkfi-testnet", 0x01).unwrap();
        ensure_chain_matches_network("darkfi-localnet", 0x01).unwrap();
        assert!(ensure_chain_matches_network("darkfi-mainnet", 0x01).is_err());
    }

    #[test]
    fn test_chain_matches_mainnet() {
        ensure_chain_matches_network("darkfi-mainnet", 0x00).unwrap();
        assert!(ensure_chain_matches_network("darkfi-testnet", 0x00).is_err());
    }

    #[test]
    fn test_pad_block_range_min_bucket() {
        let (ps, pe) = pad_block_range(100, 100, 50000);
        assert_eq!(ps, 0);
        assert_eq!(pe, 1023);
    }

    #[test]
    fn test_pad_block_range_small() {
        let (ps, pe) = pad_block_range(42000, 42100, 50000);
        assert_eq!(pe - ps + 1, 1024);
        assert_eq!(ps % 1024, 0);
        assert!(ps <= 42000);
        assert!(pe >= 42100);
    }

    #[test]
    fn test_pad_block_range_medium() {
        let (ps, pe) = pad_block_range(10000, 12000, 50000);
        assert_eq!(ps % 2048, 0);
        assert!(ps <= 10000);
        assert!(pe >= 12000);
    }

    #[test]
    fn test_pad_block_range_near_tip() {
        let (ps, pe) = pad_block_range(49900, 50000, 50000);
        assert_eq!(pe, 50000);
        assert!(ps <= 49900);
    }

    #[test]
    fn test_pad_block_range_deterministic() {
        let a = pad_block_range(42000, 42500, 100_000);
        let b = pad_block_range(42000, 42500, 100_000);
        assert_eq!(a, b);
    }

    #[test]
    fn test_redact_sync_error_ips() {
        let msg = "connection failed to 192.168.1.100:9067";
        let redacted = redact_sync_error(msg);
        assert!(!redacted.contains("192.168.1.100"));
        assert!(redacted.contains("[redacted-addr]"));
    }

    #[test]
    fn test_redact_sync_error_urls() {
        let msg = "failed: http://lw.darkfi.xyz:9067/rpc timeout";
        let redacted = redact_sync_error(msg);
        assert!(!redacted.contains("lw.darkfi.xyz"));
        assert!(redacted.contains("[redacted-url]"));
    }

    #[test]
    fn test_redact_preserves_safe() {
        let msg = "OMR not available on server";
        assert_eq!(redact_sync_error(msg), msg);
    }

    #[test]
    fn test_trial_decrypt_too_short() {
        assert!(trial_decrypt_note(&[0u8; 10], &[0u8; 32]).is_none());
    }

    #[test]
    fn test_inter_match_gap_11_blocks() {
        // Gap of exactly 11 empty blocks between matches (100 -> 112)
        // 112 - 100 - 1 = 11 blocks (101..=111)
        let matches = vec![100, 112];
        let extra = compute_supplemental_heights(0, 200, 200, &matches);

        assert!(extra.contains(&101));
        assert!(extra.contains(&111));
        assert_eq!(extra.iter().filter(|&&h| h > 100 && h < 112).count(), 11);
    }
}
