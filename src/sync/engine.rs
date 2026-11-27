use super::*;

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
    /// When true, never supplemental-trial-decrypt empty OMR / inter-match gaps.
    pub strict_omr: bool,
    /// Local compact-block cache (beside wallet DB). Optional for tests.
    pub block_cache: Option<BlockCache>,
    /// Route remote lightwalletd traffic through embedded Tor (config `use_tor`).
    pub use_tor: bool,
    /// Configured network name (`mainnet` / `testnet` / `localnet`) when known.
    pub network_name: Option<String>,
}

impl Drop for SyncEngine {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for sk in &mut self.secret_keys {
            sk.zeroize();
        }
    }
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
        strict_omr: bool,
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
            strict_omr,
            block_cache,
            use_tor,
            network_name: None,
        }
    }

    /// Attach full config network name so `localnet` vs `testnet` is strictly checked.
    pub fn with_network(mut self, network: &str) -> Self {
        self.network_name = Some(network.to_string());
        self
    }

    /// Run a single sparse OMR sync cycle (or force-trial full decrypt).
    pub async fn sync_once(&self) -> Result<SyncResult, Box<dyn std::error::Error>> {
        let mut client = LightwalletClient::new(&self.server_url, self.tls_pin_sha256.clone())
            .with_tor(self.use_tor);

        let info = client.get_light_info().await?;
        let tip_stale = tip_poll_is_stale(info.tip_fetched_unix);
        crate::wallet::check_directory_attest_pin(
            &self.db,
            &self.server_url,
            &info.directory_attest_pubkey,
        )?;
        if let Some(ref net) = self.network_name {
            ensure_chain_matches_network_name(&info.chain_name, net)?;
        } else {
            if let Some(ref net) = self.network_name {
                ensure_chain_matches_network_name(&info.chain_name, net)?;
            } else {
                ensure_chain_matches_network(&info.chain_name, self.network_byte)?;
            }
        }

        let tip = client.get_chain_tip().await?;
        let tip_height = tip.height;

        let (last_synced, birthday) = self.db.get_sync_state()?;

        // Reorg / tip regression: invalidate notes + txs above fork point, then rewind.
        // Never clamp above `tip_height` (avoids an infinite loop when `tip_height < birthday`).
        if tip_height < last_synced {
            let rewind_to = reorg_rewind_height(tip_height);
            tracing::warn!(
                "Chain tip {} is below last synced {} — rewinding sync height to {}",
                tip_height,
                last_synced,
                rewind_to
            );
            self.perform_reorg_rewind(rewind_to)?;
            return Ok(SyncResult {
                blocks_scanned: 0,
                notes_found: 0,
                notes_spent: 0,
                tip_height,
                tip_stale,
                rewound: true,
            });
        }

        // Same-height and longer-chain reorg detection: verify hash continuity at `last_synced`.
        if last_synced > 0 {
            if let Some(ancestor) = self
                .detect_hash_reorg_ancestor(&mut client, last_synced, &tip)
                .await?
            {
                tracing::warn!(
                    "Chain reorg detected at synced height {} — rewinding to common ancestor {}",
                    last_synced,
                    ancestor
                );
                self.perform_reorg_rewind(ancestor)?;
                return Ok(SyncResult {
                    blocks_scanned: 0,
                    notes_found: 0,
                    notes_spent: 0,
                    tip_height,
                    tip_stale,
                    rewound: true,
                });
            }
        }

        // Fresh/birthday/rescanned wallet with no owned notes and no tree yet:
        // install the greatest snapshot <= birthday, or the latest snapshot when
        // the wallet has no birthday. NOT_FOUND and a tip-only server fall through
        // to commitment replay.
        //
        // The snapshot only seeds the Money Merkle tree. Do **not** advance the
        // note cursor to the tip — trial decrypt (the default) still has to walk
        // birthday..=tip or a tip snapshot would hide every prior payment until
        // `--force-trial`.
        let no_owned_notes = self.db.list_owned_commitments()?.is_empty();
        if !self.db.merkle_from_genesis()
            && self.tree_applied_recorded().is_none()
            && no_owned_notes
            && tip_height > 0
        {
            let _ = self.try_install_checkpoint(&mut client, birthday).await?;
        }
        let (last_synced, birthday) = self.db.get_sync_state()?;
        // `--force-trial` keeps its own cursor. A strict sync records heights
        // as scanned without decrypting clue-less payments, and a later
        // `--force-trial` must walk those heights again. The Money tree cursor
        // stays where it is so the replay does not append the same leaves twice.
        let trial_cursor = self.trial_cursor();
        let force_backfill =
            self.force_trial && trial_cursor.unwrap_or(birthday.saturating_sub(1)) < tip_height;

        if last_synced >= tip_height && !force_backfill {
            if !self.db.merkle_from_genesis()
                || self.db.get_meta("tree_state")?.is_none()
                || self.tree_applied_height() < last_synced
            {
                eprintln!(
                    "Money Merkle tree is missing pre-birthday / height-0 leaves; \
                     rebuilding from genesis so spend roots match the chain..."
                );
                self.rebuild_money_tree_from_genesis().await?;
            }
            if last_synced == tip_height && tip.hash.len() == 32 {
                let _ = self.db.record_synced_block_hash(tip_height, &tip.hash);
            }
            return Ok(SyncResult {
                blocks_scanned: 0,
                notes_found: 0,
                notes_spent: 0,
                tip_height,
                tip_stale,
                rewound: false,
            });
        }

        // last_synced == 0 means never synced (or rescan-to-genesis), not
        // "already applied height 0", unless a snapshot already installed the tree.
        let scan_start = note_scan_start(
            self.force_trial,
            trial_cursor,
            last_synced,
            birthday,
            self.db.merkle_from_genesis(),
            self.tree_applied_height(),
        );
        if scan_start > tip_height {
            self.db.set_sync_height(tip_height)?;
            if tip.hash.len() == 32 {
                let _ = self.db.record_synced_block_hash(tip_height, &tip.hash);
            }
            return Ok(SyncResult {
                blocks_scanned: 0,
                notes_found: 0,
                notes_spent: 0,
                tip_height,
                tip_stale,
                rewound: false,
            });
        }
        // May be clamped down below if the server truncates the OMR digest at its
        // DoS cap; the dropped tail is then re-scanned on the next cycle.
        let mut scan_end = tip_height.min(scan_start + MAX_BLOCKS_PER_REQUEST - 1);

        let (padded_start, padded_end) = pad_block_range(scan_start, scan_end, tip_height);

        jittered_sleep(POLL_BASE_SECS).await;

        // Matching heights for sparse UnifOMR only. Default sync never dials
        // UnifOMR (server builds ship without `fhe-omr`); go straight to
        // padded GetCompactOutputBodies trial decrypt.
        let matching_heights: Vec<u32> = if !self.strict_omr || self.force_trial {
            if self.force_trial {
                tracing::warn!("--force-trial: skipping OMR; full-range trial decrypt");
            }
            (scan_start..=scan_end).collect()
        } else {
            match self
                .try_omr_detect(&mut client, padded_start, padded_end)
                .await
            {
                Ok((heights, covered_end)) => {
                    // Server truncated at its DoS cap: clamp the scan cursor to the
                    // covered end so the dropped tail heights are re-requested next
                    // cycle instead of being skipped. Never regress below scan_start
                    // (guarantees forward progress and avoids a u32 underflow).
                    if let Some(c) = covered_end {
                        if c < scan_end {
                            scan_end = c.max(scan_start);
                        }
                    }
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
                        "OMR detection failed ({}); strict UnifOMR refuses trial-decrypt \
                         fallback (tip not advanced).",
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
        let mut window_anchors: Vec<(u32, [u8; 32])> = Vec::new();
        let collect_anchors = |blocks: &[crate::client::proto::CompactBlock],
                               out: &mut Vec<(u32, [u8; 32])>| {
            for b in blocks {
                if b.hash.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b.hash);
                    out.push((b.height, arr));
                }
            }
        };
        // Default and `--force-trial` trial-decrypt the full padded window so
        // clue-less payments (`drk`, other lightwalletds) are received.
        let use_full_window_trial = self.force_trial || !self.strict_omr;
        let heights_to_fetch: Vec<u32> = if use_full_window_trial {
            (scan_start..=scan_end).collect()
        } else {
            matching_heights.clone()
        };
        if matching_heights.is_empty() && self.strict_omr && !self.force_trial {
            tracing::info!(
                "OMR returned 0 matches in [{scan_start}, {scan_end}] — \
                 skipping trial decrypt (--strict-omr)"
            );
        }

        if use_full_window_trial {
            tracing::info!(
                "Trial-decrypting compact blocks [{scan_start}, {scan_end}] \
                 via lightwalletd GetCompactOutputBodies"
            );
            let blocks = self
                .fetch_padded_window_blocks(&mut client, scan_start, scan_end, tip_height)
                .await?;
            let in_window: Vec<_> = blocks
                .iter()
                .filter(|block| height_in_scan_window(block.height, scan_start, scan_end))
                .cloned()
                .collect();
            collect_anchors(&in_window, &mut window_anchors);
            notes_found += self.trial_decrypt_blocks(&in_window)?;
            self.store_contract_records(&mut client, padded_start, padded_end)
                .await?;
        } else if !heights_to_fetch.is_empty() {
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
            let mut in_window: Vec<_> = blocks
                .into_iter()
                .filter(|block| height_in_scan_window(block.height, scan_start, scan_end))
                .collect();
            let extra: Vec<_> = self
                .fetch_outputs_by_func(&mut client, padded_start, padded_end, MONEY_FUNC_TOKEN_MINT)
                .await?
                .into_iter()
                .filter(|block| height_in_scan_window(block.height, scan_start, scan_end))
                .collect();
            let extra = dedup_extra_blocks_against_window(&in_window, extra);
            in_window.extend(extra);
            collect_anchors(&in_window, &mut window_anchors);
            self.store_contract_records(&mut client, padded_start, padded_end)
                .await?;
            notes_found += self.trial_decrypt_blocks(&in_window)?;
        } else {
            let extra: Vec<_> = self
                .fetch_outputs_by_func(&mut client, padded_start, padded_end, MONEY_FUNC_TOKEN_MINT)
                .await?
                .into_iter()
                .filter(|block| height_in_scan_window(block.height, scan_start, scan_end))
                .collect();
            collect_anchors(&extra, &mut window_anchors);
            notes_found += self.trial_decrypt_blocks(&extra)?;
            self.store_contract_records(&mut client, padded_start, padded_end)
                .await?;
        }

        // 2) Note commitments → Merkle tree.
        //    Trial decrypt has already inserted owned coins so they can be marked.
        //    Pre-birthday heights are backfilled first; never append birthday..tip
        //    onto a dummy-only tree (that is Money Custom(5) on spend).
        // A snapshot installed above skips 0..=snapshot. The suffix up to the
        // birthday is the only pre-scan replay.
        // Wallets synced before `tree_applied_height` existed already hold a
        // tree through `last_synced`. Stamp that cursor so a backfill does not
        // append those leaves a second time.
        // If notes were newly discovered in a range where the Merkle tree was
        // already stamped ahead (e.g. from a checkpoint snapshot or an earlier
        // clue-less scan), the snapshot tree never marked our owned leaf positions.
        // Reset the tree to genesis so ensure_genesis_merkle + apply_note_commitments
        // rebuild and mark every owned coin at its exact leaf position.
        if notes_found > 0
            && self
                .tree_applied_recorded()
                .is_some_and(|applied| applied >= scan_start)
        {
            tracing::info!(
                "Rebuilding Merkle tree from genesis: {} note(s) discovered at or below tree_applied_height ({:?})",
                notes_found,
                self.tree_applied_recorded()
            );
            let mut out = Vec::new();
            darkfi_serial::Encodable::encode(&genesis_money_tree(), &mut out)
                .map_err(|e| format!("encode genesis tree: {e}"))?;
            self.db.save_money_tree_state(&out, 0, false)?;
            self.db.delete_meta("tree_applied_height")?;
        }

        if self.db.merkle_from_genesis()
            && self.db.get_meta("tree_state")?.is_some()
            && self.tree_applied_recorded().is_none()
            && last_synced > 0
        {
            self.set_tree_applied_height(last_synced)?;
        }
        self.ensure_genesis_merkle(&mut client, scan_start, tip_height)
            .await?;
        let merkle_complete = scan_start == 0 || self.db.merkle_from_genesis();
        self.apply_note_commitments(
            &mut client,
            scan_start,
            scan_end,
            tip_height,
            merkle_complete,
        )
        .await?;

        // 3) Nullifiers → mark spent (full scan range, padded on the wire)
        let notes_spent = self
            .apply_nullifiers_range(&mut client, scan_start, scan_end, tip_height)
            .await?;
        match self
            .db
            .release_stale_reservations(tip_height, crate::db::WalletDb::RESERVATION_GRACE_BLOCKS)
        {
            Ok(n) if n > 0 => eprintln!(
                "  released {n} unconfirmed reservation(s); those txs did not land within {} blocks",
                crate::db::WalletDb::RESERVATION_GRACE_BLOCKS
            ),
            Ok(_) => {}
            Err(e) => eprintln!("  warning: release stale reservations failed: {e}"),
        }

        // Tip advance: commitments + nullifiers done; sparse fetches succeeded.
        // A force-trial backfill must not rewind a cursor that is already at the tip.
        if scan_end > last_synced {
            self.db.set_sync_height(scan_end)?;
            // Record hashes solely from the tip RPC or the already-fetched padded window
            // so we never leak the exact sync cursor via unpadded GetBlock(height).
            for (h, bh) in window_anchors.iter().rev().take(16).rev() {
                let _ = self.db.record_synced_block_hash(*h, bh);
            }
            if scan_end == tip_height {
                if tip_height > 0 && tip.prev_hash.len() == 32 {
                    let _ = self
                        .db
                        .record_synced_block_hash(tip_height - 1, &tip.prev_hash);
                }
                if tip.hash.len() == 32 {
                    let _ = self.db.record_synced_block_hash(tip_height, &tip.hash);
                }
            }
        }
        if self.force_trial {
            self.set_trial_cursor(scan_end)?;
        }
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
            tip_stale,
            rewound: false,
        })
    }

    pub(super) fn perform_reorg_rewind(
        &self,
        rewind_to: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(cache) = &self.block_cache {
            if let Err(e) = cache.delete_above(rewind_to) {
                tracing::warn!("block cache reorg prune failed: {e}");
            }
        }
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
        Ok(())
    }

    /// Verify block hash continuity at `last_synced`. Returns `Some(common_ancestor)`
    /// when a same-height or longer-chain reorg is detected.
    pub(super) async fn detect_hash_reorg_ancestor(
        &self,
        client: &mut LightwalletClient,
        last_synced: u32,
        tip: &crate::client::proto::ChainTip,
    ) -> Result<Option<u32>, Box<dyn std::error::Error>> {
        let anchors = self.db.get_synced_block_anchors()?;
        let stored_at_last = anchors
            .iter()
            .rev()
            .find(|(h, _)| *h == last_synced)
            .map(|(_, bh)| *bh)
            .or_else(|| {
                self.db
                    .get_last_synced_hash()
                    .ok()
                    .flatten()
                    .filter(|(h, _)| *h == last_synced)
                    .map(|(_, bh)| bh)
            });
        let Some(expected_hash) = stored_at_last else {
            return Ok(None);
        };

        let chain_matches = if tip.height == last_synced && tip.hash.len() == 32 {
            tip.hash.as_slice() == expected_hash.as_slice()
        } else if tip.height == last_synced.saturating_add(1) && tip.prev_hash.len() == 32 {
            tip.prev_hash.as_slice() == expected_hash.as_slice()
        } else {
            // Check continuity using a padded window fetch rather than an unpadded
            // GetBlock(last_synced), which would reveal the wallet's exact cursor.
            match self
                .fetch_padded_window_blocks(client, last_synced, last_synced, tip.height)
                .await
            {
                Ok(blocks) => match blocks.into_iter().find(|b| b.height == last_synced) {
                    Some(blk) if blk.hash.len() == 32 => {
                        blk.hash.as_slice() == expected_hash.as_slice()
                    }
                    _ => true,
                },
                Err(e) if grpc_code_is(e.as_ref(), tonic::Code::Unimplemented) => {
                    tracing::debug!("GetCompactOutputBodies unimplemented; skipping hash check");
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        };

        if chain_matches {
            return Ok(None);
        }

        // Walk stored anchors descending to find the highest common ancestor.
        for &(anchor_h, anchor_hash) in anchors.iter().rev() {
            if anchor_h >= last_synced {
                continue;
            }
            match client.get_block(anchor_h).await {
                Ok(blk)
                    if blk.hash.len() == 32 && blk.hash.as_slice() == anchor_hash.as_slice() =>
                {
                    return Ok(Some(anchor_h));
                }
                Ok(_) => continue,
                Err(e) if grpc_code_is(e.as_ref(), tonic::Code::NotFound) => continue,
                Err(e) => return Err(e),
            }
        }
        // If no stored anchor matches, the fork is deeper than all recorded anchors;
        // trigger a clean rewind to 0 so orphaned notes/spends are cleared completely.
        Ok(Some(0))
    }

    pub(super) async fn apply_note_commitments(
        &self,
        client: &mut LightwalletClient,
        scan_start: u32,
        scan_end: u32,
        tip: u32,
        merkle_from_genesis: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owned = self.owned_commitment_set()?;
        let stored_tree = self.db.get_meta("tree_state")?;
        // A crash after a mid-window flush left the tree ahead of the note
        // cursor. Resume at the next unapplied height instead of appending
        // the same coins again (only when tree_state is actually present).
        let start = if stored_tree.is_some() {
            match self.tree_applied_recorded() {
                Some(applied) if applied >= scan_start => applied.saturating_add(1),
                _ => scan_start,
            }
        } else {
            scan_start
        };
        if start > scan_end {
            if merkle_from_genesis && !self.db.merkle_from_genesis() {
                self.db.set_merkle_from_genesis(true)?;
            }
            return Ok(());
        }
        let tree_bytes = stored_tree.unwrap_or_else(|| {
            let mut out = Vec::new();
            darkfi_serial::Encodable::encode(&genesis_money_tree(), &mut out).unwrap_or(0);
            out
        });

        let mut tree: MerkleTree =
            darkfi_serial::Decodable::decode(&mut std::io::Cursor::new(&tree_bytes))
                .map_err(|e| format!("Failed to decode MerkleTree: {}", e))?;

        let total_marked = self
            .append_note_commitments_range(client, &mut tree, &owned, start, scan_end, tip)
            .await?;

        if total_marked > 0 {
            eprintln!(
                "[DEBUG] Marked {} owned positions in Merkle tree",
                total_marked
            );
        }

        self.save_money_tree(&tree, scan_end, merkle_from_genesis)?;
        Ok(())
    }

    pub(super) fn owned_commitment_set(
        &self,
    ) -> Result<std::collections::HashSet<[u8; 32]>, Box<dyn std::error::Error>> {
        Ok(self
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
            .collect())
    }

    /// Stream padded `GetNoteCommitments` and append coins inside `[start, end]`.
    ///
    /// Heights outside the scan window are dropped so a power-of-two bucket
    /// does not append leaves the previous cycle already applied.
    pub(super) async fn append_note_commitments_range(
        &self,
        client: &mut LightwalletClient,
        tree: &mut MerkleTree,
        owned_commitments: &std::collections::HashSet<[u8; 32]>,
        start: u32,
        end: u32,
        tip: u32,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        if start > end {
            return Ok(0);
        }
        let (pad_start, pad_end) = require_padded_range(start, end, tip)?;
        let mut nc_stream = client.get_note_commitments(pad_start, pad_end).await?;
        let mut total_marked = 0u64;
        let mut heights_in_batch = 0u32;
        let mut prev_height: Option<u32> = None;
        while let Some(nc_result) = nc_stream.next().await {
            let nc = nc_result?;
            if !height_in_scan_window(nc.height, start, end) {
                continue;
            }
            if prev_height.is_some() && prev_height != Some(nc.height) {
                heights_in_batch += 1;
                if heights_in_batch >= 256 {
                    if let Some(done) = prev_height {
                        self.save_money_tree(tree, done, self.db.merkle_from_genesis())?;
                    }
                    heights_in_batch = 0;
                }
            }
            prev_height = Some(nc.height);
            for coin in nc.coins {
                if coin.len() != 32 {
                    continue;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&coin);
                let Some(node) = MerkleNode::from_bytes(arr) else {
                    continue;
                };
                tree.append(node);
                if owned_commitments.contains(&arr) {
                    if let Some(pos) = tree.mark() {
                        let pos_u64: u64 = pos.into();
                        self.db.update_leaf_position(&arr, pos_u64 as u32).ok();
                        total_marked += 1;
                    }
                }
            }
        }
        Ok(total_marked)
    }

    /// If the Money tree is not known to include height 0, replay 0..=scan_start-1
    /// onto a fresh dummy leaf. Never append a birthday window onto a dummy-only tree.
    pub(super) async fn ensure_genesis_merkle(
        &self,
        client: &mut LightwalletClient,
        scan_start: u32,
        tip: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if scan_start == 0 {
            return Ok(());
        }
        let has_tree_state = self.db.get_meta("tree_state")?.is_some();
        let applied = self.tree_applied_height();
        if has_tree_state
            && self.db.merkle_from_genesis()
            && applied.saturating_add(1) >= scan_start
        {
            return Ok(());
        }
        let end = scan_start - 1;
        let start_from = if has_tree_state && self.db.merkle_from_genesis() {
            applied.saturating_add(1)
        } else {
            0
        };
        if start_from > end {
            return Ok(());
        }
        eprintln!(
            "Backfilling Money Merkle tree for heights {start_from}..={end} \
             (note scan starts at {scan_start}; pre-history must still be in the tree)..."
        );
        let owned = self.owned_commitment_set()?;
        let mut tree = if has_tree_state && self.db.merkle_from_genesis() {
            self.load_money_tree()?
        } else {
            genesis_money_tree()
        };
        let mut start = start_from;
        let mut marked = 0u64;
        while start <= end {
            let chunk_end = start.saturating_add(MAX_BLOCKS_PER_REQUEST - 1).min(end);
            marked += self
                .append_note_commitments_range(client, &mut tree, &owned, start, chunk_end, tip)
                .await?;
            eprintln!("  merkle backfill {chunk_end}/{end}");
            start = chunk_end.saturating_add(1);
            if start == 0 {
                break;
            }
        }
        if marked > 0 {
            eprintln!("[DEBUG] Marked {marked} owned positions during genesis backfill");
        }
        self.save_money_tree(&tree, end, true)?;
        Ok(())
    }

    pub(super) fn trial_cursor(&self) -> Option<u32> {
        match self.db.get_meta("trial_synced_height") {
            Ok(Some(bytes)) if bytes.len() == 4 => Some(u32::from_le_bytes(
                bytes.as_slice().try_into().unwrap_or([0; 4]),
            )),
            _ => None,
        }
    }

    pub(super) fn set_trial_cursor(&self, height: u32) -> Result<(), Box<dyn std::error::Error>> {
        self.db
            .set_meta("trial_synced_height", &height.to_le_bytes())
            .map_err(|e| format!("set trial_synced_height: {e}").into())
    }

    pub(super) fn tree_applied_recorded(&self) -> Option<u32> {
        match self.db.get_meta("tree_applied_height") {
            Ok(Some(bytes)) if bytes.len() == 4 => Some(u32::from_le_bytes(
                bytes.as_slice().try_into().unwrap_or([0; 4]),
            )),
            _ => None,
        }
    }

    pub(super) fn tree_applied_height(&self) -> u32 {
        self.tree_applied_recorded().unwrap_or(0)
    }

    pub(super) fn save_money_tree(
        &self,
        tree: &MerkleTree,
        applied_height: u32,
        merkle_from_genesis: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        darkfi_serial::Encodable::encode(tree, &mut out).map_err(
            |e| -> Box<dyn std::error::Error> {
                format!("Failed to encode MerkleTree: {e}").into()
            },
        )?;
        self.db
            .save_money_tree_state(&out, applied_height, merkle_from_genesis)?;
        Ok(())
    }

    pub(super) fn set_tree_applied_height(
        &self,
        height: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.db
            .set_meta("tree_applied_height", &height.to_le_bytes())
            .map_err(|e| format!("set tree_applied_height: {e}").into())
    }

    pub(super) fn load_money_tree(&self) -> Result<MerkleTree, Box<dyn std::error::Error>> {
        let bytes = self
            .db
            .get_meta("tree_state")?
            .ok_or("money tree missing after checkpoint")?;
        darkfi_serial::Decodable::decode(&mut std::io::Cursor::new(bytes))
            .map_err(|e| format!("decode money tree: {e}").into())
    }

    /// Install a server Money-tree snapshot.
    ///
    /// `birthday > 0` requests that height and accepts only a snapshot `<=` it.
    /// `birthday == 0` requests the latest snapshot. `Ok(None)` means replay
    /// commitments (NOT_FOUND, a tip-only server, or a snapshot the client will
    /// not install). The tree is written only after the hash and decode succeed.
    pub(super) async fn try_install_checkpoint(
        &self,
        client: &mut LightwalletClient,
        birthday: u32,
    ) -> Result<Option<u32>, Box<dyn std::error::Error>> {
        let preferred = preferred_checkpoint_height(birthday);
        let chunks = match client.get_checkpoint_snapshot(preferred).await {
            Ok(chunks) => chunks,
            Err(e) if checkpoint_status_falls_back(e.as_ref()) => {
                tracing::warn!(
                    "checkpoint unavailable ({}); replaying commitments",
                    redact_sync_error(&e.to_string())
                );
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let Some(first) = chunks.first() else {
            tracing::warn!("empty checkpoint snapshot; replaying commitments");
            return Ok(None);
        };
        let height = first.height;
        if chunks.iter().any(|chunk| chunk.height != height) {
            tracing::warn!("checkpoint chunks disagree on height; replaying commitments");
            return Ok(None);
        }
        if !checkpoint_snapshot_accepted(height, birthday) {
            tracing::warn!(
                "checkpoint height {height} is above birthday {birthday}; replaying commitments"
            );
            return Ok(None);
        }
        let mut tree_data = Vec::new();
        let mut total_bytes = first.nullifier_index.len();
        for chunk in &chunks {
            total_bytes = total_bytes.saturating_add(chunk.tree_data.len());
            if total_bytes > crate::client::MAX_CHECKPOINT_SNAPSHOT_BYTES {
                tracing::warn!(
                    "checkpoint snapshot at {height} exceeds max byte cap ({}); replaying commitments",
                    crate::client::MAX_CHECKPOINT_SNAPSHOT_BYTES
                );
                return Ok(None);
            }
            tree_data.extend_from_slice(&chunk.tree_data);
        }
        let digest = snapshot_integrity_hash(height, &tree_data, &first.nullifier_index);
        if digest.as_slice() != first.snapshot_hash.as_slice() {
            tracing::warn!("checkpoint integrity check failed at {height}; replaying commitments");
            return Ok(None);
        }
        let tree: MerkleTree =
            match darkfi_serial::Decodable::decode(&mut std::io::Cursor::new(&tree_data)) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(
                        "checkpoint tree decode failed at {height} ({e}); replaying commitments"
                    );
                    return Ok(None);
                }
            };
        let Some(snap_root) = tree.root(0) else {
            tracing::warn!("checkpoint tree at {height} has no root; replaying commitments");
            return Ok(None);
        };
        // Authenticate the snapshot root against GetTreeState(height) when the server
        // can serve that height (e.g. tip or checkpoint-capable server). Historical
        // heights return FAILED_PRECONDITION/NOT_FOUND on tip-only servers; in that
        // case also cross-check block_hash against GetBlock(height) if available.
        match client.get_tree_state(height).await {
            Ok(ts) => {
                if first.block_hash.len() == 32
                    && ts.block_hash.len() == 32
                    && first.block_hash != ts.block_hash
                {
                    tracing::warn!(
                        "checkpoint block_hash mismatch vs GetTreeState at {height}; replaying commitments"
                    );
                    return Ok(None);
                }
                match darkfi_serial::Decodable::decode(&mut std::io::Cursor::new(&ts.tree_data)) {
                    Ok(expected_tree) => {
                        let expected_tree: MerkleTree = expected_tree;
                        if expected_tree.root(0) != Some(snap_root) {
                            tracing::warn!(
                                "checkpoint root mismatch vs GetTreeState at {height}; replaying commitments"
                            );
                            return Ok(None);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "GetTreeState decode failed while authenticating checkpoint at {height} ({e}); replaying commitments"
                        );
                        return Ok(None);
                    }
                }
            }
            Err(e) if checkpoint_status_falls_back(e.as_ref()) => {
                if first.block_hash.len() == 32 {
                    if let Ok(blk) = client.get_block(height).await {
                        if blk.hash.len() == 32 && blk.hash != first.block_hash {
                            tracing::warn!(
                                "checkpoint block_hash mismatch vs GetBlock({height}); replaying commitments"
                            );
                            return Ok(None);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "GetTreeState check failed for checkpoint at {height} ({}); replaying commitments",
                    redact_sync_error(&e.to_string())
                );
                return Ok(None);
            }
        }
        self.save_money_tree(&tree, height, true)?;
        eprintln!(
            "Installed Money tree snapshot at height {height} (birthday {birthday}); \
             commitments at or below the snapshot are not replayed"
        );
        Ok(Some(height))
    }

    /// Rewrite unspent note commitments from compact-block `output.coin`.
    ///
    /// Local `CoinAttributes::to_coin()` can diverge from the on-chain coin
    /// (truncated spend_hook, overwritten commitments). Spends and Merkle
    /// marks require the exact leaf bytes in `GetNoteCommitments`.
    pub(super) async fn restore_commitments_from_compact(
        &self,
        client: &mut LightwalletClient,
    ) -> Result<(u32, u32), Box<dyn std::error::Error>> {
        let locs = self.db.list_unspent_note_locs()?;
        let n = locs.len() as u32;
        if locs.is_empty() {
            return Ok((0, 0));
        }
        let min_h = locs.iter().map(|l| l.2).min().unwrap_or(0);
        let max_h = locs.iter().map(|l| l.2).max().unwrap_or(0);
        // Pad each <= MAX_BLOCKS_PER_REQUEST chunk so the server does not learn
        // exact note heights and wide historical gaps still fit within server limits.
        let tip = client.get_chain_tip().await?.height.max(max_h);
        let mut by_h: std::collections::HashMap<u32, crate::client::proto::CompactBlock> =
            std::collections::HashMap::new();
        let mut chunk_start = min_h.min(tip);
        let end_h = max_h.min(tip);
        while chunk_start <= end_h {
            let chunk_end = chunk_start
                .saturating_add(MAX_BLOCKS_PER_REQUEST - 1)
                .min(end_h);
            let (pad_start, pad_end) = require_padded_range(chunk_start, chunk_end, tip)?;
            eprintln!(
                "  fetching compact blocks {pad_start}..={pad_end} to restore coin commitments..."
            );
            let blocks = self.fetch_window_range(client, pad_start, pad_end).await?;
            for b in blocks {
                by_h.entry(b.height).or_insert(b);
            }
            chunk_start = chunk_end.saturating_add(1);
            if chunk_start == 0 {
                break;
            }
        }
        let mut updated = 0u32;
        let mut missing_block = 0u32;
        let mut missing_tx = 0u32;
        let mut decrypted = 0u32;
        let mut any_decrypt = 0u32;
        // First pass: try every compact output in the window (output_index in
        // the DB can lag the decrypting output).
        for block in by_h.values() {
            for tx in &block.txs {
                for output in &tx.outputs {
                    if output.encrypted_note.len() < 48 {
                        continue;
                    }
                    for sk in &self.secret_keys {
                        if trial_decrypt_note(&output.encrypted_note, sk).is_some() {
                            any_decrypt += 1;
                            break;
                        }
                    }
                }
            }
        }
        if any_decrypt == 0 {
            let sample = by_h.values().find_map(|b| {
                b.txs.iter().find_map(|t| {
                    t.outputs
                        .iter()
                        .find(|o| o.encrypted_note.len() >= 48)
                        .map(|o| o.encrypted_note.len())
                })
            });
            eprintln!(
                "  no compact outputs in {min_h}..={max_h} decrypted (sample enc_len={sample:?}, keys={})",
                self.secret_keys.len()
            );
        } else {
            eprintln!("  compact outputs decryptable in window: {any_decrypt}");
        }
        for (tx_hash, idx, height) in &locs {
            let Some(block) = by_h.get(height) else {
                missing_block += 1;
                continue;
            };
            let tx = block
                .txs
                .iter()
                .find(|t| hex::encode(&t.tx_hash) == *tx_hash);
            let Some(tx) = tx else {
                missing_tx += 1;
                continue;
            };
            let Some(output) = tx.outputs.get(*idx as usize) else {
                missing_tx += 1;
                continue;
            };
            if output.coin.len() != 32 {
                continue;
            }
            let mut refreshed = false;
            for sk in &self.secret_keys {
                if let Some(note) = trial_decrypt_note(&output.encrypted_note, sk) {
                    let derived = derived_coin_from_note(&note, sk);
                    let matches_chain = derived.as_deref() == Some(output.coin.as_slice());
                    if !matches_chain {
                        if decrypted == 0 && !refreshed {
                            eprintln!(
                                "  decrypt coin mismatch at {}:{} derived={} chain={} (skipping overwrite)",
                                tx_hash,
                                idx,
                                derived
                                    .as_ref()
                                    .map(hex::encode)
                                    .unwrap_or_else(|| "-".into()),
                                hex::encode(&output.coin)
                            );
                        }
                        continue;
                    }
                    decrypted += 1;
                    let Ok(value_i64) = i64::try_from(note.value) else {
                        tracing::error!(
                            "Skipping note {}:{} with value {} exceeding i64::MAX",
                            tx_hash,
                            idx,
                            note.value
                        );
                        continue;
                    };
                    self.db.update_note_spend_fields(
                        tx_hash,
                        *idx,
                        value_i64,
                        &hex::encode(&note.token_id),
                        &note.coin_blind,
                        &note.value_blind,
                        &note.token_blind,
                        note.spend_hook,
                        &note.spend_hook_bytes,
                        &note.user_data,
                        &output.coin,
                        sk,
                    )?;
                    updated += 1;
                    refreshed = true;
                    break;
                }
            }
            if !refreshed {
                if updated < 3 {
                    eprintln!(
                        "  trial_decrypt failed {}:{} enc_len={} reason={} keys={} \
                         (keeping stored commitment — do not overwrite from compact coin)",
                        tx_hash,
                        idx,
                        output.encrypted_note.len(),
                        trial_decrypt_fail_reason(
                            &output.encrypted_note,
                            self.secret_keys
                                .first()
                                .map(|s| s.as_slice())
                                .unwrap_or(&[])
                        ),
                        self.secret_keys.len()
                    );
                }
                // Legacy compact AEAD often fails (enc_len=300). Writing
                // `output.coin` here desyncs blinds from the leaf and makes
                // later spends prove a coin the wallet cannot open.
            } else {
                updated += 1;
            }
        }
        if missing_block > 0 || missing_tx > 0 {
            eprintln!(
                "  restore gaps: missing_block={missing_block} missing_tx_or_output={missing_tx}"
            );
        }
        eprintln!(
            "  re-decrypted MoneyNote fields matching on-chain coin for {decrypted}/{n} notes"
        );
        Ok((n, updated))
    }

    /// Rebuild the Money Merkle tree from height 0 through the LWD tip.
    ///
    /// Birthday-skipped wallets only append post-birthday commitments, so spend
    /// proofs use a root that does not match the chain (`-32110` simulate fail).
    /// This walks `GetNoteCommitments` in height order, matching LWD's tip tree
    /// (dummy ZERO leaf, then every coin).
    pub async fn rebuild_money_tree_from_genesis(
        &self,
    ) -> Result<(u64, u32, u32), Box<dyn std::error::Error>> {
        let mut client = LightwalletClient::new(&self.server_url, self.tls_pin_sha256.clone())
            .with_tor(self.use_tor);

        let info = client.get_light_info().await?;
        crate::wallet::check_directory_attest_pin(
            &self.db,
            &self.server_url,
            &info.directory_attest_pubkey,
        )?;
        if let Some(ref net) = self.network_name {
            ensure_chain_matches_network_name(&info.chain_name, net)?;
        } else {
            ensure_chain_matches_network(&info.chain_name, self.network_byte)?;
        }

        let tip = client.get_chain_tip().await?.height;
        match self.restore_commitments_from_compact(&mut client).await {
            Ok((n, u)) => {
                eprintln!("  restored on-chain coin commitments: {u}/{n} unspent notes");
            }
            Err(e) => {
                eprintln!(
                    "  warning: could not restore commitments from compact blocks: {}",
                    redact_sync_error(&e.to_string())
                );
            }
        }
        let owned_list = self
            .db
            .list_owned_commitments()
            .map_err(|e| format!("list_owned_commitments: {e}"))?;
        eprintln!(
            "  owned note commitments: {} (example {})",
            owned_list.len(),
            owned_list
                .first()
                .map(hex::encode)
                .unwrap_or_else(|| "<none>".into())
        );
        let owned_commitments: std::collections::HashSet<[u8; 32]> = owned_list
            .iter()
            .filter_map(|c| {
                if c.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(c);
                    Some(arr)
                } else {
                    eprintln!("  skip owned commitment with len {} (want 32)", c.len());
                    None
                }
            })
            .collect();

        // Server checkpoints authenticate the tree *root* but do not contain
        // this wallet's marked leaf positions. `BridgeTree::mark()` only marks
        // the most recently appended leaf, so spend witnesses require a genesis
        // replay (dummy ZERO leaf, then every coin, mark on owned). Skipping
        // that replay after a tip checkpoint leaves `leaf_position` unset and
        // `make_transfer_call` fails with "Missing inputs in transfer call".
        let mut tree = genesis_money_tree();
        let mut start = 0u32;

        let mut appended = 0u64;
        let mut marked = 0u32;
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        const CHUNK: u32 = 4096;
        while start <= tip {
            let end = start.saturating_add(CHUNK - 1).min(tip);
            let (pad_start, pad_end) = require_padded_range(start, end, tip)?;
            let mut stream = client.get_note_commitments(pad_start, pad_end).await?;
            let mut by_h: std::collections::BTreeMap<u32, Vec<Vec<u8>>> =
                std::collections::BTreeMap::new();
            while let Some(nc_result) = stream.next().await {
                let nc = nc_result?;
                if !height_in_scan_window(nc.height, start, end) {
                    continue;
                }
                by_h.entry(nc.height).or_default().extend(nc.coins);
            }
            for (_h, coins) in by_h {
                for coin in coins {
                    if coin.len() != 32 {
                        continue;
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&coin);
                    let Some(node) = MerkleNode::from_bytes(arr) else {
                        continue;
                    };
                    tree.append(node);
                    appended += 1;
                    seen.insert(arr);
                    if owned_commitments.contains(&arr) {
                        let pos = tree
                            .mark()
                            .ok_or_else(|| "merkle mark failed for owned coin".to_string())?;
                        let pos_u64: u64 = pos.into();
                        self.db.update_leaf_position(&arr, pos_u64 as u32)?;
                        marked += 1;
                    }
                }
            }
            eprintln!("  merkle rebuild {end}/{tip} (appended {appended}, marked {marked})");
            start = end.saturating_add(1);
            if start == 0 {
                break;
            }
        }

        let hits = owned_commitments
            .iter()
            .filter(|c| seen.contains(*c))
            .count();
        eprintln!(
            "  owned coins found in chain stream: {hits}/{}",
            owned_commitments.len()
        );
        if hits == 0 {
            if let Some(c) = owned_commitments.iter().next() {
                eprintln!("  wallet coin example: {}", hex::encode(c));
            }
            if let Some(ex) = seen.iter().next() {
                eprintln!("  chain coin example:  {}", hex::encode(ex));
            }
        }

        match client.get_tree_state(tip).await {
            Ok(st) => {
                let server_tree: MerkleTree =
                    darkfi_serial::Decodable::decode(&mut std::io::Cursor::new(st.tree_data))
                        .map_err(|e| format!("Failed to decode LWD GetTreeState: {e}"))?;
                let local_root = tree.root(0);
                let server_root = server_tree.root(0);
                eprintln!(
                    "  merkle roots tip={tip} local={} lwd={} darkfid_hint=compare-last_coins_root",
                    local_root
                        .map(|r| hex::encode(r.to_bytes()))
                        .unwrap_or_else(|| "-".into()),
                    server_root
                        .map(|r| hex::encode(r.to_bytes()))
                        .unwrap_or_else(|| "-".into()),
                );
                if local_root != server_root {
                    return Err(format!(
                        "rebuilt Merkle root does not match LWD GetTreeState at tip {tip}"
                    )
                    .into());
                }
                // Match `drk`: checkpoint the tip so rewind/witness depth > 0 stay valid.
                let _ = tree.checkpoint(tip as usize);
            }
            Err(e) => {
                // Tip can advance during the rebuild; retry against current tip.
                match client.get_chain_tip().await {
                    Ok(now) if now.height == tip => {
                        eprintln!(
                            "  warning: could not verify against GetTreeState: {}",
                            redact_sync_error(&e.to_string())
                        );
                    }
                    Ok(now) => {
                        eprintln!(
                            "  warning: tip moved {tip} → {} during rebuild; skip GetTreeState check ({})",
                            now.height,
                            redact_sync_error(&e.to_string())
                        );
                    }
                    Err(_) => {
                        eprintln!(
                            "  warning: could not verify against GetTreeState: {}",
                            redact_sync_error(&e.to_string())
                        );
                    }
                }
            }
        }

        self.save_money_tree(&tree, tip, true)?;

        let now = client.get_chain_tip().await?.height;
        if now > tip {
            eprintln!(
                "  catching up Merkle {}..={now} (blocks mined during rebuild)",
                tip + 1
            );
            self.apply_note_commitments(&mut client, tip + 1, now, now, true)
                .await?;
        }
        let final_tip = now.max(tip);
        match self.db.recompute_owned_nullifiers() {
            Ok(n) => eprintln!("  recomputed nullifiers for {n} unspent notes"),
            Err(e) => eprintln!("  warning: recompute nullifiers failed: {e}"),
        }
        match self
            .apply_nullifiers_range(&mut client, 0, final_tip, final_tip)
            .await
        {
            Ok(spent) => {
                if spent > 0 {
                    eprintln!("  marked {spent} notes spent from chain nullifiers");
                }
            }
            Err(e) => eprintln!(
                "  warning: nullifier rescan failed: {}",
                redact_sync_error(&e.to_string())
            ),
        }
        Ok((appended, marked, final_tip))
    }

    /// Mark positions of all unspent owned coins in the Merkle tree so that
    /// `tree.witness(position, depth)` can produce authentication paths for spending.
    /// Note: primary marking now happens inline in `apply_note_commitments`.
    /// This method is called as a safety net for coins discovered in the current
    /// sync batch (which weren't in the DB yet when the tree was built).
    #[allow(dead_code)]
    pub(super) fn mark_owned_positions(&self) -> Result<(), Box<dyn std::error::Error>> {
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

    /// Mark wallet notes spent when their nullifiers appear in `[start, end]`.
    ///
    /// Recomputes `poseidon(secret, coin)` first so rows inserted before that
    /// column was populated still match the LWD stream. Chunks stay inside a
    /// 4096-block window so padding cannot exceed the server range cap.
    pub(super) async fn apply_nullifiers_range(
        &self,
        client: &mut LightwalletClient,
        start: u32,
        end: u32,
        tip: u32,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let _ = self.db.recompute_owned_nullifiers()?;
        let mut notes_spent = 0u32;
        let mut s = start;
        while s <= end {
            let e = s.saturating_add(MAX_BLOCKS_PER_REQUEST - 1).min(end);
            let (pad_start, pad_end) = require_padded_range(s, e, tip)?;
            let mut nf_stream = client.get_nullifiers(pad_start, pad_end).await?;
            while let Some(nf_result) = nf_stream.next().await {
                let nf = nf_result?;
                if !height_in_scan_window(nf.height, s, e) {
                    continue;
                }
                for nullifier in nf.nullifiers {
                    let marked = self.db.mark_note_spent_at(&nullifier, Some(nf.height))?;
                    if marked > 0 {
                        notes_spent += marked as u32;
                    }
                }
            }
            s = e.saturating_add(1);
            if s == 0 {
                break;
            }
        }
        Ok(notes_spent)
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
    pub(super) async fn fetch_matching_blocks(
        &self,
        client: &mut LightwalletClient,
        window_start: u32,
        window_end: u32,
        matching_heights: &[u32],
    ) -> Result<Vec<crate::client::proto::CompactBlock>, Box<dyn std::error::Error>> {
        let caps = client.get_omr_capabilities().await?;
        if !self.force_trial && caps.enabled && caps.scheme.contains("unifomr") {
            let mut last_err: Option<String> = None;
            for attempt in 1..=3 {
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
                        last_err = Some(redact_sync_error(&e.to_string()));
                        if attempt < 3 {
                            tracing::warn!(
                                "UnifOMR Round 2 PIR attempt {attempt}/3 failed ({}); retrying",
                                last_err.as_deref().unwrap_or("error")
                            );
                            jittered_sleep(1).await;
                        }
                    }
                }
            }
            tracing::warn!(
                "UnifOMR Round 2 PIR failed ({}); falling back to full-window range fetch \
                 (privacy-preserving — does not reveal matched heights)",
                last_err.unwrap_or_else(|| "error".into())
            );
        }

        // Privacy-preserving fallback: the padded window, never the match set.
        // Prefer compact output bodies; GetBlockRange covers servers that do
        // not implement that RPC yet. The range stays padded either way.
        self.fetch_padded_window_blocks(client, window_start, window_end, window_end)
            .await
    }

    /// Stream every compact block in `[window_start, window_end]` (the padded
    /// digest window). Reveals only the window — never the OMR match set.
    pub(super) async fn fetch_window_range(
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

    pub(super) async fn fetch_matching_blocks_sparse(
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
    pub(super) async fn fetch_matching_blocks_pir(
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
        let pir = darkfi_lightwalletd::pir_server::BatchPirClient::from_seed(pir_seed)?;

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
                needed_limbs = Some(darkfi_lightwalletd::pir_server::padded_limb_count(max_need));
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

    pub(super) async fn fetch_outputs_by_func(
        &self,
        client: &mut LightwalletClient,
        start: u32,
        end: u32,
        func_code: u32,
    ) -> Result<Vec<crate::client::proto::CompactBlock>, Box<dyn std::error::Error>> {
        use futures::StreamExt;
        let mut stream = client
            .get_compact_outputs_by_func(start, end, func_code)
            .await?;
        let mut bodies = Vec::new();
        while let Some(body) = stream.next().await {
            bodies.push(body?);
        }
        Ok(compact_blocks_from_output_bodies(bodies)
            .into_iter()
            .filter(|block| {
                block.txs.iter().any(|tx| {
                    tx.outputs
                        .iter()
                        .any(|output| !output.encrypted_note.is_empty())
                })
            })
            .collect())
    }

    pub(super) async fn store_contract_records(
        &self,
        client: &mut LightwalletClient,
        start: u32,
        end: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use futures::StreamExt;
        let mut dao = client.get_compact_dao_calls(start, end).await?;
        while let Some(call) = dao.next().await {
            let call = call?;
            self.db.insert_dao_call(
                call.height,
                &call.tx_hash,
                call.kind,
                &call.bulla,
                &call.payload,
            )?;
            if self.db.changed() {
                crate::tx_status::emit(
                    crate::tx_status::dao_kind(call.kind),
                    "sync",
                    "success",
                    "confirmed",
                    &hex::encode(&call.tx_hash),
                    Some(call.height),
                    "",
                    None,
                    crate::tx_status::dao_detail(call.kind),
                    "",
                );
            }
        }
        for code in [MONEY_FUNC_AUTH_TOKEN_MINT, MONEY_FUNC_AUTH_TOKEN_FREEZE] {
            let Ok(mut stream) = client.get_compact_outputs_by_func(start, end, code).await else {
                continue;
            };
            while let Some(body) = stream.next().await {
                let body = body?;
                if body.encrypted_note.is_empty() {
                    self.db
                        .insert_func_event(body.height, &body.tx_hash, body.func_code)?;
                    if self.db.changed() {
                        crate::tx_status::emit(
                            crate::tx_status::money_event_kind(body.func_code),
                            "sync",
                            "success",
                            "confirmed",
                            &hex::encode(&body.tx_hash),
                            Some(body.height),
                            "",
                            None,
                            crate::tx_status::money_event_detail(body.func_code),
                            "",
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn trial_decrypt_blocks(
        &self,
        blocks: &[crate::client::proto::CompactBlock],
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let hits = batch_open_blocks(&self.secret_keys, blocks);
        let mut notes_found = 0u32;
        for (block_pos, block) in blocks.iter().enumerate() {
            notes_found += self.trial_decrypt_block(block_pos, block, &hits)?;
            if let Some(cache) = &self.block_cache {
                if let Err(e) = cache.delete_height(block.height) {
                    tracing::warn!(
                        "failed to delete processed compact block {}: {e}",
                        block.height
                    );
                }
            }
        }
        Ok(notes_found)
    }

    pub(super) fn trial_decrypt_block(
        &self,
        block_pos: usize,
        block: &crate::client::proto::CompactBlock,
        hits: &TrialHits,
    ) -> Result<u32, Box<dyn std::error::Error>> {
        let mut notes_found = 0u32;
        for (tx_pos, tx) in block.txs.iter().enumerate() {
            let tx_hash_hex = hex::encode(&tx.tx_hash);
            if self
                .db
                .confirm_transaction(&tx_hash_hex, block.height)
                .unwrap_or(0)
                > 0
            {
                if let Ok(Some(row)) = self.db.get_transaction(&tx_hash_hex) {
                    let kind = if row.kind.is_empty() || row.kind == "transfer" {
                        if row.direction == "incoming" {
                            "receive"
                        } else {
                            "send"
                        }
                    } else {
                        row.kind.as_str()
                    };
                    crate::tx_status::emit(
                        kind,
                        "sync",
                        "success",
                        "confirmed",
                        &row.hash,
                        Some(row.block_height),
                        &row.token_id,
                        Some(row.value_raw as u64),
                        "",
                        "",
                    );
                }
            }
            for (idx, output) in tx.outputs.iter().enumerate() {
                if tx.tx_hash.len() != 32 {
                    continue;
                }
                let Some((note, secret_key)) = hits.get(&(block_pos, tx_pos, idx)) else {
                    continue;
                };
                {
                    let tx_hash_hex = hex::encode(&tx.tx_hash);
                    // S5: commitment is output.coin from the compact block
                    let commitment = if output.coin.len() == 32 {
                        Some(output.coin.as_slice())
                    } else {
                        None
                    };
                    // Skip if this exact on-chain coin commitment is already recorded for this tx
                    // (e.g. a TOKEN_MINT output appearing in both a full block and an extra block).
                    if let Some(c) = commitment {
                        if self.db.note_exists_by_commitment(&tx_hash_hex, c)? {
                            continue;
                        }
                    }
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
                    let Ok(value_i64) = i64::try_from(note.value) else {
                        tracing::error!(
                            "Skipping decrypted note {}:{} with value {} exceeding i64::MAX",
                            tx_hash_hex,
                            idx,
                            note.value
                        );
                        continue;
                    };
                    // Avoid synthetic `idx = 0` collisions when extra TOKEN_MINT blocks
                    // share a tx_hash with another output already stored at output_index 0.
                    let db_output_index =
                        self.db
                            .resolve_note_output_index(&tx_hash_hex, idx as u32, commitment)?;
                    let token_hex = hex::encode(&note.token_id);
                    let _rowid = self.db.insert_note(
                        &tx_hash_hex,
                        db_output_index,
                        value_i64,
                        &token_hex,
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
                    let fresh_note = self.db.changed();
                    if note.spend_hook_bytes.len() == 32 {
                        let _ = self.db.set_spend_hook_bytes(
                            &tx_hash_hex,
                            db_output_index,
                            &note.spend_hook_bytes,
                        );
                    }
                    // Multi-output incoming tx accounting: sum all notes in this tx
                    // for `token_hex` instead of collapsing to output 0.
                    self.db.upsert_incoming_transaction(
                        &tx_hash_hex,
                        block.height,
                        value_i64,
                        &token_hex,
                        note.memo.as_deref(),
                    )?;
                    if fresh_note {
                        let (kind, detail) = match self.db.get_transaction(&tx_hash_hex) {
                            Ok(Some(row)) if row.direction == "outgoing" => {
                                let kind = if row.kind.is_empty() || row.kind == "transfer" {
                                    "send".to_string()
                                } else {
                                    row.kind
                                };
                                (kind, format!("own-output-{db_output_index}"))
                            }
                            _ => ("receive".to_string(), format!("output-{db_output_index}")),
                        };
                        crate::tx_status::emit(
                            &kind,
                            "sync",
                            "success",
                            "confirmed",
                            &tx_hash_hex,
                            Some(block.height),
                            &token_hex,
                            Some(note.value),
                            &detail,
                            "",
                        );
                        notes_found += 1;
                    }
                }
            }
        }
        Ok(notes_found)
    }

    /// Attempt UnifOMR detection via the server (scheme 0x05 only).
    ///
    /// Returns `(matching_heights, covered_end)`. `covered_end` is `Some(h)` when
    /// the server truncated the digest at its DoS cap (`complete == false`) and
    /// only covered heights up to `h`; the caller must clamp its scan window to
    /// `h` so the dropped tail is re-requested next cycle. `None` ⇒ full coverage.
    pub(super) async fn try_omr_detect(
        &self,
        client: &mut LightwalletClient,
        start: u32,
        end: u32,
    ) -> Result<(Vec<u32>, Option<u32>), Box<dyn std::error::Error>> {
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
        // Server cap on the sum of detection_keys lengths per request
        // (lightwalletd MAX_DETECTION_KEYS_TOTAL_BYTES = 160 MiB).  One Param2
        // det-key is ~120 MiB (D=4096, n=1024, 3×40-bit moduli), so
        // multi-address wallets are effectively limited to 1 key per RPC;
        // additional keys must be chunked into separate requests and the
        // per-chunk results unioned.
        const SERVER_DETECTION_KEYS_TOTAL_BUDGET: usize = 160 * 1024 * 1024;

        let mut clients = Vec::new();
        let mut detection_keys = Vec::new();
        // The registered clue key is derived from the first wallet secret
        // (`Wallet::wallet_secret_bytes`). Detection keys from other
        // sub-address secrets never match that clue and only upload ~120 MiB
        // of ciphertext the server can ignore.
        for sk in self.secret_keys.iter().take(1) {
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
        // Lowest covered-end across chunks whose digest was truncated at the DoS
        // cap (all chunks share the same block range, so their coverage agrees).
        let mut covered_end: Option<u32> = None;
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
                let digest = self
                    .pooled_unif_omr_digest(
                        client,
                        &chunk_clients,
                        std::mem::take(&mut chunk_keys),
                        start,
                        end,
                    )
                    .await?;
                let slot_heights =
                    darkfi_lightwalletd::unifomr::unpack_slot_heights(&digest.slot_heights)?;
                if !digest.complete {
                    // Truncated at a whole-height boundary: the covered end is the
                    // highest mapped height. Track the minimum across chunks.
                    if let Some(&end_h) = slot_heights.iter().max() {
                        covered_end = Some(covered_end.map_or(end_h, |c: u32| c.min(end_h)));
                    } else {
                        return Err("UnifOMR digest truncated with empty slot_heights; \
                             refusing to skip the uncovered tail"
                            .into());
                    }
                }
                let chunk_heights = decrypt_unif_omr_heights(
                    &chunk_clients,
                    &digest.encrypted_digest,
                    &slot_heights,
                )?;
                heights.extend(chunk_heights);
                chunk_clients.clear();
                chunk_bytes = 0;
            }
        }
        heights.sort_unstable();
        heights.dedup();
        if let Some(c) = covered_end {
            tracing::warn!(
                "UnifOMR digest truncated at DoS cap: covered up to height {c} \
                 (requested [{start}, {end}]); scan window will be clamped"
            );
        }
        tracing::debug!(
            "UnifOMR Round 1: {} matching heights in [{start}, {end}] ({} detection keys)",
            heights.len(),
            total_keys
        );
        Ok((heights, covered_end))
    }

    /// Trial-decrypt download for one padded window.
    pub(super) async fn fetch_padded_window_blocks(
        &self,
        client: &mut LightwalletClient,
        window_start: u32,
        window_end: u32,
        tip: u32,
    ) -> Result<Vec<crate::client::proto::CompactBlock>, Box<dyn std::error::Error>> {
        let (pad_start, pad_end) = require_padded_range(window_start, window_end, tip)?;
        let mut stream = client.get_compact_output_bodies(pad_start, pad_end).await?;
        let mut bodies = Vec::new();
        while let Some(body) = stream.next().await {
            bodies.push(body?);
        }
        Ok(compact_blocks_from_output_bodies(bodies))
    }

    /// Register the detection key once per process, then ask for a pooled digest.
    /// `NOT_FOUND` drops the handle, builds a fresh key, and registers again.
    /// The handle is never logged.
    pub(super) async fn pooled_unif_omr_digest(
        &self,
        client: &mut LightwalletClient,
        omr_clients: &[darkfi_lightwalletd::unifomr::UnifOmrClient],
        detection_keys: Vec<Vec<u8>>,
        start: u32,
        end: u32,
    ) -> Result<crate::client::proto::OmrDigestResponse, Box<dyn std::error::Error>> {
        match self
            .digest_from_pool_or_register(client, &detection_keys, start, end)
            .await
        {
            Ok(digest) => Ok(digest),
            Err(e) if grpc_code_is(e.as_ref(), tonic::Code::NotFound) => {
                clear_detection_pool();
                let fresh = rebuild_detection_keys(omr_clients, self.network_byte)?;
                self.digest_from_pool_or_register(client, &fresh, start, end)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    pub(super) async fn digest_from_pool_or_register(
        &self,
        client: &mut LightwalletClient,
        detection_keys: &[Vec<u8>],
        start: u32,
        end: u32,
    ) -> Result<crate::client::proto::OmrDigestResponse, Box<dyn std::error::Error>> {
        if let Some(handle) = detection_pool_handle(&self.server_url, self.network_byte) {
            match client
                .get_unif_omr_digest_from_pool(&handle, start, end)
                .await
            {
                Ok(digest) => return Ok(digest),
                Err(e) if grpc_code_is(e.as_ref(), tonic::Code::NotFound) => {
                    clear_detection_pool();
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
        match client.register_detection_key(detection_keys.to_vec()).await {
            Ok(registered) => {
                let handle = registered.handle;
                if handle.is_empty() {
                    return Err("RegisterDetectionKey returned an empty handle".into());
                }
                store_detection_pool(
                    &self.server_url,
                    self.network_byte,
                    handle.clone(),
                    registered.expires_unix,
                );
                match client
                    .get_unif_omr_digest_from_pool(&handle, start, end)
                    .await
                {
                    Ok(digest) => Ok(digest),
                    Err(e) if grpc_code_is(e.as_ref(), tonic::Code::NotFound) => {
                        clear_detection_pool();
                        Err(e)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}
