use super::*;

/// Decrypt UnifOMR Round-1 digest(s) and collect matching heights.
///
/// `slot_heights` is the response's packed slot → height map (same for every
/// key); slot `i` decrypts to a match iff its clue is pertinent, mapping to
/// `slot_heights[i]`. Single-key responses are unframed; multi-key responses are
/// length-prefixed frames (one digest per detection key), matching lightwalletd.
pub(super) fn decrypt_unif_omr_heights(
    clients: &[darkfi_lightwalletd::unifomr::UnifOmrClient],
    encrypted_digest: &[u8],
    slot_heights: &[u32],
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
            darkfi_lightwalletd::unifomr::UnifOmrClient::range_check_matches(&slots, slot_heights)
                .map_err(|e| format!("UnifOMR range check failed: {e}"))?,
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
            darkfi_lightwalletd::unifomr::UnifOmrClient::range_check_matches(&slots, slot_heights)
                .map_err(|e| format!("UnifOMR range check failed for key[{i}]: {e}"))?
        {
            heights.insert(h);
        }
    }
    Ok(heights.into_iter().collect())
}

/// True when `height` is inside the inclusive scan window.
pub fn height_in_scan_window(height: u32, start: u32, end: u32) -> bool {
    height >= start && height <= end
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

/// A wire range lightwalletd accepts for commitments, nullifiers, and compact
/// output bodies, i.e. any shape [`pad_block_range`] emits, with a span of at
/// most [`MAX_RANGE_PER_REQUEST`]. `start` sits on a multiple of
/// `max(next_pow2(span) / 2, MIN_BUCKET_SIZE)`, and the span is either a power
/// of two of at least [`MIN_BUCKET_SIZE`] or a bucket cut short at `tip`. The
/// server also takes unaligned power-of-two spans; refusing them here keeps a
/// raw chunk start off the wire.
pub fn padded_range_accepted(start: u32, end: u32, tip: u32) -> bool {
    if start > end || end > tip {
        return false;
    }
    let span = u64::from(end - start) + 1;
    if span > u64::from(MAX_RANGE_PER_REQUEST) {
        return false;
    }
    let full = span.max(u64::from(MIN_BUCKET_SIZE)).next_power_of_two();
    let align = (full / 2).max(u64::from(MIN_BUCKET_SIZE));
    if u64::from(start) % align != 0 {
        return false;
    }
    span == full || end == tip
}

/// Pad `[start, end]` and refuse to return a range the server would reject.
pub fn require_padded_range(start: u32, end: u32, tip: u32) -> Result<(u32, u32), String> {
    if start > end {
        return Err(format!("invalid block range {start}..={end}"));
    }
    if start > tip {
        return Err(format!(
            "block range {start}..={end} starts above tip {tip}"
        ));
    }
    let end = end.min(tip);
    // Re-padding a two-bucket window can widen it, so keep one already padded.
    if padded_range_accepted(start, end, tip) {
        return Ok((start, end));
    }
    let (padded_start, padded_end) = pad_block_range(start, end, tip);
    if !padded_range_accepted(padded_start, padded_end, tip) {
        return Err(format!(
            "refusing unpadded or oversized range {padded_start}..={padded_end} (tip {tip})"
        ));
    }
    Ok((padded_start, padded_end))
}

/// Where note discovery starts.
///
/// `--force-trial` follows `trial_synced_height` (missing means "start at the
/// birthday") so clue-less payments hidden by an earlier strict scan are
/// decrypted. The Money tree cursor is intentionally not part of that start:
/// commitments already applied are skipped in `apply_note_commitments`.
pub fn note_scan_start(
    force_trial: bool,
    trial_cursor: Option<u32>,
    last_synced: u32,
    birthday: u32,
    merkle_from_genesis: bool,
    tree_applied: u32,
) -> u32 {
    if force_trial {
        return match trial_cursor {
            Some(covered) => covered.saturating_add(1).max(birthday),
            None => birthday,
        };
    }
    scan_start_for_sync(last_synced, birthday, merkle_from_genesis, tree_applied)
}

/// First height to scan after optional checkpoint state.
///
/// Note discovery scans every block from birthday to tip (default trial decrypt).
/// A Money-tree checkpoint snapshot (`tree_applied`) only skips commitment replay
/// in `apply_note_commitments`, never trial decryption.
pub fn scan_start_for_sync(
    last_synced: u32,
    birthday: u32,
    _merkle_from_genesis: bool,
    _tree_applied: u32,
) -> u32 {
    if last_synced == 0 {
        birthday
    } else {
        last_synced.saturating_add(1).max(birthday)
    }
}

/// `birthday == 0` asks for the latest snapshot. Any other birthday is the
/// preferred height (greatest snapshot `<=` birthday).
pub fn preferred_checkpoint_height(birthday: u32) -> u32 {
    birthday
}

/// Accept the greatest snapshot at or below the birthday. A birthday of 0
/// means "latest", so any returned height is acceptable.
pub fn checkpoint_snapshot_accepted(snapshot_height: u32, birthday: u32) -> bool {
    birthday == 0 || snapshot_height <= birthday
}

/// `expires_unix == 0` means the server did not set an expiry.
pub fn pool_handle_usable(expires_unix: u64, now_unix: u64) -> bool {
    expires_unix == 0 || now_unix < expires_unix
}

pub(super) fn grpc_code_is(err: &(dyn std::error::Error + 'static), code: tonic::Code) -> bool {
    err.downcast_ref::<tonic::Status>()
        .is_some_and(|status| status.code() == code)
}

pub(super) fn checkpoint_status_falls_back(err: &(dyn std::error::Error + 'static)) -> bool {
    grpc_code_is(err, tonic::Code::NotFound) || grpc_code_is(err, tonic::Code::FailedPrecondition)
}

pub(super) fn rebuild_detection_keys(
    clients: &[darkfi_lightwalletd::unifomr::UnifOmrClient],
    network: u8,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut keys = Vec::with_capacity(clients.len());
    for client in clients {
        keys.push(client.build_detection_key(network)?);
    }
    if keys.is_empty() {
        return Err("no detection key to re-register".into());
    }
    Ok(keys)
}

pub(super) struct ProcessDetectionPool {
    server: String,
    network: u8,
    handle: Vec<u8>,
    expires_unix: u64,
}

pub(super) fn detection_pool() -> &'static std::sync::Mutex<Option<ProcessDetectionPool>> {
    static POOL: std::sync::OnceLock<std::sync::Mutex<Option<ProcessDetectionPool>>> =
        std::sync::OnceLock::new();
    POOL.get_or_init(|| std::sync::Mutex::new(None))
}

pub(super) fn detection_pool_handle(server: &str, network: u8) -> Option<Vec<u8>> {
    let mut slot = detection_pool().lock().unwrap_or_else(|e| e.into_inner());
    let now = unix_now();
    let usable = slot.as_ref().is_some_and(|state| {
        state.server == server
            && state.network == network
            && pool_handle_usable(state.expires_unix, now)
    });
    if !usable {
        if slot.is_some() {
            *slot = None;
        }
        return None;
    }
    slot.as_ref().map(|state| state.handle.clone())
}

pub(super) fn store_detection_pool(server: &str, network: u8, handle: Vec<u8>, expires_unix: u64) {
    *detection_pool().lock().unwrap_or_else(|e| e.into_inner()) = Some(ProcessDetectionPool {
        server: server.to_string(),
        network,
        handle,
        expires_unix,
    });
}

pub(super) fn clear_detection_pool() {
    *detection_pool().lock().unwrap_or_else(|e| e.into_inner()) = None;
}

pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
