use super::*;

pub(super) fn compact_blocks_from_output_bodies(
    bodies: Vec<crate::client::proto::CompactOutputBody>,
) -> Vec<crate::client::proto::CompactBlock> {
    use std::collections::BTreeMap;
    struct HeightAcc {
        hash: Vec<u8>,
        prev_hash: Vec<u8>,
        txs: BTreeMap<Vec<u8>, Vec<crate::client::proto::CompactOutput>>,
    }
    let mut by_height: BTreeMap<u32, HeightAcc> = BTreeMap::new();
    for body in bodies {
        let entry = by_height.entry(body.height).or_insert_with(|| HeightAcc {
            hash: body.hash.clone(),
            prev_hash: body.prev_hash.clone(),
            txs: BTreeMap::new(),
        });
        entry.txs.entry(body.tx_hash.clone()).or_default().push(
            crate::client::proto::CompactOutput {
                coin: body.coin,
                encrypted_note: body.encrypted_note,
                value_commit: Vec::new(),
                token_commit: Vec::new(),
                omr_clue: body.omr_clue,
                omr_metadata_enc: body.omr_metadata_enc,
                func_code: body.func_code,
            },
        );
    }
    by_height
        .into_iter()
        .map(|(height, acc)| crate::client::proto::CompactBlock {
            height,
            hash: acc.hash,
            prev_hash: acc.prev_hash,
            timestamp: 0,
            txs: acc
                .txs
                .into_iter()
                .map(|(tx_hash, outputs)| crate::client::proto::CompactTx {
                    tx_hash,
                    outputs,
                    nullifiers: Vec::new(),
                    fee: 0,
                })
                .collect(),
        })
        .collect()
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

/// Redact sensitive information (URLs, IPs, IPv6, `.onion`, `host:port`) from error messages.
pub fn redact_sync_error(msg: &str) -> String {
    let mut result = msg.to_string();

    let url_re = regex_lite::Regex::new(r"(https?|tcp(\+tls)?|grpc)://[^\s]+").unwrap();
    result = url_re.replace_all(&result, "[redacted-url]").to_string();

    let onion_re = regex_lite::Regex::new(r"[a-zA-Z2-7]{16,56}\.onion(:\d+)?").unwrap();
    result = onion_re
        .replace_all(&result, "[redacted-onion]")
        .to_string();

    let ipv6_re = regex_lite::Regex::new(r"\[[0-9a-fA-F:]+\](:\d+)?").unwrap();
    result = ipv6_re.replace_all(&result, "[redacted-addr]").to_string();

    let ip_re = regex_lite::Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?").unwrap();
    result = ip_re.replace_all(&result, "[redacted-addr]").to_string();

    let hostport_re = regex_lite::Regex::new(
        r"\b[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)+:\d+\b",
    )
    .unwrap();
    result = hostport_re
        .replace_all(&result, "[redacted-addr]")
        .to_string();

    result
}

/// Result of a sync cycle.
#[derive(Debug)]
pub struct SyncResult {
    pub blocks_scanned: u32,
    pub notes_found: u32,
    pub notes_spent: u32,
    pub tip_height: u32,
    /// Served tip was last refreshed from darkfid more than two minutes ago.
    /// `false` when the server did not report a poll time.
    pub tip_stale: bool,
    /// True when this cycle performed a reorg rewind and the caller should run
    /// another pass to sync the canonical fork.
    pub rewound: bool,
}

/// `0` is unknown (older server, or the poll has not succeeded). A reported
/// time older than two minutes means the served tip may be frozen.
pub fn tip_poll_is_stale(fetched_unix: u64) -> bool {
    if fetched_unix == 0 {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(fetched_unix) > 120
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
    /// Full 32-byte `FuncId::to_repr()` — required for `CoinAttributes::to_coin()`.
    pub spend_hook_bytes: Vec<u8>,
    pub user_data: Vec<u8>,
}

/// Remaining AEAD plaintext (MoneyNote decode is applied separately so a
/// truncated/odd memo cannot fail-closed the spend fields).
pub(super) struct RemainingBytes(Vec<u8>);

impl darkfi_serial::Decodable for RemainingBytes {
    fn decode<D: std::io::Read>(d: &mut D) -> std::io::Result<Self> {
        let mut v = Vec::new();
        d.read_to_end(&mut v)?;
        Ok(Self(v))
    }
}

pub(super) fn aead_note_candidates(
    encrypted_note: &[u8],
) -> Vec<darkfi_sdk::crypto::note::AeadEncryptedNote> {
    use darkfi_sdk::crypto::note::AeadEncryptedNote;
    use darkfi_sdk::crypto::PublicKey;
    use darkfi_serial::Decodable;
    use std::io::Cursor;

    let mut out = Vec::new();
    let mut cursor = Cursor::new(encrypted_note);
    if let Ok(n) = AeadEncryptedNote::decode(&mut cursor) {
        if cursor.position() as usize == encrypted_note.len() {
            out.push(n);
        }
    }
    if encrypted_note.len() >= 48 {
        let mut c = Cursor::new(encrypted_note);
        if let Ok(ephem) = PublicKey::decode(&mut c) {
            out.push(AeadEncryptedNote {
                ciphertext: encrypted_note[32..].to_vec(),
                ephem_public: ephem,
            });
        }
        let (ct, ep) = encrypted_note.split_at(encrypted_note.len() - 32);
        let mut c = Cursor::new(ep);
        if let Ok(ephem) = PublicKey::decode(&mut c) {
            out.push(AeadEncryptedNote {
                ciphertext: ct.to_vec(),
                ephem_public: ephem,
            });
        }
    }
    out
}

pub(super) fn money_note_from_plaintext(
    pt: &[u8],
) -> Option<darkfi_money_contract::client::MoneyNote> {
    use darkfi_money_contract::client::MoneyNote;
    use darkfi_money_contract::model::TokenId;
    use darkfi_sdk::crypto::{BaseBlind, FuncId, ScalarBlind};
    use darkfi_sdk::pasta::pallas;
    use darkfi_serial::Decodable;
    use std::io::Cursor;

    let mut c = Cursor::new(pt);
    if let Ok(n) = MoneyNote::decode(&mut c) {
        return Some(n);
    }
    // PoW / older notes: spend fields present, memo VarInt missing or truncated.
    let mut c = Cursor::new(pt);
    let value = u64::decode(&mut c).ok()?;
    let token_id = TokenId::decode(&mut c).ok()?;
    let spend_hook = FuncId::decode(&mut c).ok()?;
    let user_data = pallas::Base::decode(&mut c).ok()?;
    let coin_blind = BaseBlind::decode(&mut c).ok()?;
    let value_blind = ScalarBlind::decode(&mut c).ok()?;
    let token_blind = BaseBlind::decode(&mut c).ok()?;
    let memo = Vec::<u8>::decode(&mut c).unwrap_or_default();
    Some(MoneyNote {
        value,
        token_id,
        spend_hook,
        user_data,
        coin_blind,
        value_blind,
        token_blind,
        memo,
    })
}

pub(super) fn decrypted_from_money_note(
    note: darkfi_money_contract::client::MoneyNote,
) -> Option<DecryptedNote> {
    use darkfi_sdk::crypto::pasta_prelude::PrimeField;
    use darkfi_serial::Encodable;

    let mut coin_blind = Vec::new();
    note.coin_blind.inner().encode(&mut coin_blind).ok()?;
    let mut value_blind = Vec::new();
    note.value_blind.inner().encode(&mut value_blind).ok()?;
    let mut token_blind = Vec::new();
    note.token_blind.inner().encode(&mut token_blind).ok()?;
    let mut user_data = Vec::new();
    note.user_data.encode(&mut user_data).ok()?;

    let spend_hook_bytes = note.spend_hook.inner().to_repr().to_vec();
    let spend_hook = spend_hook_bytes.first().copied().unwrap_or(0);
    let memo = {
        let raw = &note.memo;
        if raw.is_empty() {
            None
        } else {
            String::from_utf8(raw.clone())
                .ok()
                .filter(|s| !s.trim().is_empty())
        }
    };

    Some(DecryptedNote {
        value: note.value,
        token_id: note.token_id.to_bytes().to_vec(),
        serial: coin_blind.clone(),
        memo,
        coin_blind,
        value_blind,
        token_blind,
        spend_hook,
        spend_hook_bytes,
        user_data,
    })
}

/// `CoinAttributes::to_coin()` bytes for a decrypted note + owner secret.
pub fn derived_coin_from_note(note: &DecryptedNote, wallet_key: &[u8]) -> Option<Vec<u8>> {
    use darkfi_money_contract::model::{CoinAttributes, TokenId};
    use darkfi_sdk::crypto::{FuncId, PublicKey, SecretKey};
    use darkfi_sdk::pasta::pallas;
    use darkfi_serial::Decodable;
    use std::io::Cursor;

    if wallet_key.len() < 32
        || note.token_id.len() != 32
        || note.coin_blind.len() != 32
        || note.user_data.len() != 32
        || note.spend_hook_bytes.len() != 32
    {
        return None;
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&wallet_key[..32]);
    let sk = SecretKey::from_bytes(sk_arr).ok()?;
    let mut tok = [0u8; 32];
    tok.copy_from_slice(&note.token_id);
    let token_id = TokenId::from_bytes(tok).ok()?;
    let mut hook = [0u8; 32];
    hook.copy_from_slice(&note.spend_hook_bytes);
    let spend_hook = FuncId::from_bytes(hook).ok()?;
    let coin_blind = pallas::Base::decode(&mut Cursor::new(&note.coin_blind)).ok()?;
    let user_data = pallas::Base::decode(&mut Cursor::new(&note.user_data)).ok()?;
    Some(
        CoinAttributes {
            public_key: PublicKey::from_secret(sk),
            value: note.value,
            token_id,
            spend_hook,
            user_data,
            blind: darkfi_sdk::crypto::Blind(coin_blind),
        }
        .to_coin()
        .to_bytes()
        .to_vec(),
    )
}

/// Keyed by `(block_pos, tx_pos, out_pos)` in the caller's `blocks` slice so
/// supplemental blocks at the same height (e.g. `TOKEN_MINT` extra blocks)
/// never collide with regular compact blocks.
pub(super) type TrialHits =
    std::collections::HashMap<(usize, usize, usize), (DecryptedNote, Vec<u8>)>;

/// Strip outputs from supplemental `TOKEN_MINT` blocks that are already present
/// in `in_window` (matching `(height, tx_hash, coin)`), avoiding duplicate work
/// and synthetic `idx = 0` collisions.
pub(super) fn dedup_extra_blocks_against_window(
    in_window: &[crate::client::proto::CompactBlock],
    extra: Vec<crate::client::proto::CompactBlock>,
) -> Vec<crate::client::proto::CompactBlock> {
    let mut seen: std::collections::HashSet<(u32, Vec<u8>, Vec<u8>)> =
        std::collections::HashSet::new();
    for block in in_window {
        for tx in &block.txs {
            for out in &tx.outputs {
                if out.coin.len() == 32 {
                    seen.insert((block.height, tx.tx_hash.clone(), out.coin.clone()));
                }
            }
        }
    }
    let mut out_blocks = Vec::new();
    for mut block in extra {
        for tx in &mut block.txs {
            tx.outputs.retain(|o| {
                if o.coin.len() == 32 {
                    !seen.contains(&(block.height, tx.tx_hash.clone(), o.coin.clone()))
                } else {
                    true
                }
            });
        }
        block.txs.retain(|tx| !tx.outputs.is_empty());
        if !block.txs.is_empty() {
            out_blocks.push(block);
        }
    }
    out_blocks
}

pub(super) const MONEY_FUNC_AUTH_TOKEN_MINT: u32 = 0x04;
pub(super) const MONEY_FUNC_AUTH_TOKEN_FREEZE: u32 = 0x05;
pub(super) const MONEY_FUNC_TOKEN_MINT: u32 = 0x06;

pub(super) fn batch_open_blocks(
    secrets: &[Vec<u8>],
    blocks: &[crate::client::proto::CompactBlock],
) -> TrialHits {
    use darkfi_sdk::crypto::diffie_hellman::sapling_ka_agree_batch as note_key_agree_batch;
    use darkfi_sdk::crypto::note::AeadEncryptedNote;
    use darkfi_sdk::crypto::SecretKey;
    use darkfi_serial::Decodable;
    use std::io::Cursor;

    struct Job {
        block_pos: usize,
        tx_pos: usize,
        out_pos: usize,
        coin: Vec<u8>,
        note: AeadEncryptedNote,
    }

    let mut jobs = Vec::new();
    let mut fallback = Vec::new();
    for (block_pos, block) in blocks.iter().enumerate() {
        for (tx_pos, tx) in block.txs.iter().enumerate() {
            if tx.tx_hash.len() != 32 {
                continue;
            }
            for (out_pos, output) in tx.outputs.iter().enumerate() {
                if output.encrypted_note.len() < 48 {
                    continue;
                }
                let mut cursor = Cursor::new(output.encrypted_note.as_slice());
                let decoded_exact = AeadEncryptedNote::decode(&mut cursor)
                    .ok()
                    .filter(|_| cursor.position() as usize == output.encrypted_note.len());
                if let Some(note) = decoded_exact {
                    jobs.push(Job {
                        block_pos,
                        tx_pos,
                        out_pos,
                        coin: output.coin.clone(),
                        note,
                    });
                } else {
                    fallback.push((
                        block_pos,
                        tx_pos,
                        out_pos,
                        output.coin.clone(),
                        output.encrypted_note.clone(),
                    ));
                }
            }
        }
    }

    let mut out = std::collections::HashMap::new();
    for secret_bytes in secrets {
        if secret_bytes.len() < 32 {
            continue;
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&secret_bytes[..32]);
        let Ok(secret) = SecretKey::from_bytes(raw) else {
            continue;
        };
        let pending: Vec<usize> = jobs
            .iter()
            .enumerate()
            .filter(|(_, job)| !out.contains_key(&(job.block_pos, job.tx_pos, job.out_pos)))
            .map(|(index, _)| index)
            .collect();
        if pending.is_empty() {
            continue;
        }
        // Chunks of 48 notes do Diffie-Hellman and AEAD together on the Rayon
        // pool. The caller still writes SQLite after the join. Smaller windows
        // stay on this thread.
        const BATCH_CHUNK: usize = 48;
        let open = |indexes: &[usize]| -> Vec<(usize, DecryptedNote)> {
            let epks: Vec<_> = indexes
                .iter()
                .map(|index| jobs[*index].note.ephem_public)
                .collect();
            let shared = note_key_agree_batch(&secret, &epks);
            indexes
                .iter()
                .zip(shared)
                .filter_map(|(index, shared)| {
                    let shared = shared.ok()?;
                    let Ok(RemainingBytes(plaintext)) =
                        jobs[*index].note.decrypt_with_shared(&shared)
                    else {
                        return None;
                    };
                    let money = money_note_from_plaintext(&plaintext)?;
                    let note = decrypted_from_money_note(money)?;
                    // Fail closed if note attributes cannot derive a valid coin commitment.
                    let derived = derived_coin_from_note(&note, secret_bytes)?;
                    if jobs[*index].coin.len() == 32
                        && derived.as_slice() != jobs[*index].coin.as_slice()
                    {
                        return None;
                    }
                    Some((*index, note))
                })
                .collect()
        };
        let hits: Vec<(usize, DecryptedNote)> = if pending.len() <= BATCH_CHUNK {
            open(&pending)
        } else {
            use rayon::prelude::*;
            pending
                .par_chunks(BATCH_CHUNK)
                .flat_map_iter(open)
                .collect()
        };
        for (index, note) in hits {
            out.insert(
                (
                    jobs[index].block_pos,
                    jobs[index].tx_pos,
                    jobs[index].out_pos,
                ),
                (note, secret_bytes.clone()),
            );
        }
    }
    for (block_pos, tx_pos, out_pos, coin, encrypted) in fallback {
        if out.contains_key(&(block_pos, tx_pos, out_pos)) {
            continue;
        }
        for secret_bytes in secrets {
            let Some(note) = trial_decrypt_note(&encrypted, secret_bytes) else {
                continue;
            };
            // Fail closed if note attributes cannot derive a valid coin commitment.
            let Some(derived) = derived_coin_from_note(&note, secret_bytes) else {
                continue;
            };
            if coin.len() == 32 && derived.as_slice() != coin.as_slice() {
                continue;
            }
            out.insert((block_pos, tx_pos, out_pos), (note, secret_bytes.clone()));
            break;
        }
    }
    out
}

/// Trial decrypt a compact block note using the wallet's secret key.
///
/// AEAD-decrypts the compact `AeadEncryptedNote`, then parses `MoneyNote`
/// (full decode, or spend-fields-only if memo is truncated) so blinds match
/// `CoinAttributes::to_coin()` / on-chain `output.coin`.
pub fn trial_decrypt_note(encrypted_note: &[u8], wallet_key: &[u8]) -> Option<DecryptedNote> {
    use darkfi_sdk::crypto::SecretKey;

    if encrypted_note.len() < 48 || wallet_key.len() < 32 {
        return None;
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&wallet_key[..32]);
    let secret = SecretKey::from_bytes(key_bytes).ok()?;
    for enc_note in aead_note_candidates(encrypted_note) {
        let Ok(RemainingBytes(plaintext)) = enc_note.decrypt(&secret) else {
            continue;
        };
        if let Some(note) = money_note_from_plaintext(&plaintext) {
            return decrypted_from_money_note(note);
        }
    }
    None
}

/// Why `trial_decrypt_note` returned None (first failing step).
pub fn trial_decrypt_fail_reason(encrypted_note: &[u8], wallet_key: &[u8]) -> &'static str {
    use darkfi_sdk::crypto::SecretKey;

    if encrypted_note.len() < 48 {
        return "too_short";
    }
    if wallet_key.len() < 32 {
        return "key_short";
    }
    let cands = aead_note_candidates(encrypted_note);
    if cands.is_empty() {
        return "aead_decode";
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&wallet_key[..32]);
    let Ok(secret) = SecretKey::from_bytes(key_bytes) else {
        return "bad_secret";
    };
    let mut aead_ok = false;
    for enc_note in cands {
        let Ok(RemainingBytes(plaintext)) = enc_note.decrypt(&secret) else {
            continue;
        };
        aead_ok = true;
        if money_note_from_plaintext(&plaintext).is_some() {
            return "ok";
        }
    }
    if aead_ok {
        "note_parse"
    } else {
        "aead"
    }
}

/// Ensure lightwalletd `chain_name` matches the configured wallet network name (`mainnet`, `testnet`, `localnet`).
pub fn ensure_chain_matches_network_name(
    chain_name: &str,
    network: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let c = chain_name.to_ascii_lowercase();
    let norm = network.trim().to_ascii_lowercase();
    let ok = match norm.as_str() {
        "mainnet" => c.contains("mainnet") && !c.contains("testnet") && !c.contains("localnet"),
        "localnet" => c.contains("localnet") && !c.contains("mainnet"),
        "testnet" => c.contains("testnet") && !c.contains("mainnet") && !c.contains("localnet"),
        _ => {
            return Err(format!("Unsupported wallet network '{network}'").into());
        }
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "lightwalletd chain_name '{chain_name}' does not match wallet network '{network}'. \
             Use the same darkfi-lightwalletd network for all clients."
        )
        .into())
    }
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

#[allow(dead_code)]
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
