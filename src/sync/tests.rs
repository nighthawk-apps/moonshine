#[allow(unused_imports)]
use super::*;

#[test]
fn unknown_tip_poll_time_is_not_stale() {
    assert!(!tip_poll_is_stale(0));
    assert!(tip_poll_is_stale(1));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(!tip_poll_is_stale(now));
}

#[test]
fn raw_cursor_range_is_rejected() {
    assert!(!padded_range_accepted(42000, 42100, 50_000));
    assert!(!padded_range_accepted(100, 100, 50_000));
    assert!(!padded_range_accepted(0, 9999, 50_000));
    assert!(require_padded_range(100, 100, 50_000).unwrap() != (100, 100));
}

#[test]
fn padded_power_of_two_bucket_is_accepted() {
    let (start, end) = require_padded_range(42000, 42100, 50_000).unwrap();
    assert!(padded_range_accepted(start, end, 50_000));
    assert!(start <= 42000 && end >= 42100);
    let span = end - start + 1;
    assert!(span >= 1024);
    assert!(span.is_power_of_two());
    assert!(span <= 10_000);
    assert_eq!(
        require_padded_range(start, end, 50_000).unwrap(),
        (start, end)
    );
}

#[test]
fn tip_clamped_bucket_is_accepted_and_oversized_bucket_is_rejected() {
    let (start, end) = require_padded_range(49900, 50000, 50_000).unwrap();
    assert!(padded_range_accepted(start, end, 50_000));
    assert_eq!(end, 50_000);
    assert!(start <= 49900);
    assert!(!padded_range_accepted(0, 16_383, 100_000));
    assert!(require_padded_range(0, 9999, 100_000).is_err());
}

#[test]
fn two_bucket_windows_are_accepted_and_not_widened() {
    // 1500..=2500 crosses the 2048 boundary: two 1024 buckets.
    let (start, end) = require_padded_range(1500, 2500, 50_000).unwrap();
    assert_eq!((start, end), (1024, 3071));
    assert!(padded_range_accepted(start, end, 50_000));
    assert_eq!(require_padded_range(start, end, end).unwrap(), (start, end));
    // The same window cut at the tip.
    let (start, end) = require_padded_range(1500, 2500, 2600).unwrap();
    assert_eq!((start, end), (1024, 2600));
    assert_eq!(
        require_padded_range(start, end, 2600).unwrap(),
        (start, end)
    );
    // A raw power-of-two chunk off the bucket grid is still padded.
    assert!(!padded_range_accepted(1500, 5595, 50_000));
    // A chain shorter than one bucket is served whole from genesis.
    assert_eq!(require_padded_range(0, 10, 10).unwrap(), (0, 10));
    assert!(!padded_range_accepted(5, 10, 10));
}

#[test]
fn checkpoint_accepts_snapshot_at_or_below_birthday() {
    assert_eq!(preferred_checkpoint_height(0), 0);
    assert_eq!(preferred_checkpoint_height(5000), 5000);
    assert!(checkpoint_snapshot_accepted(4096, 5000));
    assert!(checkpoint_snapshot_accepted(5000, 5000));
    assert!(!checkpoint_snapshot_accepted(5001, 5000));
    assert!(checkpoint_snapshot_accepted(80_000, 0));
}

#[test]
fn scan_start_skips_snapshot_prefix() {
    assert_eq!(scan_start_for_sync(0, 5000, false, 0), 5000);
    assert_eq!(scan_start_for_sync(0, 5000, true, 4096), 5000);
    // Fresh wallet: birthday is the note cursor even if the tree snapshot
    // sits at the birthday height (commitments are skipped separately).
    assert_eq!(scan_start_for_sync(0, 5000, true, 5000), 5000);
    assert_eq!(scan_start_for_sync(5000, 0, true, 5000), 5001);
    // Multi-window scan: last_synced progresses sequentially without skipping to tree_applied
    assert_eq!(scan_start_for_sync(100, 0, true, 5000), 101);
    assert_eq!(scan_start_for_sync(0, 0, false, 0), 0);
    assert_eq!(scan_start_for_sync(0, 0, true, 117), 0);
}

#[test]
fn force_trial_ignores_a_strict_cursor_already_at_the_tip() {
    // Strict sync left last_synced and the Money tree at the tip.
    // force-trial with no trial cursor starts at the birthday.
    assert_eq!(note_scan_start(true, None, 6000, 0, true, 6000), 0);
    // A recorded trial cursor continues after that height, not after the tree.
    assert_eq!(note_scan_start(true, Some(100), 6000, 0, true, 6000), 101);
    // Strict sync still starts after the tree.
    assert_eq!(note_scan_start(false, None, 6000, 0, true, 6000), 6001);
}

#[test]
fn pool_handle_expiry() {
    assert!(pool_handle_usable(0, 1_000));
    assert!(pool_handle_usable(2_000, 1_999));
    assert!(!pool_handle_usable(2_000, 2_000));
}

#[test]
fn padded_commitment_window_drops_heights_outside_scan() {
    let (pad_start, pad_end) = pad_block_range(42000, 42100, 50_000);
    assert!(pad_start < 42000);
    assert!(pad_end > 42100);
    let returned = [pad_start, 41999, 42000, 42100, pad_end];
    let kept: Vec<u32> = returned
        .into_iter()
        .filter(|h| height_in_scan_window(*h, 42000, 42100))
        .collect();
    assert_eq!(kept, vec![42000, 42100]);
}

#[test]
fn test_pre_birthday_commitment_range() {
    assert_eq!(pre_birthday_commitment_range(0), None);
    assert_eq!(pre_birthday_commitment_range(1), Some((0, 0)));
    assert_eq!(pre_birthday_commitment_range(53000), Some((0, 52999)));
}

#[test]
fn test_chain_matches_testnet() {
    ensure_chain_matches_network("darkfi-testnet", 0x01).unwrap();
    ensure_chain_matches_network("darkfi-localnet", 0x01).unwrap();
    assert!(ensure_chain_matches_network("darkfi-mainnet", 0x01).is_err());

    ensure_chain_matches_network_name("darkfi-testnet", "testnet").unwrap();
    ensure_chain_matches_network_name("darkfi-localnet", "localnet").unwrap();
    assert!(ensure_chain_matches_network_name("darkfi-localnet", "testnet").is_err());
    assert!(ensure_chain_matches_network_name("darkfi-testnet", "localnet").is_err());
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
fn trial_decrypt_roundtrip_pow_style_memo() {
    use darkfi_money_contract::client::MoneyNote;
    use darkfi_money_contract::model::DARK_TOKEN_ID;
    use darkfi_sdk::crypto::note::AeadEncryptedNote;
    use darkfi_sdk::crypto::pasta_prelude::{Field, PrimeField};
    use darkfi_sdk::crypto::{Blind, FuncId, Keypair};
    use darkfi_sdk::pasta::pallas;
    use darkfi_serial::serialize;

    let kp = Keypair::default();
    let note = MoneyNote {
        value: 100_000_000,
        token_id: *DARK_TOKEN_ID,
        spend_hook: FuncId::none(),
        user_data: pallas::Base::ZERO,
        coin_blind: Blind::from(1u64),
        value_blind: Blind(pallas::Scalar::from(2u64)),
        token_blind: Blind::from(3u64),
        memo: serialize(&kp.secret),
    };
    let enc = AeadEncryptedNote::encrypt(&note, &kp.public, &mut rand_core::OsRng).unwrap();
    let bytes = serialize(&enc);
    let dec = trial_decrypt_note(&bytes, &kp.secret.inner().to_repr()).expect("decrypt");
    assert_eq!(dec.value, note.value);
    assert_eq!(dec.token_id, note.token_id.to_bytes());
    let derived = derived_coin_from_note(&dec, &kp.secret.inner().to_repr()).unwrap();
    let coin = darkfi_money_contract::model::CoinAttributes {
        public_key: kp.public,
        value: note.value,
        token_id: note.token_id,
        spend_hook: note.spend_hook,
        user_data: note.user_data,
        blind: note.coin_blind,
    }
    .to_coin();
    assert_eq!(derived, coin.to_bytes());
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

#[test]
fn snapshot_integrity_hash_lockstep() {
    let height = 42u32;
    let tree = b"tree-bytes";
    let nfs = b"nullifiers";
    let a = snapshot_integrity_hash(height, tree, nfs);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&height.to_le_bytes());
    hasher.update(tree);
    hasher.update(nfs);
    assert_eq!(a, *hasher.finalize().as_bytes());
    assert!(snapshot_integrity_hash(height, tree, b"").as_slice() != blake3::hash(tree).as_bytes());
}

#[test]
fn reorg_rewind_never_exceeds_tip_even_when_tip_below_birthday() {
    assert_eq!(reorg_rewind_height(0), 0);
    assert_eq!(reorg_rewind_height(1), 0);
    assert_eq!(reorg_rewind_height(50), 49);
    // Must never be pushed back up above tip_height when birthday = 100 > tip_height = 50.
    assert!(reorg_rewind_height(50) < 50);
}

#[test]
fn redact_sync_error_strips_onion_ipv6_and_hostport() {
    let onion = "dial failed to abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:9067";
    let r_onion = redact_sync_error(onion);
    assert!(!r_onion.contains(".onion"));
    assert!(r_onion.contains("[redacted-onion]"));

    let v6 = "connect [2001:db8::1]:9067 refused";
    let r_v6 = redact_sync_error(v6);
    assert!(!r_v6.contains("2001:db8"));
    assert!(r_v6.contains("[redacted-addr]"));

    let hp = "connect lwd.darkfi.example:9067 reset";
    let r_hp = redact_sync_error(hp);
    assert!(!r_hp.contains("lwd.darkfi.example"));
    assert!(r_hp.contains("[redacted-addr]"));
}

#[test]
fn batch_open_and_trial_decrypt_multi_output_and_extra_token_mint_no_collision() {
    use darkfi_money_contract::client::MoneyNote;
    use darkfi_money_contract::model::{CoinAttributes, DARK_TOKEN_ID};
    use darkfi_sdk::crypto::note::AeadEncryptedNote;
    use darkfi_sdk::crypto::pasta_prelude::{Field, PrimeField};
    use darkfi_sdk::crypto::{Blind, FuncId, Keypair};
    use darkfi_sdk::pasta::pallas;
    use darkfi_serial::serialize;

    let kp = Keypair::random(&mut rand_core::OsRng);
    let sk_bytes = kp.secret.inner().to_repr().to_vec();
    let mk_out = |val: u64, memo: Vec<u8>| {
        let cb = Blind::random(&mut rand_core::OsRng);
        let note = MoneyNote {
            value: val,
            token_id: *DARK_TOKEN_ID,
            spend_hook: FuncId::none(),
            user_data: pallas::Base::ZERO,
            coin_blind: cb,
            value_blind: Blind::random(&mut rand_core::OsRng),
            token_blind: Blind::random(&mut rand_core::OsRng),
            memo,
        };
        let coin = CoinAttributes {
            public_key: kp.public,
            value: val,
            token_id: *DARK_TOKEN_ID,
            spend_hook: FuncId::none(),
            user_data: pallas::Base::ZERO,
            blind: cb,
        }
        .to_coin();
        let enc = AeadEncryptedNote::encrypt(&note, &kp.public, &mut rand_core::OsRng).unwrap();
        crate::client::proto::CompactOutput {
            coin: coin.to_bytes().to_vec(),
            encrypted_note: serialize(&enc),
            value_commit: Vec::new(),
            token_commit: Vec::new(),
            omr_clue: Vec::new(),
            omr_metadata_enc: Vec::new(),
            func_code: 0,
        }
    };

    let tx_hash = vec![0x42u8; 32];
    let out0 = mk_out(300, b"part1".to_vec());
    let out1 = mk_out(450, Vec::new());
    let out_mint_extra = mk_out(250, Vec::new());

    // Block 0: normal compact block with 2 outputs for our wallet.
    let main_block = crate::client::proto::CompactBlock {
        height: 77,
        hash: vec![0x01; 32],
        prev_hash: vec![0x00; 32],
        timestamp: 1,
        txs: vec![crate::client::proto::CompactTx {
            tx_hash: tx_hash.clone(),
            outputs: vec![out0.clone(), out1],
            nullifiers: Vec::new(),
            fee: 0,
        }],
    };
    // Extra TOKEN_MINT block at the SAME height and SAME tx_hash with synthetic idx=0:
    // contains both a duplicate of out0 and a distinct extra output out_mint_extra!
    let extra_raw = vec![crate::client::proto::CompactBlock {
        height: 77,
        hash: vec![0x01; 32],
        prev_hash: vec![0x00; 32],
        timestamp: 1,
        txs: vec![crate::client::proto::CompactTx {
            tx_hash: tx_hash.clone(),
            outputs: vec![out0, out_mint_extra],
            nullifiers: Vec::new(),
            fee: 0,
        }],
    }];
    let mut combined = vec![main_block];
    let extra_deduped = dedup_extra_blocks_against_window(&combined, extra_raw);
    assert_eq!(extra_deduped.len(), 1);
    assert_eq!(extra_deduped[0].txs[0].outputs.len(), 1);
    combined.extend(extra_deduped);

    let db = WalletDb::in_memory().unwrap();
    let engine = SyncEngine::new(
        db,
        "http://127.0.0.1:9067",
        vec![sk_bytes],
        None,
        0x01,
        false,
        false,
        None,
        false,
    );
    let found = engine.trial_decrypt_blocks(&combined).unwrap();
    assert_eq!(
        found, 3,
        "all 3 distinct outputs must be stored without synthetic idx=0 collision"
    );
    assert_eq!(engine.db.confirmed_balance("DRK").unwrap(), 1000);
    let tx_row = engine
        .db
        .get_transaction(&hex::encode(&tx_hash))
        .unwrap()
        .expect("incoming tx row must exist");
    assert_eq!(
        tx_row.value_raw, 1000,
        "multi-output incoming tx must sum all 3 outputs"
    );
}

#[test]
fn batch_open_blocks_enforces_trailing_byte_check_and_falls_back() {
    use darkfi_money_contract::client::MoneyNote;
    use darkfi_money_contract::model::{CoinAttributes, DARK_TOKEN_ID};
    use darkfi_sdk::crypto::note::AeadEncryptedNote;
    use darkfi_sdk::crypto::pasta_prelude::{Field, PrimeField};
    use darkfi_sdk::crypto::{Blind, FuncId, Keypair};
    use darkfi_sdk::pasta::pallas;
    use darkfi_serial::serialize;

    let kp = Keypair::random(&mut rand_core::OsRng);
    let sk_bytes = kp.secret.inner().to_repr().to_vec();
    let cb = Blind::random(&mut rand_core::OsRng);
    let note = MoneyNote {
        value: 123_456,
        token_id: *DARK_TOKEN_ID,
        spend_hook: FuncId::none(),
        user_data: pallas::Base::ZERO,
        coin_blind: cb,
        value_blind: Blind::random(&mut rand_core::OsRng),
        token_blind: Blind::random(&mut rand_core::OsRng),
        memo: Vec::new(),
    };
    let coin = CoinAttributes {
        public_key: kp.public,
        value: 123_456,
        token_id: *DARK_TOKEN_ID,
        spend_hook: FuncId::none(),
        user_data: pallas::Base::ZERO,
        blind: cb,
    }
    .to_coin();
    let enc = AeadEncryptedNote::encrypt(&note, &kp.public, &mut rand_core::OsRng).unwrap();
    // Raw (ephem_pk || ciphertext) encoding without VarInt length prefix — only
    // handled by fallback `aead_note_candidates`, NOT `AeadEncryptedNote::decode`!
    let mut raw_enc = serialize(&enc.ephem_public);
    raw_enc.extend_from_slice(&enc.ciphertext);

    let block = crate::client::proto::CompactBlock {
        height: 10,
        hash: vec![0x02; 32],
        prev_hash: vec![0x01; 32],
        timestamp: 1,
        txs: vec![crate::client::proto::CompactTx {
            tx_hash: vec![0x99; 32],
            outputs: vec![crate::client::proto::CompactOutput {
                coin: coin.to_bytes().to_vec(),
                encrypted_note: raw_enc,
                value_commit: Vec::new(),
                token_commit: Vec::new(),
                omr_clue: Vec::new(),
                omr_metadata_enc: Vec::new(),
                func_code: 0,
            }],
            nullifiers: Vec::new(),
            fee: 0,
        }],
    };

    let hits = batch_open_blocks(&[sk_bytes], &[block]);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits.get(&(0, 0, 0)).unwrap().0.value, 123_456);
}
