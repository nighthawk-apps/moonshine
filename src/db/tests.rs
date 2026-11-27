#[allow(unused_imports)]
use super::*;

#[test]
fn test_db_initialize() {
    let db = WalletDb::in_memory().unwrap();
    let (height, birthday) = db.get_sync_state().unwrap();
    assert_eq!(height, 0);
    assert_eq!(birthday, 0);
}

#[test]
fn test_secret_not_stored_plaintext() {
    let db = WalletDb::in_memory().unwrap();
    let secret = [0xABu8; 32];
    db.insert_address("pk", &secret).unwrap();
    let stored: Vec<u8> = db
        .conn
        .query_row(
            "SELECT secret_key FROM addresses WHERE public_key = ?1",
            params!["pk"],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        stored.starts_with(b"MSK2"),
        "secret_key must be wrapped (MSK2), got {:?}",
        &stored[..stored.len().min(8)]
    );
    assert_ne!(stored, secret.to_vec());
    // Round-trip via public API still yields plaintext.
    let secrets = db.get_all_secrets().unwrap();
    assert_eq!(secrets, vec![secret.to_vec()]);
}

#[test]
fn test_all_sensitive_secrets_wrapped_at_rest_and_legacy_migrates() {
    let db = WalletDb::in_memory().unwrap();
    let wrap_key = db.wrap_key;

    // 1. Fresh inserts wrap derivation_seed, token_mints, deploy_auths, dao_records with MSK2.
    db.set_wrapped_meta("derivation_seed", &[0x55u8; 32])
        .unwrap();
    let raw_seed: Vec<u8> = db
        .conn
        .query_row(
            "SELECT value FROM wallet_meta WHERE key = 'derivation_seed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(raw_seed.starts_with(b"MSK2"));
    assert_eq!(
        db.get_wrapped_meta("derivation_seed").unwrap().unwrap(),
        vec![0x55u8; 32]
    );

    db.insert_token_mint("tok1", &[0x11u8; 32], &[0x22u8; 32], Some("T1"))
        .unwrap();
    let (raw_auth, raw_blind): (Vec<u8>, Vec<u8>) = db
        .conn
        .query_row(
            "SELECT mint_authority, token_blind FROM token_mints WHERE token_id = 'tok1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(raw_auth.starts_with(b"MSK2"));
    assert!(raw_blind.starts_with(b"MSK2"));

    db.insert_deploy_auth("cid1", &[0x33u8; 32]).unwrap();
    let raw_deploy: Vec<u8> = db
        .conn
        .query_row(
            "SELECT secret_key FROM deploy_auths WHERE contract_id = 'cid1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(raw_deploy.starts_with(b"MSK2"));

    db.upsert_dao_record("d1", "notes_secret_key = \"supersecret\"", None, None)
        .unwrap();
    let raw_dao: String = db
        .conn
        .query_row(
            "SELECT params_toml FROM dao_records WHERE name = 'd1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(raw_dao.starts_with("MSK2:"));
    assert!(!raw_dao.contains("supersecret"));
    assert_eq!(
        db.get_dao_toml("d1").unwrap().unwrap(),
        "notes_secret_key = \"supersecret\""
    );

    // 2. Simulate legacy MSK1 & plaintext rows directly in SQLite -> fail closed before migration.
    let legacy_addr_v1 = crate::secret_wrap::wrap_secret_legacy_v1(&[0x77u8; 32], &wrap_key);
    db.conn
        .execute(
            "INSERT INTO addresses (public_key, secret_key) VALUES ('legacy_pk', ?1)",
            params![legacy_addr_v1],
        )
        .unwrap();
    db.conn
        .execute(
            "UPDATE wallet_meta SET value = ?1 WHERE key = 'derivation_seed'",
            params![vec![0x66u8; 32]],
        )
        .unwrap();
    db.conn
        .execute(
            "UPDATE token_mints SET mint_authority = ?1, token_blind = ?2 WHERE token_id = 'tok1'",
            params![vec![0x88u8; 32], vec![0x99u8; 32]],
        )
        .unwrap();
    db.conn
        .execute(
            "UPDATE deploy_auths SET secret_key = ?1 WHERE contract_id = 'cid1'",
            params![vec![0xAAu8; 32]],
        )
        .unwrap();
    db.conn
        .execute(
            "UPDATE dao_records SET params_toml = 'legacy_plain = true' WHERE name = 'd1'",
            [],
        )
        .unwrap();

    // Fail-closed runtime reads refuse unmigrated MSK1/plaintext!
    assert!(db.get_all_secrets().is_err());
    assert!(db.get_wrapped_meta("derivation_seed").is_err());
    assert!(db.get_token_mint("tok1").is_err());
    assert!(db.get_deploy_auth("cid1").is_err());
    assert!(db.get_dao_toml("d1").is_err());

    // One-time migration upgrades all 5 rows to MSK2!
    let count = db.migrate_secrets_to_v2().unwrap();
    assert_eq!(count, 5);
    assert_eq!(
        db.migrate_secrets_to_v2().unwrap(),
        0,
        "migration must be idempotent"
    );

    assert_eq!(db.get_all_secrets().unwrap(), vec![vec![0x77u8; 32]]);
    assert_eq!(
        db.get_wrapped_meta("derivation_seed").unwrap().unwrap(),
        vec![0x66u8; 32]
    );
    let (_, auth, blind, _) = db.get_token_mint("tok1").unwrap().unwrap();
    assert_eq!(auth, vec![0x88u8; 32]);
    assert_eq!(blind, vec![0x99u8; 32]);
    assert_eq!(
        db.get_deploy_auth("cid1").unwrap().unwrap().0,
        vec![0xAAu8; 32]
    );
    assert_eq!(
        db.get_dao_toml("d1").unwrap().unwrap(),
        "legacy_plain = true"
    );
}

#[test]
fn test_multi_output_incoming_tx_sums_and_avoids_synthetic_idx_collision() {
    let db = WalletDb::in_memory().unwrap();
    let tok = WalletDb::dark_token_id_hex();
    let c0 = [0x10u8; 32];
    let c1 = [0x20u8; 32];

    // First output at idx=0
    let idx0 = db
        .resolve_note_output_index("tx_multi", 0, Some(&c0))
        .unwrap();
    assert_eq!(idx0, 0);
    db.insert_note(
        "tx_multi",
        idx0,
        500,
        &tok,
        &[1],
        100,
        Some("split"),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&c0),
        Some(&[1]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    db.upsert_incoming_transaction("tx_multi", 100, 500, &tok, Some("split"))
        .unwrap();
    assert_eq!(
        db.get_transaction("tx_multi").unwrap().unwrap().value_raw,
        500
    );

    // Second output with synthetic idx=0 but DIFFERENT commitment c1 -> gets idx=1, no collision!
    assert!(!db.note_exists_by_commitment("tx_multi", &c1).unwrap());
    let idx1 = db
        .resolve_note_output_index("tx_multi", 0, Some(&c1))
        .unwrap();
    assert_eq!(idx1, 1);
    db.insert_note(
        "tx_multi",
        idx1,
        700,
        &tok,
        &[2],
        100,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&c1),
        Some(&[2]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    db.upsert_incoming_transaction("tx_multi", 100, 700, &tok, None)
        .unwrap();

    let tx_row = db.get_transaction("tx_multi").unwrap().unwrap();
    assert_eq!(
        tx_row.value_raw, 1200,
        "multi-output incoming tx must sum all outputs"
    );
    assert_eq!(tx_row.memo.as_deref(), Some("split"));

    // Re-scanning is idempotent (no double-counting).
    assert!(db.note_exists_by_commitment("tx_multi", &c0).unwrap());
    db.upsert_incoming_transaction("tx_multi", 100, 500, &tok, Some("split"))
        .unwrap();
    assert_eq!(
        db.get_transaction("tx_multi").unwrap().unwrap().value_raw,
        1200
    );
}

#[test]
fn test_insert_and_list_addresses() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_address("addr1_public_key_hex", &[1, 2, 3])
        .unwrap();
    db.insert_address("addr2_public_key_hex", &[4, 5, 6])
        .unwrap();
    db.set_default_address("addr1_public_key_hex").unwrap();

    let addrs = db.list_addresses().unwrap();
    assert_eq!(addrs.len(), 2);
    assert_eq!(addrs[0].0, "addr1_public_key_hex");
    assert!(addrs[0].1); // is_default

    let def = db.get_default_address().unwrap();
    assert_eq!(def, Some("addr1_public_key_hex".to_string()));
}

#[test]
fn test_insert_note_and_balance() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_note(
        "txhash1",
        0,
        1000,
        "DRK",
        &[1, 2, 3, 4],
        100,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&[1, 2, 3, 4]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    db.insert_note(
        "txhash2",
        0,
        500,
        "DRK",
        &[5, 6, 7, 8],
        101,
        Some("test memo"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&[5, 6, 7, 8]),
        Some(&[9u8; 32]),
    )
    .unwrap();

    let balance = db.confirmed_balance("DRK").unwrap();
    assert_eq!(balance, 1500);

    let unspent = db.list_unspent().unwrap();
    assert_eq!(unspent.len(), 2);
}

#[test]
fn test_mark_spent_reduces_balance() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_note(
        "tx1",
        0,
        1000,
        "DRK",
        &[1, 2, 3, 4],
        100,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&[1, 2, 3, 4]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    db.insert_note(
        "tx2",
        0,
        500,
        "DRK",
        &[5, 6, 7, 8],
        101,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&[5, 6, 7, 8]),
        Some(&[9u8; 32]),
    )
    .unwrap();

    db.mark_note_spent(&[1, 2, 3, 4]).unwrap();

    let balance = db.confirmed_balance("DRK").unwrap();
    assert_eq!(balance, 500);
}

#[test]
fn test_release_stale_reservations_keeps_confirmed_spends() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_note(
        "reserved",
        0,
        1000,
        "DRK",
        &[1],
        10,
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
        "confirmed",
        0,
        2000,
        "DRK",
        &[2],
        11,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&[2]),
        Some(&[8u8; 32]),
    )
    .unwrap();
    assert_eq!(db.reserve_note(&[1], 100).unwrap(), 1);
    assert_eq!(db.mark_note_spent_at(&[2], Some(100)).unwrap(), 1);
    // Still inside the grace window.
    assert_eq!(db.release_stale_reservations(107, 8).unwrap(), 0);
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);
    // Chain moved on; the unconfirmed reservation is spendable again.
    assert_eq!(db.release_stale_reservations(109, 8).unwrap(), 1);
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 1000);
    // Confirmed spend stays spent.
    assert_eq!(db.release_stale_reservations(200, 8).unwrap(), 0);
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 1000);
}

#[test]
fn test_mark_spent_by_commitment_and_loc() {
    let db = WalletDb::in_memory().unwrap();
    let commit_a = [0xAAu8; 32];
    let commit_b = [0xBBu8; 32];
    db.insert_note(
        "aabbccdd1111",
        0,
        1000,
        "DRK",
        &[1, 2, 3, 4],
        100,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&commit_a),
        Some(&[1, 2, 3, 4]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    db.insert_note(
        "ccddeeff2222",
        1,
        500,
        "DRK",
        &[5, 6, 7, 8],
        101,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&commit_b),
        Some(&[5, 6, 7, 8]),
        Some(&[9u8; 32]),
    )
    .unwrap();

    assert_eq!(db.mark_note_spent_by_commitment(&commit_a).unwrap(), 1);
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 500);
    assert_eq!(db.mark_note_spent_by_loc("ccddeeff", 1).unwrap(), 1);
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);
    assert_eq!(db.list_unspent().unwrap().len(), 0);
}

#[test]
fn test_sync_state_update() {
    let db = WalletDb::in_memory().unwrap();
    db.set_sync_height(42).unwrap();
    db.set_birthday_height(10).unwrap();

    let (height, birthday) = db.get_sync_state().unwrap();
    assert_eq!(height, 42);
    assert_eq!(birthday, 10);
}

#[test]
fn test_prune_spent_notes() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_note(
        "tx1",
        0,
        100,
        "DRK",
        &[1],
        50,
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
        60,
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
    db.mark_note_spent_at(&[1], Some(52)).unwrap();

    let pruned = db.prune_spent_below(55).unwrap();
    assert_eq!(pruned, 1);

    // Unspent note still there
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 200);
}

#[test]
fn test_prune_spent_below_preserves_reserved_and_recently_spent_old_coins() {
    let db = WalletDb::in_memory().unwrap();
    // Old coin (height 10) reserved at broadcast (spent_height IS NULL).
    db.insert_note(
        "tx_reserved",
        0,
        100,
        "DRK",
        &[1],
        10,
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
    db.reserve_note(&[1], 1000).unwrap();

    // Old coin (height 10) spent recently at height 950.
    db.insert_note(
        "tx_recent",
        0,
        200,
        "DRK",
        &[2],
        10,
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
    db.mark_note_spent_at(&[2], Some(950)).unwrap();

    // Old coin (height 10) spent long ago at height 100.
    db.insert_note(
        "tx_old",
        0,
        300,
        "DRK",
        &[3],
        10,
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
    db.mark_note_spent_at(&[3], Some(100)).unwrap();

    let pruned = db.prune_spent_below(500).unwrap();
    assert_eq!(pruned, 1, "only tx_old spent at 100 should be pruned");

    let count: i64 = db
        .conn
        .query_row("SELECT COUNT(*) FROM notes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        count, 2,
        "reserved and recently spent old coins must remain"
    );
}

#[test]
fn test_metadata_roundtrip() {
    let db = WalletDb::in_memory().unwrap();
    db.set_meta("seed_hash", &[0xDE, 0xAD]).unwrap();
    let val = db.get_meta("seed_hash").unwrap();
    assert_eq!(val, Some(vec![0xDE, 0xAD]));

    assert_eq!(db.get_meta("nonexistent").unwrap(), None);
}

#[test]
fn test_duplicate_note_ignored() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_note(
        "tx1",
        0,
        100,
        "DRK",
        &[1],
        50,
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
    // Same tx_hash + output_index should be ignored (INSERT OR IGNORE)
    db.insert_note(
        "tx1",
        0,
        999,
        "DRK",
        &[1],
        50,
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

    let balance = db.confirmed_balance("DRK").unwrap();
    assert_eq!(balance, 100); // Not 999
}

#[test]
fn test_invalidate_above_height_removes_notes() {
    let db = WalletDb::in_memory().unwrap();
    for (h, ser) in [(100u32, &[10u8][..]), (200, &[20u8]), (300, &[30u8])] {
        db.insert_note(
            &format!("tx_{h}"),
            0,
            1000,
            "DRK",
            ser,
            h,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(ser),
            Some(&[9u8; 32]),
        )
        .unwrap();
    }
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 3000);

    let (notes_del, _) = db.invalidate_above_height(150).unwrap();
    assert_eq!(notes_del, 2);
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 1000);
    let (sync_h, _) = db.get_sync_state().unwrap();
    assert_eq!(sync_h, 150);
}

#[test]
fn test_invalidate_above_height_unspends_coins() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_note(
        "tx_lo",
        0,
        500,
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
        "tx_hi",
        0,
        300,
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
    // Spent in a block that the rewind keeps (height 80).
    db.mark_note_spent_at(&[1], Some(80)).unwrap();
    // Spent in a block the rewind orphans (height 200).
    db.mark_note_spent_at(&[2], Some(200)).unwrap();
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);

    db.invalidate_above_height(150).unwrap();
    // The height-200 note is deleted. The height-100 note was spent at 80,
    // which is still canonical, so it stays spent.
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);

    db.insert_note(
        "tx_reorg_spend",
        0,
        700,
        "DRK",
        &[3],
        120,
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
    db.mark_note_spent_at(&[3], Some(180)).unwrap();
    db.invalidate_above_height(150).unwrap();
    // Spend was above the fork, so the coin is unspent again.
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 700);
}

#[test]
fn test_invalidate_above_height_removes_transactions() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_transaction("hash_100", 100, "incoming", 1000, "DRK", None, None)
        .unwrap();
    db.insert_transaction("hash_200", 200, "outgoing", 500, "DRK", None, None)
        .unwrap();
    db.insert_transaction("hash_300", 300, "incoming", 200, "DRK", None, None)
        .unwrap();

    let (_, txs_del) = db.invalidate_above_height(150).unwrap();
    assert_eq!(txs_del, 2);

    let remaining = db.list_transactions(100).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].hash, "hash_100");
}

#[test]
fn test_insert_transaction_promotes_mempool_height() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_transaction(
        "685d3b0f",
        0,
        "outgoing",
        1_000_000,
        "DRK",
        None,
        Some("e2e"),
    )
    .unwrap();
    db.insert_transaction("685d3b0f", 62369, "incoming", 4_000_000, "DRK", None, None)
        .unwrap();
    let tx = db.get_transaction("685d3b0f").unwrap().expect("row");
    assert_eq!(tx.block_height, 62369);
    assert_eq!(tx.direction, "outgoing");
    assert_eq!(tx.memo.as_deref(), Some("e2e"));

    db.insert_transaction("aabbccdd", 0, "outgoing", 1, "DRK", None, None)
        .unwrap();
    assert_eq!(db.confirm_transaction("aabbccdd", 61675).unwrap(), 1);
    assert_eq!(
        db.get_transaction("aabbccdd")
            .unwrap()
            .unwrap()
            .block_height,
        61675
    );
}

#[test]
fn test_reset_for_rescan_wipes_everything() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_note(
        "tx1",
        0,
        1000,
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
    db.insert_transaction("hash1", 100, "incoming", 1000, "DRK", None, None)
        .unwrap();
    db.set_meta("tree_state", &[0xFF; 64]).unwrap();
    db.set_sync_height(100).unwrap();

    db.set_meta("trial_synced_height", &500u32.to_le_bytes())
        .unwrap();
    db.reset_for_rescan(0).unwrap();

    assert_eq!(db.confirmed_balance("DRK").unwrap(), 0);
    assert_eq!(db.get_meta("trial_synced_height").unwrap(), None);
    assert!(db.list_transactions(100).unwrap().is_empty());
    assert_eq!(db.get_meta("tree_state").unwrap(), None);
    assert!(!db.merkle_from_genesis());
    let (h, _) = db.get_sync_state().unwrap();
    assert_eq!(h, 0);
}

#[test]
fn test_merkle_from_genesis_flag_roundtrip() {
    let db = WalletDb::in_memory().unwrap();
    assert!(!db.merkle_from_genesis());
    db.set_merkle_from_genesis(true).unwrap();
    assert!(db.merkle_from_genesis());
    db.set_meta("tree_state", &[0xFF; 8]).unwrap();
    db.reset_for_rescan(52999).unwrap();
    assert!(!db.merkle_from_genesis());
    assert_eq!(db.get_meta("tree_state").unwrap(), None);
}

#[test]
fn test_invalidate_clears_merkle_state_and_clamps_trial_cursor() {
    let db = WalletDb::in_memory().unwrap();
    db.set_meta("tree_state", &[0xAA; 16]).unwrap();
    db.set_merkle_from_genesis(true).unwrap();
    db.set_meta("trial_synced_height", &6_000u32.to_le_bytes())
        .unwrap();
    db.set_meta("tree_applied_height", &6_000u32.to_le_bytes())
        .unwrap();
    db.record_synced_block_hash(90, &[0x11; 32]).unwrap();
    db.record_synced_block_hash(120, &[0x22; 32]).unwrap();
    db.insert_note(
        "tx_keep",
        0,
        500,
        "DRK",
        &[7],
        50,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(42),
        Some(&[8u8; 32]),
        Some(&[7]),
        Some(&[9u8; 32]),
    )
    .unwrap();

    db.invalidate_above_height(100).unwrap();
    assert_eq!(db.get_meta("tree_state").unwrap(), None);
    assert_eq!(db.get_meta("tree_applied_height").unwrap(), None);
    assert!(!db.merkle_from_genesis());
    assert_eq!(
        db.get_meta("trial_synced_height").unwrap().unwrap(),
        100u32.to_le_bytes()
    );
    assert_eq!(db.get_last_synced_hash().unwrap(), Some((90, [0x11; 32])));
    let leaf_pos: Option<u32> = db
        .conn
        .query_row(
            "SELECT leaf_position FROM notes WHERE tx_hash = 'tx_keep'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(leaf_pos, None, "leaf_position must be cleared on reorg");
}

#[test]
fn test_list_unspent_for_dao_requires_both_hook_and_bulla() {
    let db = WalletDb::in_memory().unwrap();
    let hook_dao = [0xA1u8; 32];
    let hook_other = [0xB2u8; 32];
    let bulla_a = [0x11u8; 32];
    let bulla_b = [0x22u8; 32];

    // DAO A treasury coin (matches hook_dao + bulla_a).
    db.insert_note(
        "tx_dao_a",
        0,
        1000,
        "DRK",
        &[1],
        10,
        None,
        None,
        None,
        None,
        Some(hook_dao[0]),
        Some(&bulla_a),
        Some(1),
        Some(&[1u8; 32]),
        Some(&[1]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    db.set_spend_hook_bytes("tx_dao_a", 0, &hook_dao).unwrap();

    // DAO B treasury coin (same hook_dao, different bulla_b).
    db.insert_note(
        "tx_dao_b",
        0,
        2000,
        "DRK",
        &[2],
        11,
        None,
        None,
        None,
        None,
        Some(hook_dao[0]),
        Some(&bulla_b),
        Some(2),
        Some(&[2u8; 32]),
        Some(&[2]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    db.set_spend_hook_bytes("tx_dao_b", 0, &hook_dao).unwrap();

    // Unrelated hooked coin sharing bulla_a but different spend_hook.
    db.insert_note(
        "tx_other_hook",
        0,
        3000,
        "DRK",
        &[3],
        12,
        None,
        None,
        None,
        None,
        Some(hook_other[0]),
        Some(&bulla_a),
        Some(3),
        Some(&[3u8; 32]),
        Some(&[3]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    db.set_spend_hook_bytes("tx_other_hook", 0, &hook_other)
        .unwrap();

    let dao_a_coins = db.list_unspent_for_dao(&hook_dao, &bulla_a).unwrap();
    assert_eq!(dao_a_coins.len(), 1);
    assert_eq!(dao_a_coins[0].0, "tx_dao_a");
    assert_eq!(dao_a_coins[0].2, 1000);

    let dao_b_coins = db.list_unspent_for_dao(&hook_dao, &bulla_b).unwrap();
    assert_eq!(dao_b_coins.len(), 1);
    assert_eq!(dao_b_coins[0].0, "tx_dao_b");
    assert_eq!(dao_b_coins[0].2, 2000);

    // Hooked DAO coins must never appear in ordinary spendable queries.
    assert!(db.list_unspent().unwrap().is_empty());
    assert!(db.list_unspent_full().unwrap().is_empty());
}

#[test]
fn test_list_token_balances_resolves_alias_across_hex_and_base58() {
    use darkfi_money_contract::model::TokenId;
    use std::str::FromStr;

    let db = WalletDb::in_memory().unwrap();
    let b58_id = "DkKtPmBw2LKCpo5KXq5RKR7Cp3V4pTzVchtJ4kJaPjpK";
    let id = TokenId::from_str(b58_id).unwrap();
    let hex_id = hex::encode(id.to_bytes());

    db.insert_token_mint(b58_id, &[1u8; 32], &[2u8; 32], Some("ANON"))
        .unwrap();
    db.insert_note(
        "tx_tok",
        0,
        555_000,
        &hex_id,
        &[1],
        50,
        None,
        None,
        None,
        None,
        Some(0),
        None,
        Some(1),
        Some(&[7u8; 32]),
        Some(&[1]),
        Some(&[9u8; 32]),
    )
    .unwrap();

    let balances = db.list_token_balances().unwrap();
    assert_eq!(balances.len(), 1);
    assert_eq!(balances[0].0, hex_id);
    assert_eq!(balances[0].1.as_deref(), Some("ANON"));
    assert_eq!(balances[0].2, 555_000);
}

#[test]
fn test_reimport_preserves_freeze_and_lock_state_and_prefers_unfrozen() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_token_mint("tok_a", &[1u8; 32], &[2u8; 32], Some("SHARED"))
        .unwrap();
    db.set_token_frozen("tok_a", Some(123)).unwrap();
    // Re-importing must preserve is_frozen and freeze_height.
    db.insert_token_mint("tok_a", &[1u8; 32], &[2u8; 32], None)
        .unwrap();
    let rows = db.list_token_mints().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].3.as_deref(), Some("SHARED"));
    assert!(rows[0].4, "is_frozen must be preserved on re-import");
    assert_eq!(rows[0].5, Some(123), "freeze_height must be preserved");

    // Second mint sharing alias "SHARED" (unfrozen) must win get_token_mint.
    db.insert_token_mint("tok_b", &[3u8; 32], &[4u8; 32], Some("SHARED"))
        .unwrap();
    let picked = db.get_token_mint("SHARED").unwrap().unwrap();
    assert_eq!(picked.0, "tok_b");
    assert!(!picked.3);

    // Same preservation check for deploy_auths.
    db.insert_deploy_auth("cid_1", &[5u8; 32]).unwrap();
    db.set_deploy_locked("cid_1", Some(456)).unwrap();
    db.insert_deploy_auth("cid_1", &[5u8; 32]).unwrap();
    let auths = db.list_deploy_auths().unwrap();
    assert_eq!(auths, vec![("cid_1".to_string(), true, Some(456))]);
}

#[test]
fn test_get_all_secrets_orders_default_first() {
    let db = WalletDb::in_memory().unwrap();
    db.insert_address("addr_first", &[1u8; 32]).unwrap();
    db.insert_address("addr_second", &[2u8; 32]).unwrap();
    db.set_default_address("addr_second").unwrap();
    let secrets = db.get_all_secrets().unwrap();
    assert_eq!(secrets[0], vec![2u8; 32]);
    assert_eq!(secrets[1], vec![1u8; 32]);
}

#[test]
fn test_invalidate_empty_db_succeeds() {
    let db = WalletDb::in_memory().unwrap();
    let (notes, txs) = db.invalidate_above_height(0).unwrap();
    assert_eq!(notes, 0);
    assert_eq!(txs, 0);
}

#[test]
fn test_zeroblob_spend_hook_bytes_count_as_unhooked() {
    let db = WalletDb::in_memory().unwrap();
    let drk = WalletDb::dark_token_id_hex();
    db.insert_note(
        "tx-zero-hook",
        0,
        2_000_000_000,
        &drk,
        &[1, 2, 3, 4],
        50,
        None,
        None,
        None,
        None,
        Some(0),
        None,
        Some(1),
        Some(&[7u8; 32]),
        Some(&[1, 2, 3, 4]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    // Compact sync stores FuncId::none() as 32 zero bytes, not NULL/empty.
    db.set_spend_hook_bytes("tx-zero-hook", 0, &[0u8; 32])
        .unwrap();
    assert_eq!(db.confirmed_balance("DRK").unwrap(), 2_000_000_000);
    let listed = db.list_token_balances().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(WalletDb::is_drk_token(&listed[0].0));
    assert_eq!(listed[0].2, 2_000_000_000);
}

#[test]
fn confirmed_balance_matches_base58_token_id_to_hex_note() {
    use std::str::FromStr;

    use darkfi_money_contract::model::TokenId;

    let db = WalletDb::in_memory().unwrap();
    let id = TokenId::from_str("DkKtPmBw2LKCpo5KXq5RKR7Cp3V4pTzVchtJ4kJaPjpK").unwrap();
    let hex_id = hex::encode(id.to_bytes());
    assert_eq!(
        WalletDb::token_id_hex("DkKtPmBw2LKCpo5KXq5RKR7Cp3V4pTzVchtJ4kJaPjpK").as_deref(),
        Some(hex_id.as_str())
    );
    db.insert_note(
        "tx-omr2",
        0,
        100_000_000,
        &hex_id,
        &[1, 2, 3, 4],
        50,
        None,
        None,
        None,
        None,
        Some(0),
        None,
        Some(1),
        Some(&[7u8; 32]),
        Some(&[1, 2, 3, 4]),
        Some(&[9u8; 32]),
    )
    .unwrap();
    assert_eq!(
        db.confirmed_balance("DkKtPmBw2LKCpo5KXq5RKR7Cp3V4pTzVchtJ4kJaPjpK")
            .unwrap(),
        100_000_000
    );
}
