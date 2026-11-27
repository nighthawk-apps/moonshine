use super::*;

impl WalletDb {
    /// Open or create the wallet database at the given path.
    pub fn open(path: &str) -> SqlResult<Self> {
        let passphrase = crate::secret_wrap::load_or_create_passphrase(path)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                crate::secret_wrap::ensure_dir_0700(parent)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            }
        }
        let conn = Connection::open(path)?;
        crate::secret_wrap::set_file_mode_0600(Path::new(path))
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        // SQLCipher: unlock / encrypt the database with the wallet passphrase.
        conn.pragma_update(None, "key", passphrase.as_str())?;
        let mut db = Self {
            conn,
            wrap_key: [0u8; 32],
        };
        db.initialize()?;
        let _ = crate::secret_wrap::set_file_mode_0600(Path::new(&format!("{path}-wal")));
        let _ = crate::secret_wrap::set_file_mode_0600(Path::new(&format!("{path}-shm")));
        // The wrap key lives inside the encrypted DB. A legacy `{path}.wrapkey`
        // file is imported once, then removed so the key is not sitting beside
        // the ciphertext. Legacy unsalted / MSK1 meta keys are upgraded in place.
        if let Some(stored) = db.get_meta(crate::secret_wrap::META_WRAP_KEY)? {
            let salt = db.get_meta(crate::secret_wrap::META_PASS_SALT)?;
            let kdf_meta = db.get_meta(crate::secret_wrap::META_PASS_KDF)?;
            let (wrap_key, needs_rekey, kdf_used) = crate::secret_wrap::unwrap_meta_wrap_key(
                &stored,
                &passphrase,
                salt.as_deref(),
                kdf_meta.as_deref(),
            )
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            if needs_rekey {
                let new_salt = crate::secret_wrap::random_pass_salt();
                // Keep the KDF that opened this wallet. Existing auto-generated
                // hex keys stay on blake3; do not switch them to argon2id.
                crate::secret_wrap::store_wrap_key_in_meta(
                    |k, v| db.set_meta(k, v).map_err(|e| e.to_string()),
                    &wrap_key,
                    &passphrase,
                    &new_salt,
                    kdf_used,
                )
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                let stored2 = db
                    .get_meta(crate::secret_wrap::META_WRAP_KEY)?
                    .ok_or_else(|| {
                        rusqlite::Error::ToSqlConversionFailure(
                            "wrap key missing after MSK2 re-key".into(),
                        )
                    })?;
                let salt2 = db.get_meta(crate::secret_wrap::META_PASS_SALT)?;
                let kdf_meta2 = db.get_meta(crate::secret_wrap::META_PASS_KDF)?;
                let (mut check, still_legacy, _) = crate::secret_wrap::unwrap_meta_wrap_key(
                    &stored2,
                    &passphrase,
                    salt2.as_deref(),
                    kdf_meta2.as_deref(),
                )
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if check != wrap_key || still_legacy {
                    check.zeroize();
                    return Err(rusqlite::Error::ToSqlConversionFailure(
                        "wrap key MSK2 re-key round-trip mismatch".into(),
                    ));
                }
                check.zeroize();
            }
            db.wrap_key = wrap_key;
            db.migrate_secrets_to_v2()?;
            crate::secret_wrap::delete_legacy_wrap_key(path);
            return Ok(db);
        }
        let mut wrap_key = match crate::secret_wrap::read_legacy_wrap_key(path)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?
        {
            Some(key) => key,
            None => crate::secret_wrap::random_wrap_key(),
        };
        let pass_salt = crate::secret_wrap::random_pass_salt();
        // `load_or_create_passphrase` only returns a user-supplied passphrase
        // (`MOONSHINE_WALLET_PASS` or `{db}.pass`), including 64 hex characters.
        // New wallets record argon2id. Older 64-hex wallets stay on the blake3
        // heuristic until `pass_kdf` is written.
        let kdf = crate::secret_wrap::PassKdf::Argon2id;
        crate::secret_wrap::store_wrap_key_in_meta(
            |k, v| db.set_meta(k, v).map_err(|e| e.to_string()),
            &wrap_key,
            &passphrase,
            &pass_salt,
            kdf,
        )
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        // Confirm the meta copy unwraps before deleting the sidecar.
        let stored = db
            .get_meta(crate::secret_wrap::META_WRAP_KEY)?
            .ok_or_else(|| {
                rusqlite::Error::ToSqlConversionFailure(
                    "wrap key missing from wallet_meta after store".into(),
                )
            })?;
        let stored_salt = db.get_meta(crate::secret_wrap::META_PASS_SALT)?;
        let stored_kdf = db.get_meta(crate::secret_wrap::META_PASS_KDF)?;
        let (mut check, still_legacy, _) = crate::secret_wrap::unwrap_meta_wrap_key(
            &stored,
            &passphrase,
            stored_salt.as_deref(),
            stored_kdf.as_deref(),
        )
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        if check != wrap_key || still_legacy {
            wrap_key.zeroize();
            check.zeroize();
            return Err(rusqlite::Error::ToSqlConversionFailure(
                "wrap key round-trip mismatch".into(),
            ));
        }
        db.wrap_key = wrap_key;
        wrap_key.zeroize();
        check.zeroize();
        db.migrate_secrets_to_v2()?;
        crate::secret_wrap::delete_legacy_wrap_key(path);
        Ok(db)
    }

    /// Open an in-memory database for testing.
    #[cfg(test)]
    pub fn in_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "key", crate::secret_wrap::test_passphrase())?;
        let db = Self {
            conn,
            wrap_key: crate::secret_wrap::test_wrap_key(),
        };
        db.initialize()?;
        Ok(db)
    }

    /// Create all tables if they don't exist.
    pub(super) fn initialize(&self) -> SqlResult<()> {
        // S14: overwrite deleted pages; use WAL for crash-safe writes.
        self.conn.execute_batch(
            "
            PRAGMA secure_delete = ON;
            PRAGMA journal_mode = WAL;
            ",
        )?;
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS wallet_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key TEXT NOT NULL UNIQUE,
                secret_key BLOB NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_hash TEXT NOT NULL,
                output_index INTEGER NOT NULL,
                value_raw INTEGER NOT NULL,
                token_id TEXT NOT NULL,
                serial_number BLOB NOT NULL,
                nullifier BLOB,
                block_height INTEGER NOT NULL,
                spent INTEGER NOT NULL DEFAULT 0,
                memo TEXT,
                coin_blind BLOB,
                value_blind BLOB,
                token_blind BLOB,
                spend_hook INTEGER,
                spend_hook_bytes BLOB,
                user_data BLOB,
                leaf_position INTEGER,
                commitment BLOB,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(tx_hash, output_index)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                hash TEXT PRIMARY KEY,
                block_height INTEGER NOT NULL,
                direction TEXT NOT NULL, -- 'incoming' or 'outgoing'
                value_raw INTEGER NOT NULL,
                token_id TEXT NOT NULL,
                counterparty TEXT,
                memo TEXT,
                kind TEXT NOT NULL DEFAULT 'transfer',
                timestamp TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                last_synced_height INTEGER NOT NULL DEFAULT 0,
                birthday_height INTEGER NOT NULL DEFAULT 0,
                last_sync_timestamp TEXT
            );

            INSERT OR IGNORE INTO sync_state (id, last_synced_height, birthday_height)
            VALUES (1, 0, 0);

            CREATE TABLE IF NOT EXISTS dao_calls (
                height INTEGER NOT NULL,
                tx_hash BLOB NOT NULL,
                kind INTEGER NOT NULL,
                bulla BLOB NOT NULL,
                payload BLOB NOT NULL,
                PRIMARY KEY (height, tx_hash, kind, bulla)
            );

            CREATE TABLE IF NOT EXISTS func_events (
                height INTEGER NOT NULL,
                tx_hash BLOB NOT NULL,
                func_code INTEGER NOT NULL,
                PRIMARY KEY (height, tx_hash, func_code)
            );

            CREATE TABLE IF NOT EXISTS token_mints (
                token_id TEXT PRIMARY KEY,
                mint_authority BLOB NOT NULL,
                token_blind BLOB NOT NULL,
                alias TEXT,
                is_frozen INTEGER NOT NULL DEFAULT 0,
                freeze_height INTEGER
            );

            CREATE TABLE IF NOT EXISTS dao_records (
                name TEXT PRIMARY KEY,
                params_toml TEXT NOT NULL,
                bulla TEXT,
                tx_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS deploy_auths (
                contract_id TEXT PRIMARY KEY,
                secret_key BLOB NOT NULL,
                is_locked INTEGER NOT NULL DEFAULT 0,
                lock_height INTEGER
            );

            CREATE TABLE IF NOT EXISTS dao_proposals (
                proposal_bulla TEXT PRIMARY KEY,
                dao_bulla TEXT NOT NULL,
                proposal_bytes BLOB NOT NULL,
                coin_attrs_bytes BLOB,
                mint_height INTEGER,
                tx_hash TEXT,
                exec_height INTEGER,
                exec_tx_hash TEXT
            );
        ",
        )?;
        self.migrate_notes_columns()?;
        Ok(())
    }

    /// One-time atomic upgrade of legacy `MSK1` or plaintext secret columns to `MSK2`
    /// (`XChaCha20Poly1305`). Safe to call repeatedly (idempotent when already `MSK2`).
    pub fn migrate_secrets_to_v2(&self) -> SqlResult<usize> {
        let mut upgraded = 0usize;
        let tx = self.conn.unchecked_transaction()?;

        // 1. addresses.secret_key
        {
            let mut stmt = tx.prepare("SELECT id, secret_key FROM addresses")?;
            let rows: Vec<(i64, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (id, stored) in rows {
                let (mut plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE addresses SET secret_key = ?1 WHERE id = ?2",
                        params![wrapped, id],
                    )?;
                    upgraded += 1;
                }
                plain.zeroize();
            }
        }

        // 2. notes.owner_secret
        {
            let mut stmt =
                tx.prepare("SELECT id, owner_secret FROM notes WHERE owner_secret IS NOT NULL")?;
            let rows: Vec<(i64, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (id, stored) in rows {
                let (mut plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE notes SET owner_secret = ?1 WHERE id = ?2",
                        params![wrapped, id],
                    )?;
                    upgraded += 1;
                }
                plain.zeroize();
            }
        }

        // 3. wallet_meta['derivation_seed']
        {
            let mut stmt =
                tx.prepare("SELECT value FROM wallet_meta WHERE key = 'derivation_seed'")?;
            let existing: Option<Vec<u8>> = stmt.query_map([], |r| r.get(0))?.next().transpose()?;
            drop(stmt);
            if let Some(stored) = existing {
                let (mut plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE wallet_meta SET value = ?1 WHERE key = 'derivation_seed'",
                        params![wrapped],
                    )?;
                    upgraded += 1;
                }
                plain.zeroize();
            }
        }

        // 4. token_mints (mint_authority + token_blind)
        {
            let mut stmt =
                tx.prepare("SELECT token_id, mint_authority, token_blind FROM token_mints")?;
            let rows: Vec<(String, Vec<u8>, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (tid, auth_stored, blind_stored) in rows {
                let (mut auth_plain, auth_rw) =
                    crate::secret_wrap::unwrap_secret_for_migration(&auth_stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                let (mut blind_plain, blind_rw) =
                    crate::secret_wrap::unwrap_secret_for_migration(&blind_stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if auth_rw || blind_rw {
                    let auth_w = crate::secret_wrap::wrap_secret(&auth_plain, &self.wrap_key);
                    let blind_w = crate::secret_wrap::wrap_secret(&blind_plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE token_mints SET mint_authority = ?1, token_blind = ?2 WHERE token_id = ?3",
                        params![auth_w, blind_w, tid],
                    )?;
                    upgraded += 1;
                }
                auth_plain.zeroize();
                blind_plain.zeroize();
            }
        }

        // 5. deploy_auths.secret_key
        {
            let mut stmt = tx.prepare("SELECT contract_id, secret_key FROM deploy_auths")?;
            let rows: Vec<(String, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (cid, stored) in rows {
                let (mut plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE deploy_auths SET secret_key = ?1 WHERE contract_id = ?2",
                        params![wrapped, cid],
                    )?;
                    upgraded += 1;
                }
                plain.zeroize();
            }
        }

        // 6. dao_records.params_toml
        {
            let mut stmt = tx.prepare("SELECT name, params_toml FROM dao_records")?;
            let rows: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<SqlResult<_>>()?;
            drop(stmt);
            for (name, stored) in rows {
                let (mut plain, needs_rewrite) =
                    crate::secret_wrap::unwrap_secret_text_for_migration(&stored, &self.wrap_key)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                if needs_rewrite {
                    let wrapped = crate::secret_wrap::wrap_secret_text(&plain, &self.wrap_key);
                    tx.execute(
                        "UPDATE dao_records SET params_toml = ?1 WHERE name = ?2",
                        params![wrapped, name],
                    )?;
                    upgraded += 1;
                }
                plain.zeroize();
            }
        }

        tx.commit()?;
        Ok(upgraded)
    }

    /// Recompute each unspent note's commitment from note attributes + owner
    /// key (`CoinAttributes::to_coin`). Compact-block `output.coin` must match
    /// this; overwriting commitments with unrelated coins in the same block
    /// makes spend proofs use a Merkle root that is not on chain (Money 0x5).
    ///
    /// Returns `(checked, updated)`.
    #[allow(dead_code)]
    pub fn recompute_note_commitments(&self) -> SqlResult<(u32, u32)> {
        use darkfi_money_contract::model::{CoinAttributes, TokenId};
        use darkfi_sdk::crypto::{FuncId, PublicKey, SecretKey};
        use darkfi_sdk::pasta::pallas;
        use darkfi_serial::Decodable;

        let mut stmt = self.conn.prepare(
            "SELECT id, value_raw, token_id, coin_blind, spend_hook, spend_hook_bytes, user_data, \
             commitment, owner_secret FROM notes \
             WHERE spent = 0 AND owner_secret IS NOT NULL AND coin_blind IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })?;

        let mut checked = 0u32;
        let mut updated = 0u32;
        let mut updates: Vec<(i64, Vec<u8>)> = Vec::new();
        for row in rows {
            let (
                id,
                value_raw,
                tok_hex,
                coin_blind,
                hook_i,
                hook_bytes,
                user_data,
                old_commit,
                owner_stored,
            ) = row?;
            let hook = hook_i.unwrap_or(0) as u8;
            let Ok(owner) = crate::secret_wrap::unwrap_secret(&owner_stored, &self.wrap_key) else {
                continue;
            };
            if owner.len() < 32 || coin_blind.len() != 32 {
                continue;
            }
            let tok_bytes = match hex::decode(&tok_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => continue,
            };
            let mut tok_arr = [0u8; 32];
            tok_arr.copy_from_slice(&tok_bytes);
            let Ok(token_id) = TokenId::from_bytes(tok_arr) else {
                continue;
            };
            let mut sk_arr = [0u8; 32];
            sk_arr.copy_from_slice(&owner[..32]);
            let Ok(sk) = SecretKey::from_bytes(sk_arr) else {
                continue;
            };
            let mut cb_arr = [0u8; 32];
            cb_arr.copy_from_slice(&coin_blind);
            let Ok(coin_blind_f) = pallas::Base::decode(&mut std::io::Cursor::new(cb_arr)) else {
                continue;
            };
            let ud = user_data.unwrap_or_else(|| vec![0u8; 32]);
            if ud.len() != 32 {
                continue;
            }
            let mut ud_arr = [0u8; 32];
            ud_arr.copy_from_slice(&ud);
            let Ok(user_data_f) = pallas::Base::decode(&mut std::io::Cursor::new(ud_arr)) else {
                continue;
            };
            let mut hook_arr = [0u8; 32];
            match hook_bytes {
                Some(b) if b.len() == 32 => hook_arr.copy_from_slice(&b),
                _ => hook_arr[0] = hook,
            }
            let Ok(spend_hook) = FuncId::from_bytes(hook_arr) else {
                continue;
            };
            let derived = CoinAttributes {
                public_key: PublicKey::from_secret(sk),
                value: value_raw as u64,
                token_id,
                spend_hook,
                user_data: user_data_f,
                blind: darkfi_sdk::crypto::Blind(coin_blind_f),
            }
            .to_coin();
            let derived_bytes = derived.to_bytes().to_vec();
            checked += 1;
            if old_commit.as_deref() != Some(derived_bytes.as_slice()) {
                updates.push((id, derived_bytes));
                updated += 1;
            }
        }
        drop(stmt);
        for (id, bytes) in updates {
            self.conn.execute(
                "UPDATE notes SET commitment = ?1, leaf_position = NULL WHERE id = ?2",
                params![bytes, id],
            )?;
        }
        Ok((checked, updated))
    }

    pub fn update_leaf_position(&self, commitment: &[u8], leaf_position: u32) -> SqlResult<usize> {
        self.conn.execute(
            "UPDATE notes SET leaf_position = ?1 WHERE commitment = ?2 AND spent = 0",
            params![leaf_position, commitment],
        )
    }

    /// Return all 32-byte commitment blobs for unspent owned notes.
    /// Unlike `list_unspent_full`, this does NOT require `leaf_position` to be set,
    /// which is important during sync when notes are discovered before tree positions
    /// are assigned.
    pub fn list_owned_commitments(&self) -> SqlResult<Vec<Vec<u8>>> {
        let mut stmt = self.conn.prepare(
            "SELECT commitment FROM notes WHERE spent = 0 \
             AND commitment IS NOT NULL AND length(commitment) = 32",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect()
    }

    /// `(tx_hash, output_index, block_height)` for unspent notes.
    pub fn list_unspent_note_locs(&self) -> SqlResult<Vec<(String, u32, u32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT tx_hash, output_index, block_height FROM notes WHERE spent = 0 ORDER BY block_height",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, u32>(2)?,
            ))
        })?;
        rows.collect()
    }

    /// Overwrite a note's on-chain coin commitment (clears leaf_position).
    #[allow(dead_code)]
    pub fn set_note_commitment(
        &self,
        tx_hash: &str,
        output_index: u32,
        commitment: &[u8],
    ) -> SqlResult<usize> {
        self.conn.execute(
            "UPDATE notes SET commitment = ?1, leaf_position = NULL \
             WHERE tx_hash = ?2 AND output_index = ?3 AND spent = 0",
            params![commitment, tx_hash, output_index],
        )
    }

    pub fn set_spend_hook_bytes(
        &self,
        tx_hash: &str,
        output_index: u32,
        spend_hook_bytes: &[u8],
    ) -> SqlResult<usize> {
        self.conn.execute(
            "UPDATE notes SET spend_hook_bytes = ?1 \
             WHERE tx_hash = ?2 AND output_index = ?3 AND spent = 0",
            params![spend_hook_bytes, tx_hash, output_index],
        )
    }

    /// Refresh spend fields from a re-decrypted MoneyNote (plus on-chain coin).
    #[allow(clippy::too_many_arguments)]
    pub fn update_note_spend_fields(
        &self,
        tx_hash: &str,
        output_index: u32,
        value_raw: i64,
        token_id: &str,
        coin_blind: &[u8],
        value_blind: &[u8],
        token_blind: &[u8],
        spend_hook: u8,
        spend_hook_bytes: &[u8],
        user_data: &[u8],
        commitment: &[u8],
        owner_secret: &[u8],
    ) -> SqlResult<usize> {
        let wrapped_owner = crate::secret_wrap::wrap_secret(owner_secret, &self.wrap_key);
        self.conn.execute(
            "UPDATE notes SET value_raw = ?1, token_id = ?2, coin_blind = ?3, \
             value_blind = ?4, token_blind = ?5, spend_hook = ?6, spend_hook_bytes = ?7, \
             user_data = ?8, commitment = ?9, owner_secret = ?10, leaf_position = NULL \
             WHERE tx_hash = ?11 AND output_index = ?12 AND spent = 0",
            params![
                value_raw,
                token_id,
                coin_blind,
                value_blind,
                token_blind,
                spend_hook,
                spend_hook_bytes,
                user_data,
                commitment,
                wrapped_owner,
                tx_hash,
                output_index,
            ],
        )
    }

    /// Ensure migrated columns exist on older wallet DBs.
    pub fn insert_dao_call(
        &self,
        height: u32,
        tx_hash: &[u8],
        kind: u32,
        bulla: &[u8],
        payload: &[u8],
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO dao_calls (height, tx_hash, kind, bulla, payload) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![height, tx_hash, kind, bulla, payload],
        )?;
        Ok(())
    }

    pub fn insert_func_event(&self, height: u32, tx_hash: &[u8], func_code: u32) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO func_events (height, tx_hash, func_code) VALUES (?1, ?2, ?3)",
            rusqlite::params![height, tx_hash, func_code],
        )?;
        Ok(())
    }

    /// Synced compact DAO calls (most recent first).
    pub fn list_dao_calls(&self, limit: u32) -> SqlResult<Vec<DaoCallRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, tx_hash, kind, bulla FROM dao_calls \
             ORDER BY height DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        rows.collect()
    }

    /// Synced Money/DAO/deploy func markers (most recent first).
    pub fn list_func_events(&self, limit: u32) -> SqlResult<Vec<(u32, Vec<u8>, u32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, tx_hash, func_code FROM func_events \
             ORDER BY height DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
            ))
        })?;
        rows.collect()
    }

    pub fn insert_token_mint(
        &self,
        token_id: &str,
        mint_authority: &[u8],
        token_blind: &[u8],
        alias: Option<&str>,
    ) -> SqlResult<()> {
        let wrapped_auth = crate::secret_wrap::wrap_secret(mint_authority, &self.wrap_key);
        let wrapped_blind = crate::secret_wrap::wrap_secret(token_blind, &self.wrap_key);
        self.conn.execute(
            "INSERT INTO token_mints (token_id, mint_authority, token_blind, alias, is_frozen) \
             VALUES (?1, ?2, ?3, ?4, 0) \
             ON CONFLICT(token_id) DO UPDATE SET \
               mint_authority = excluded.mint_authority, \
               token_blind = excluded.token_blind, \
               alias = COALESCE(excluded.alias, token_mints.alias)",
            rusqlite::params![token_id, wrapped_auth, wrapped_blind, alias],
        )?;
        Ok(())
    }

    pub fn list_token_mints(&self) -> SqlResult<Vec<TokenMintRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT token_id, mint_authority, token_blind, alias, is_frozen, freeze_height \
             FROM token_mints ORDER BY alias IS NULL, alias, token_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)? != 0,
                row.get::<_, Option<u32>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (tid, auth_stored, blind_stored, alias, frozen, fh) = r?;
            let auth = crate::secret_wrap::unwrap_secret(&auth_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            let blind = crate::secret_wrap::unwrap_secret(&blind_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push((tid, auth, blind, alias, frozen, fh));
        }
        Ok(out)
    }

    pub fn get_token_mint(&self, token_or_alias: &str) -> SqlResult<Option<TokenMintLookup>> {
        let mut stmt = self.conn.prepare(
            "SELECT token_id, mint_authority, token_blind, is_frozen FROM token_mints \
             WHERE token_id = ?1 OR alias = ?1 \
             ORDER BY is_frozen ASC, token_id ASC \
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map([token_or_alias], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)? != 0,
            ))
        })?;
        match rows.next() {
            Some(Ok((tid, auth_stored, blind_stored, frozen))) => {
                let auth = crate::secret_wrap::unwrap_secret(&auth_stored, &self.wrap_key)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                let blind = crate::secret_wrap::unwrap_secret(&blind_stored, &self.wrap_key)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                Ok(Some((tid, auth, blind, frozen)))
            }
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub fn set_token_frozen(&self, token_id: &str, height: Option<u32>) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE token_mints SET is_frozen = 1, freeze_height = ?2 WHERE token_id = ?1",
            rusqlite::params![token_id, height],
        )?;
        Ok(())
    }

    pub fn upsert_dao_record(
        &self,
        name: &str,
        params_toml: &str,
        bulla: Option<&str>,
        tx_hash: Option<&str>,
    ) -> SqlResult<()> {
        let wrapped_toml = crate::secret_wrap::wrap_secret_text(params_toml, &self.wrap_key);
        self.conn.execute(
            "INSERT INTO dao_records (name, params_toml, bulla, tx_hash) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET
               params_toml = excluded.params_toml,
               bulla = COALESCE(excluded.bulla, dao_records.bulla),
               tx_hash = COALESCE(excluded.tx_hash, dao_records.tx_hash)",
            rusqlite::params![name, wrapped_toml, bulla, tx_hash],
        )?;
        Ok(())
    }

    pub fn list_dao_records(&self) -> SqlResult<Vec<DaoRecordRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, bulla, tx_hash FROM dao_records ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        rows.collect()
    }

    pub fn get_dao_toml(&self, name: &str) -> SqlResult<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT params_toml FROM dao_records WHERE name = ?1")?;
        let mut rows = stmt.query_map([name], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(Ok(stored)) => {
                let plain = crate::secret_wrap::unwrap_secret_text(&stored, &self.wrap_key)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                Ok(Some(plain))
            }
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub fn insert_deploy_auth(&self, contract_id: &str, secret_key: &[u8]) -> SqlResult<()> {
        let wrapped = crate::secret_wrap::wrap_secret(secret_key, &self.wrap_key);
        self.conn.execute(
            "INSERT INTO deploy_auths (contract_id, secret_key, is_locked) \
             VALUES (?1, ?2, 0) \
             ON CONFLICT(contract_id) DO UPDATE SET \
               secret_key = excluded.secret_key",
            rusqlite::params![contract_id, wrapped],
        )?;
        Ok(())
    }

    pub fn list_deploy_auths(&self) -> SqlResult<Vec<(String, bool, Option<u32>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT contract_id, is_locked, lock_height FROM deploy_auths ORDER BY contract_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? != 0,
                row.get::<_, Option<u32>>(2)?,
            ))
        })?;
        rows.collect()
    }

    pub fn get_deploy_auth(&self, contract_id: &str) -> SqlResult<Option<(Vec<u8>, bool)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret_key, is_locked FROM deploy_auths WHERE contract_id = ?1")?;
        let mut rows = stmt.query_map([contract_id], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)? != 0))
        })?;
        match rows.next() {
            Some(Ok((stored, locked))) => {
                let plain = crate::secret_wrap::unwrap_secret(&stored, &self.wrap_key)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                Ok(Some((plain, locked)))
            }
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub fn set_deploy_locked(&self, contract_id: &str, height: Option<u32>) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE deploy_auths SET is_locked = 1, lock_height = ?2 WHERE contract_id = ?1",
            rusqlite::params![contract_id, height],
        )?;
        Ok(())
    }
}
