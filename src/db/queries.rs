use super::*;

impl WalletDb {
    pub(super) fn migrate_notes_columns(&self) -> SqlResult<()> {
        let _ = self
            .conn
            .execute("ALTER TABLE notes ADD COLUMN owner_secret BLOB", []);
        let _ = self
            .conn
            .execute("ALTER TABLE notes ADD COLUMN spend_hook_bytes BLOB", []);
        // Height at which the nullifier was observed. Absent on rows spent
        // before this column existed; those stay spent across a reorg.
        let _ = self
            .conn
            .execute("ALTER TABLE notes ADD COLUMN spent_height INTEGER", []);
        // Height of the wallet tip when a broadcast reserved the note. Cleared
        // once the nullifier is seen on chain. Sync drops the reservation if
        // the chain moves on without that nullifier (mempool GC).
        let _ = self
            .conn
            .execute("ALTER TABLE notes ADD COLUMN reserved_height INTEGER", []);
        let _ = self.conn.execute(
            "ALTER TABLE transactions ADD COLUMN kind TEXT NOT NULL DEFAULT 'transfer'",
            [],
        );
        Ok(())
    }

    /// Rows changed by the last statement. `INSERT OR IGNORE` that skipped is 0.
    pub fn changed(&self) -> bool {
        self.conn.changes() > 0
    }

    /// Hex encoding of the native DRK token id (what sync stores).
    pub fn dark_token_id_hex() -> String {
        hex::encode(darkfi_money_contract::model::DARK_TOKEN_ID.to_bytes())
    }

    /// True if `token` is DRK display name or the on-wire hex token id.
    pub fn is_drk_token(token: &str) -> bool {
        token.eq_ignore_ascii_case("DRK") || token.eq_ignore_ascii_case(&Self::dark_token_id_hex())
    }

    /// Unspent notes with full fields for spend construction.
    /// Returns `(tx_hash, output_index, value, token_id, coin_blind, value_blind,
    /// token_blind, spend_hook_bytes, user_data, leaf_position, commitment, owner_secret)`.
    #[allow(clippy::type_complexity)]
    pub fn list_unspent_full(
        &self,
    ) -> SqlResult<
        Vec<(
            String,
            u32,
            i64,
            String,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            u32,
            Vec<u8>,
            Vec<u8>,
        )>,
    > {
        let is_unhooked = Self::sql_note_unhooked("");
        let query = format!(
            "SELECT tx_hash, output_index, value_raw, token_id, coin_blind, value_blind, token_blind, \
             spend_hook, spend_hook_bytes, user_data, leaf_position, commitment, owner_secret \
             FROM notes WHERE spent = 0 AND leaf_position IS NOT NULL \
             AND commitment IS NOT NULL AND length(commitment) = 32 \
             AND owner_secret IS NOT NULL AND {is_unhooked} \
             ORDER BY block_height"
        );
        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            let hook_i: u8 = row.get::<_, Option<u8>>(7)?.unwrap_or(0);
            let hook_bytes: Option<Vec<u8>> = row.get(8)?;
            let spend_hook = match hook_bytes {
                Some(b) if b.len() == 32 => b,
                _ => {
                    let mut b = vec![0u8; 32];
                    b[0] = hook_i;
                    b
                }
            };
            let owner_stored: Vec<u8> = row.get(12)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                spend_hook,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, u32>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                owner_stored,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (tx, idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner_stored) = row?;
            let owner = crate::secret_wrap::unwrap_secret(&owner_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push((
                tx, idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner,
            ));
        }
        Ok(out)
    }

    // =========================================================================
    // Wallet Metadata
    // =========================================================================

    /// Get or create a dedicated random 32-byte key for the companion `BlockCache`
    /// stored wrapped under `wrap_key` inside `wallet_meta`.
    pub fn block_cache_key(&self) -> SqlResult<[u8; 32]> {
        if let Some(mut existing) = self.get_wrapped_meta("block_cache_key")? {
            if existing.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&existing);
                existing.zeroize();
                return Ok(key);
            }
            existing.zeroize();
        }
        let key = crate::secret_wrap::random_wrap_key();
        self.set_wrapped_meta("block_cache_key", &key)?;
        Ok(key)
    }

    /// Atomically persist `tree_state`, `tree_applied_height`, and `merkle_from_genesis`
    /// in a single SQLite transaction so crashes cannot split cursor and tree state.
    pub fn save_money_tree_state(
        &self,
        tree_bytes: &[u8],
        applied_height: u32,
        merkle_from_genesis: bool,
    ) -> SqlResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES ('tree_state', ?1)",
            params![tree_bytes],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES ('tree_applied_height', ?1)",
            params![applied_height.to_le_bytes().as_slice()],
        )?;
        if merkle_from_genesis {
            tx.execute(
                "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES (?1, ?2)",
                params![Self::META_MERKLE_FROM_GENESIS, b"1".as_slice()],
            )?;
        } else {
            tx.execute(
                "DELETE FROM wallet_meta WHERE key = ?1",
                params![Self::META_MERKLE_FROM_GENESIS],
            )?;
        }
        tx.commit()
    }

    /// Set when the Money Merkle tree includes height-0 coins after the dummy
    /// ZERO leaf. Birthday rescan used to append only post-birthday coins onto
    /// a fresh dummy tree, so spend proofs published a root the contract never
    /// stored (Money `Custom(5)` / `TransferMerkleRootNotFound`).
    const META_MERKLE_FROM_GENESIS: &'static str = "merkle_from_genesis";

    pub fn merkle_from_genesis(&self) -> bool {
        matches!(self.get_meta(Self::META_MERKLE_FROM_GENESIS), Ok(Some(v)) if v == b"1")
    }

    pub fn set_merkle_from_genesis(&self, complete: bool) -> SqlResult<()> {
        if complete {
            self.set_meta(Self::META_MERKLE_FROM_GENESIS, b"1")
        } else {
            self.conn.execute(
                "DELETE FROM wallet_meta WHERE key = ?1",
                params![Self::META_MERKLE_FROM_GENESIS],
            )?;
            Ok(())
        }
    }

    /// Store a sensitive metadata value wrapped at rest (`MSK2`).
    pub fn set_wrapped_meta(&self, key: &str, value: &[u8]) -> SqlResult<()> {
        let wrapped = crate::secret_wrap::wrap_secret(value, &self.wrap_key);
        self.set_meta(key, &wrapped)
    }

    /// Retrieve and unwrap a sensitive metadata value (`MSK2`, fail-closed).
    pub fn get_wrapped_meta(&self, key: &str) -> SqlResult<Option<Vec<u8>>> {
        let Some(stored) = self.get_meta(key)? else {
            return Ok(None);
        };
        let plain = crate::secret_wrap::unwrap_secret(&stored, &self.wrap_key)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        Ok(Some(plain))
    }

    /// Store a key-value pair in wallet metadata.
    pub fn set_meta(&self, key: &str, value: &[u8]) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Retrieve a metadata value by key.
    pub fn get_meta(&self, key: &str) -> SqlResult<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM wallet_meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            let val: Vec<u8> = row.get(0)?;
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    // =========================================================================
    // Addresses
    // =========================================================================

    /// Insert a new address. The secret is wrapped at rest (S14).
    pub fn insert_address(&self, public_key: &str, secret_key: &[u8]) -> SqlResult<i64> {
        let wrapped = crate::secret_wrap::wrap_secret(secret_key, &self.wrap_key);
        self.conn.execute(
            "INSERT INTO addresses (public_key, secret_key) VALUES (?1, ?2)",
            params![public_key, wrapped],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Set the default address.
    pub fn set_default_address(&self, public_key: &str) -> SqlResult<()> {
        self.conn
            .execute("UPDATE addresses SET is_default = 0", [])?;
        self.conn.execute(
            "UPDATE addresses SET is_default = 1 WHERE public_key = ?1",
            params![public_key],
        )?;
        Ok(())
    }

    /// Get the default address.
    pub fn get_default_address(&self) -> SqlResult<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key FROM addresses WHERE is_default = 1 LIMIT 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let pk: String = row.get(0)?;
            Ok(Some(pk))
        } else {
            Ok(None)
        }
    }

    /// List all addresses.
    pub fn list_addresses(&self) -> SqlResult<Vec<(String, bool)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key, is_default FROM addresses ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
        })?;
        rows.collect()
    }

    /// Retrieve all address secret keys for trial decryption (default address first).
    pub fn get_all_secrets(&self) -> SqlResult<Vec<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret_key FROM addresses ORDER BY is_default DESC, id ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let stored = row?;
            let plain = crate::secret_wrap::unwrap_secret(&stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push(plain);
        }
        Ok(out)
    }

    /// All wallet address secrets (default first) plus deduplicated DAO treasury `notes_secret` keys
    /// for trial decryption across every sync / rebuild path.
    pub fn get_all_trial_decrypt_secrets(&self) -> SqlResult<Vec<Vec<u8>>> {
        let mut secrets = self.get_all_secrets()?;
        let dao_secrets = self.get_all_dao_notes_secrets().unwrap_or_default();
        for ds in dao_secrets {
            if !secrets.iter().any(|sk| sk == &ds) {
                secrets.push(ds);
            }
        }
        Ok(secrets)
    }

    /// Retrieve addresses with secrets for multi-pubkey OMR (S17).
    /// Returns `(public_key_str, secret_key_bytes, is_default)` ordered by id.
    pub fn get_all_address_keys(&self) -> SqlResult<Vec<(String, Vec<u8>, bool)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key, secret_key, is_default FROM addresses ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (pk, stored, is_default) = row?;
            let plain = crate::secret_wrap::unwrap_secret(&stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push((pk, plain, is_default));
        }
        Ok(out)
    }

    // =========================================================================
    // Notes (Coins)
    // =========================================================================

    #[allow(clippy::too_many_arguments)]
    pub fn insert_note(
        &self,
        tx_hash: &str,
        output_index: u32,
        value_raw: i64,
        token_id: &str,
        serial_number: &[u8],
        block_height: u32,
        memo: Option<&str>,
        coin_blind: Option<&[u8]>,
        value_blind: Option<&[u8]>,
        token_blind: Option<&[u8]>,
        spend_hook: Option<u8>,
        user_data: Option<&[u8]>,
        leaf_position: Option<u32>,
        commitment: Option<&[u8]>,
        nullifier: Option<&[u8]>,
        owner_secret: Option<&[u8]>,
    ) -> SqlResult<i64> {
        let wrapped_owner =
            owner_secret.map(|s| crate::secret_wrap::wrap_secret(s, &self.wrap_key));
        self.conn.execute(
            "INSERT OR IGNORE INTO notes (tx_hash, output_index, value_raw, token_id, serial_number, nullifier, block_height, memo, coin_blind, value_blind, token_blind, spend_hook, user_data, leaf_position, commitment, owner_secret)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                tx_hash,
                output_index,
                value_raw,
                token_id,
                serial_number,
                nullifier,
                block_height,
                memo,
                coin_blind,
                value_blind,
                token_blind,
                spend_hook,
                user_data,
                leaf_position,
                commitment,
                wrapped_owner,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Mark a note as spent when its **nullifier** appears on-chain.
    ///
    /// Release builds call [`Self::mark_note_spent_at`]. This wrapper stays for tests.
    #[allow(dead_code)]
    pub fn mark_note_spent(&self, nullifier: &[u8]) -> SqlResult<usize> {
        self.mark_note_spent_at(nullifier, None)
    }

    /// Mark a note spent, recording the block height of the nullifier.
    ///
    /// A later sync that learns the height fills `spent_height` on a row that
    /// was reserved at broadcast time with a null height. Reorg recovery
    /// unspends only rows whose `spent_height` is above the fork.
    pub fn mark_note_spent_at(
        &self,
        nullifier: &[u8],
        spent_height: Option<u32>,
    ) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1, \
             spent_height = CASE WHEN ?2 IS NULL THEN spent_height ELSE COALESCE(spent_height, ?2) END, \
             reserved_height = CASE WHEN ?2 IS NULL THEN reserved_height ELSE NULL END \
             WHERE nullifier = ?1 \
             AND (spent = 0 OR (?2 IS NOT NULL AND spent_height IS NULL))",
            params![nullifier, spent_height],
        )?;
        Ok(rows)
    }

    /// Blocks after a broadcast reservation before sync may spend the note again.
    /// Matches the mempool window in which an unconfirmed tx can still land.
    pub const RESERVATION_GRACE_BLOCKS: u32 = 8;

    /// Reserve a note at `height` so the next send cannot reuse it before the
    /// nullifier appears. `spent_height` stays null until the chain confirms it.
    pub fn reserve_note(&self, nullifier: &[u8], height: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1, reserved_height = COALESCE(reserved_height, ?2) \
             WHERE nullifier = ?1 AND spent = 0",
            params![nullifier, height],
        )?;
        Ok(rows)
    }

    /// Same reservation, keyed by the on-chain coin commitment.
    pub fn reserve_note_by_commitment(&self, commitment: &[u8], height: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1, reserved_height = COALESCE(reserved_height, ?2) \
             WHERE commitment = ?1 AND spent = 0",
            params![commitment, height],
        )?;
        Ok(rows)
    }

    /// Unspend broadcast reservations the chain has moved past without a nullifier.
    /// Confirmed spends (`spent_height` set) are left alone.
    pub fn release_stale_reservations(&self, tip: u32, grace: u32) -> SqlResult<usize> {
        if tip <= grace {
            return Ok(0);
        }
        let oldest_kept = tip - grace;
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 0, reserved_height = NULL \
             WHERE spent = 1 AND spent_height IS NULL AND reserved_height IS NOT NULL \
             AND reserved_height < ?1",
            params![oldest_kept],
        )?;
        Ok(rows)
    }

    /// Mark a note spent by on-chain coin commitment (32-byte leaf).
    /// Used right after a successful broadcast so the next send cannot
    /// republish the same nullifier before `GetNullifiers` sees it.
    ///
    /// Callers reserve by commitment via [`Self::reserve_note_by_commitment`].
    /// This wrapper stays for tests and for a height-less spend.
    #[allow(dead_code)]
    pub fn mark_note_spent_by_commitment(&self, commitment: &[u8]) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1 WHERE commitment = ?1 AND spent = 0",
            params![commitment],
        )?;
        Ok(rows)
    }

    /// Mark a note spent by wallet locator (`tx_hash` prefix + output index).
    #[allow(dead_code)]
    pub fn mark_note_spent_by_loc(&self, tx_hash: &str, output_index: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "UPDATE notes SET spent = 1 WHERE spent = 0 AND output_index = ?1 \
             AND (tx_hash = ?2 OR tx_hash LIKE ?3)",
            params![output_index, tx_hash, format!("{tx_hash}%")],
        )?;
        Ok(rows)
    }

    /// Rewrite unspent `nullifier` columns as `poseidon(owner_secret, coin)`.
    ///
    /// Older rows were inserted with a missing or stale nullifier, so
    /// `GetNullifiers` never marked them spent and send republished an
    /// already-revealed nullifier (`-32110` / DuplicateNullifier).
    pub fn recompute_owned_nullifiers(&self) -> SqlResult<u32> {
        use darkfi_money_contract::model::Coin;
        use darkfi_sdk::crypto::pasta_prelude::PrimeField;
        use darkfi_sdk::crypto::{poseidon_hash, SecretKey};

        let mut stmt = self.conn.prepare(
            "SELECT id, commitment, owner_secret FROM notes \
             WHERE spent = 0 AND commitment IS NOT NULL AND length(commitment) = 32 \
             AND owner_secret IS NOT NULL",
        )?;
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<SqlResult<_>>()?;
        drop(stmt);

        let mut n = 0u32;
        for (id, commitment, owner_stored) in rows {
            let owner = crate::secret_wrap::unwrap_secret(&owner_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            if owner.len() < 32 || commitment.len() != 32 {
                continue;
            }
            let mut sk_arr = [0u8; 32];
            sk_arr.copy_from_slice(&owner[..32]);
            let Ok(sk) = SecretKey::from_bytes(sk_arr) else {
                continue;
            };
            let mut coin_arr = [0u8; 32];
            coin_arr.copy_from_slice(&commitment);
            let Ok(coin) = Coin::from_bytes(coin_arr) else {
                continue;
            };
            let nf = poseidon_hash([sk.inner(), coin.inner()]).to_repr();
            self.conn.execute(
                "UPDATE notes SET nullifier = ?1 WHERE id = ?2",
                params![nf.as_slice(), id],
            )?;
            n += 1;
        }
        Ok(n)
    }

    /// SQL predicate: note has no spend hook.
    ///
    /// Compact-block sync stores `FuncId::none()` as a 32-byte zero blob. Older
    /// filters only accepted NULL/empty `spend_hook_bytes`, which hid spendable
    /// DRK (balance 0 while `coins list` still showed the note).
    pub(super) fn sql_note_unhooked(alias: &str) -> String {
        let p = if alias.is_empty() {
            String::new()
        } else {
            format!("{alias}.")
        };
        format!(
            "({p}spend_hook IS NULL OR {p}spend_hook = 0) AND \
             ({p}spend_hook_bytes IS NULL OR length({p}spend_hook_bytes) = 0 OR \
              {p}spend_hook_bytes = zeroblob(length({p}spend_hook_bytes)))"
        )
    }

    /// Hex form of a token id. Accepts `TokenId` base58 or the 32-byte hex
    /// stored on synced notes. Aliases are resolved by the caller first.
    pub fn token_id_hex(token_id: &str) -> Option<String> {
        use std::str::FromStr;

        use darkfi_money_contract::model::TokenId;

        if let Ok(id) = TokenId::from_str(token_id) {
            return Some(hex::encode(id.to_bytes()));
        }
        let bytes = hex::decode(token_id).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        let id = TokenId::from_bytes(arr).ok()?;
        Some(hex::encode(id.to_bytes()))
    }

    /// Confirmed balance for a token. `"DRK"` matches the native DarkFi token
    /// hex id (and older rows stored as the literal `DRK`). Excludes contract-hooked coins.
    ///
    /// Custom tokens match both the mint-authority base58 id and the hex id
    /// written by sync.
    pub fn confirmed_balance(&self, token_id: &str) -> SqlResult<i64> {
        let is_unhooked = Self::sql_note_unhooked("");
        if Self::is_drk_token(token_id) {
            let hex = Self::dark_token_id_hex();
            let mut stmt = self.conn.prepare(&format!(
                "SELECT COALESCE(SUM(value_raw), 0) FROM notes \
                 WHERE spent = 0 AND (token_id = ?1 OR lower(token_id) = 'drk') AND {is_unhooked}"
            ))?;
            let balance: i64 = stmt.query_row(params![hex], |row| row.get(0))?;
            Ok(balance)
        } else {
            let resolved = self.resolve_token_id(token_id)?;
            let hex_key = Self::token_id_hex(&resolved).unwrap_or_else(|| resolved.clone());
            let mut stmt = self.conn.prepare(&format!(
                "SELECT COALESCE(SUM(value_raw), 0) FROM notes \
                 WHERE (token_id = ?1 OR token_id = ?2 OR token_id = ?3) \
                 AND spent = 0 AND {is_unhooked}"
            ))?;
            let balance: i64 =
                stmt.query_row(params![token_id, resolved, hex_key], |row| row.get(0))?;
            Ok(balance)
        }
    }

    /// List confirmed token balances across all unspent, unhooked notes in the wallet.
    /// Returns `(token_id, alias, balance)` with native DRK first if present.
    pub fn list_token_balances(&self) -> SqlResult<Vec<(String, Option<String>, i64)>> {
        let is_unhooked = Self::sql_note_unhooked("n");
        let query = format!(
            "SELECT n.token_id, SUM(n.value_raw) as total \
             FROM notes n \
             WHERE n.spent = 0 AND {is_unhooked} \
             GROUP BY n.token_id \
             HAVING total > 0"
        );
        // Map both Base58 token_mints.token_id and 64-char hex notes.token_id to alias.
        let mut alias_by_id: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (mint_tid, _, _, alias, _, _) in self.list_token_mints()? {
            if let Some(a) = alias {
                alias_by_id
                    .entry(mint_tid.clone())
                    .or_insert_with(|| a.clone());
                if let Some(hex_id) = Self::token_id_hex(&mint_tid) {
                    alias_by_id.entry(hex_id).or_insert(a);
                }
            }
        }
        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            let token_id: String = row.get(0)?;
            let total: i64 = row.get(1)?;
            Ok((token_id, total))
        })?;
        let mut list = Vec::new();
        for r in rows {
            let (token_id, total) = r?;
            let alias = alias_by_id
                .get(&token_id)
                .or_else(|| Self::token_id_hex(&token_id).and_then(|h| alias_by_id.get(&h)))
                .cloned();
            list.push((token_id, alias, total));
        }
        list.sort_by(|a, b| {
            let a_is_drk = Self::is_drk_token(&a.0);
            let b_is_drk = Self::is_drk_token(&b.0);
            match (a_is_drk, b_is_drk) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.0.cmp(&b.0),
            }
        });
        Ok(list)
    }

    /// Resolve a token display name or alias (e.g. "ANON", "DRK") to its 32-byte hex ID.
    ///
    /// When several mint authorities share an alias, prefer a still-mintable row so
    /// `token mint E2E` does not hit a previously frozen authority with the same name.
    pub fn resolve_token_id(&self, token_or_alias: &str) -> SqlResult<String> {
        if Self::is_drk_token(token_or_alias) {
            return Ok(Self::dark_token_id_hex());
        }
        let mut stmt = self.conn.prepare(
            "SELECT token_id FROM token_mints \
             WHERE alias = ?1 OR token_id = ?1 \
             ORDER BY is_frozen ASC, token_id ASC \
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map([token_or_alias], |r| r.get::<_, String>(0))?;
        if let Some(Ok(tid)) = rows.next() {
            return Ok(tid);
        }
        Ok(token_or_alias.to_string())
    }

    /// Unspent coins held by a DAO treasury matching BOTH spend_hook and user_data (bulla).
    pub fn list_unspent_for_dao(
        &self,
        dao_spend_hook: &[u8],
        dao_bulla: &[u8],
    ) -> SqlResult<Vec<(String, u32, i64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT tx_hash, output_index, value_raw, token_id FROM notes \
             WHERE spent = 0 AND spend_hook_bytes = ?1 AND user_data = ?2 \
             ORDER BY block_height",
        )?;
        let rows = stmt.query_map(params![dao_spend_hook, dao_bulla], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect()
    }

    /// Retrieve notes secrets from all stored DAO records so SyncEngine can trial-decrypt treasury notes.
    pub fn get_all_dao_notes_secrets(&self) -> SqlResult<Vec<Vec<u8>>> {
        use darkfi_sdk::crypto::pasta_prelude::PrimeField;
        let mut stmt = self.conn.prepare("SELECT params_toml FROM dao_records")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut secrets = Vec::new();
        for r in rows {
            let stored = r?;
            let toml_str = crate::secret_wrap::unwrap_secret_text(&stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            if let Ok(value) = toml::from_str::<toml::Value>(&toml_str) {
                if let Some(table) = value.as_table() {
                    let sec = table
                        .get("notes_secret")
                        .or_else(|| table.get("notes_secret_key"))
                        .and_then(|v| v.as_str());
                    if let Some(raw) = sec {
                        if let Ok(sk) = crate::dao_ops::sk_from_b58(raw) {
                            secrets.push(sk.inner().to_repr().to_vec());
                        } else if let Ok(bytes) = bs58::decode(raw).into_vec() {
                            if bytes.len() >= 32 {
                                secrets.push(bytes[..32].to_vec());
                            }
                        } else if let Ok(bytes) = hex::decode(raw.trim_start_matches("0x")) {
                            if bytes.len() >= 32 {
                                secrets.push(bytes[..32].to_vec());
                            }
                        }
                    }
                }
            }
        }
        Ok(secrets)
    }

    /// Unspent DAO treasury coins with full spend fields (matching BOTH spend_hook and user_data).
    #[allow(clippy::type_complexity)]
    pub fn list_unspent_dao_full(
        &self,
        dao_spend_hook: &[u8],
        dao_bulla: &[u8],
    ) -> SqlResult<
        Vec<(
            String,
            u32,
            i64,
            String,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            u32,
            Vec<u8>,
            Vec<u8>,
        )>,
    > {
        let mut stmt = self.conn.prepare(
            "SELECT tx_hash, output_index, value_raw, token_id, coin_blind, value_blind, token_blind, \
             spend_hook_bytes, user_data, leaf_position, commitment, owner_secret \
             FROM notes WHERE spent = 0 AND spend_hook_bytes = ?1 AND user_data = ?2 \
             AND leaf_position IS NOT NULL AND commitment IS NOT NULL AND length(commitment) = 32 \
             AND owner_secret IS NOT NULL \
             ORDER BY block_height",
        )?;
        let rows = stmt.query_map(params![dao_spend_hook, dao_bulla], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, u32>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (tx, idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner_stored) = row?;
            let owner = crate::secret_wrap::unwrap_secret(&owner_stored, &self.wrap_key)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
            out.push((
                tx, idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner,
            ));
        }
        Ok(out)
    }

    /// Persist a DAO proposal (locally created or decrypted from `dao_calls`).
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_dao_proposal(
        &self,
        proposal_bulla: &str,
        dao_bulla: &str,
        proposal_bytes: &[u8],
        coin_attrs_bytes: Option<&[u8]>,
        mint_height: Option<u32>,
        tx_hash: Option<&str>,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO dao_proposals \
             (proposal_bulla, dao_bulla, proposal_bytes, coin_attrs_bytes, mint_height, tx_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(proposal_bulla) DO UPDATE SET \
               coin_attrs_bytes = COALESCE(excluded.coin_attrs_bytes, dao_proposals.coin_attrs_bytes), \
               mint_height = COALESCE(excluded.mint_height, dao_proposals.mint_height), \
               tx_hash = COALESCE(excluded.tx_hash, dao_proposals.tx_hash)",
            params![
                proposal_bulla,
                dao_bulla,
                proposal_bytes,
                coin_attrs_bytes,
                mint_height,
                tx_hash
            ],
        )?;
        Ok(())
    }

    /// Look up a stored DAO proposal by Base58 `proposal_bulla`.
    #[allow(clippy::type_complexity)]
    pub fn get_dao_proposal(
        &self,
        proposal_bulla: &str,
    ) -> SqlResult<
        Option<(
            String,
            String,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<u32>,
            Option<String>,
            Option<u32>,
            Option<String>,
        )>,
    > {
        let mut stmt = self.conn.prepare(
            "SELECT proposal_bulla, dao_bulla, proposal_bytes, coin_attrs_bytes, \
             mint_height, tx_hash, exec_height, exec_tx_hash \
             FROM dao_proposals WHERE proposal_bulla = ?1",
        )?;
        let mut rows = stmt.query_map([proposal_bulla], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })?;
        match rows.next() {
            Some(Ok(v)) => Ok(Some(v)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Mark a stored DAO proposal as executed.
    pub fn set_dao_proposal_executed(
        &self,
        proposal_bulla: &str,
        exec_height: Option<u32>,
        exec_tx_hash: Option<&str>,
    ) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE dao_proposals SET \
             exec_height = COALESCE(?2, exec_height), \
             exec_tx_hash = COALESCE(?3, exec_tx_hash) \
             WHERE proposal_bulla = ?1",
            params![proposal_bulla, exec_height, exec_tx_hash],
        )?;
        Ok(())
    }

    /// All synced compact DAO calls in ascending height order (no arbitrary limit).
    pub fn list_all_dao_calls_asc(&self) -> SqlResult<Vec<DaoCallFullRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, tx_hash, kind, bulla, payload FROM dao_calls \
             ORDER BY height ASC, rowid ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        rows.collect()
    }

    /// Synced compact DAO calls including payload (ordered by height ascending for tree/replay).
    pub fn list_dao_calls_full(&self, limit: u32) -> SqlResult<Vec<DaoCallFullRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, tx_hash, kind, bulla, payload FROM dao_calls \
             ORDER BY height ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        rows.collect()
    }

    const META_LAST_SYNCED_HASH: &'static str = "last_synced_hash";
    const META_SYNCED_BLOCK_ANCHORS: &'static str = "synced_block_anchors";
    const MAX_BLOCK_ANCHORS: usize = 128;

    /// Record a canonical `(height, hash)` anchor for reorg continuity checks.
    pub fn record_synced_block_hash(&self, height: u32, hash: &[u8]) -> SqlResult<()> {
        if hash.len() != 32 {
            return Ok(());
        }
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(hash);

        let mut anchors = self.get_synced_block_anchors()?;
        anchors.retain(|(h, _)| *h != height);
        anchors.push((height, hash_arr));
        anchors.sort_by_key(|(h, _)| *h);
        if anchors.len() > Self::MAX_BLOCK_ANCHORS {
            let drop_n = anchors.len() - Self::MAX_BLOCK_ANCHORS;
            anchors.drain(..drop_n);
        }

        let mut encoded = Vec::with_capacity(anchors.len() * 36);
        for (h, bh) in &anchors {
            encoded.extend_from_slice(&h.to_le_bytes());
            encoded.extend_from_slice(bh);
        }
        self.set_meta(Self::META_SYNCED_BLOCK_ANCHORS, &encoded)?;

        // Update `last_synced_hash` if this height is >= previously recorded one.
        let update_last = match self.get_last_synced_hash()? {
            Some((prev_h, _)) => height >= prev_h,
            None => true,
        };
        if update_last {
            let mut last = Vec::with_capacity(36);
            last.extend_from_slice(&height.to_le_bytes());
            last.extend_from_slice(&hash_arr);
            self.set_meta(Self::META_LAST_SYNCED_HASH, &last)?;
        }
        Ok(())
    }

    /// Return the latest recorded `(height, hash)` pair, if any.
    pub fn get_last_synced_hash(&self) -> SqlResult<Option<(u32, [u8; 32])>> {
        let Some(bytes) = self.get_meta(Self::META_LAST_SYNCED_HASH)? else {
            return Ok(None);
        };
        if bytes.len() != 36 {
            return Ok(None);
        }
        let h = u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4]));
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[4..36]);
        Ok(Some((h, arr)))
    }

    /// Return stored `(height, hash)` anchors in ascending height order.
    pub fn get_synced_block_anchors(&self) -> SqlResult<Vec<(u32, [u8; 32])>> {
        let Some(bytes) = self.get_meta(Self::META_SYNCED_BLOCK_ANCHORS)? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(bytes.len() / 36);
        for chunk in bytes.as_chunks::<36>().0 {
            let h = u32::from_le_bytes(chunk[..4].try_into().unwrap_or([0; 4]));
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&chunk[4..36]);
            out.push((h, arr));
        }
        out.sort_by_key(|(h, _)| *h);
        Ok(out)
    }

    /// Clear notes/tx history and Merkle tree, then rewind sync height (rescan).
    pub fn reset_for_rescan(&self, height: u32) -> SqlResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM notes", [])?;
        tx.execute("DELETE FROM transactions", [])?;
        tx.execute(
            "DELETE FROM wallet_meta WHERE key IN \
             ('tree_state', 'tree_applied_height', ?1, 'trial_synced_height', ?2, ?3)",
            params![
                Self::META_MERKLE_FROM_GENESIS,
                Self::META_LAST_SYNCED_HASH,
                Self::META_SYNCED_BLOCK_ANCHORS
            ],
        )?;
        tx.execute(
            "UPDATE sync_state SET last_synced_height = ?1, last_sync_timestamp = datetime('now') WHERE id = 1",
            params![height],
        )?;
        tx.execute("DELETE FROM dao_calls", [])?;
        tx.execute("DELETE FROM func_events", [])?;
        tx.execute(
            "DELETE FROM dao_proposals WHERE coin_attrs_bytes IS NULL",
            [],
        )?;
        tx.execute(
            "UPDATE dao_proposals SET mint_height = NULL, tx_hash = NULL, exec_height = NULL, exec_tx_hash = NULL",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Invalidate notes and transactions above a given height (reorg recovery).
    ///
    /// Runs inside an atomic SQLite transaction. Preserves confirmed data below
    /// the fork point while clearing the Merkle frontier (`tree_state`,
    /// `tree_applied_height`, `merkle_from_genesis`, and unspent `leaf_position`)
    /// so the next sync rebuilds a consistent Money tree without corrupting roots.
    pub fn invalidate_above_height(&self, height: u32) -> SqlResult<(u32, u32)> {
        // Snapshot anchors before opening the transaction so we can prune above `height`.
        let mut anchors = self.get_synced_block_anchors()?;
        anchors.retain(|(h, _)| *h <= height);
        let prev_trial = self.get_meta("trial_synced_height")?;

        let tx = self.conn.unchecked_transaction()?;
        let notes_deleted =
            tx.execute("DELETE FROM notes WHERE block_height > ?1", params![height])?;
        let txs_deleted = tx.execute(
            "DELETE FROM transactions WHERE block_height > ?1",
            params![height],
        )?;
        // Unspend only notes whose nullifier was in a block above the fork.
        // `block_height` is the note's creation height, not its spend height.
        // Rows with a null `spent_height` (legacy, or reserved at broadcast)
        // stay spent so a reorg cannot resurrect historically spent coins.
        tx.execute(
            "UPDATE notes SET spent = 0, spent_height = NULL \
             WHERE spent = 1 AND spent_height IS NOT NULL AND spent_height > ?1",
            params![height],
        )?;
        // Release pending broadcast reservations placed on blocks above the fork.
        tx.execute(
            "UPDATE notes SET spent = 0, reserved_height = NULL \
             WHERE spent_height IS NULL AND reserved_height IS NOT NULL AND reserved_height > ?1",
            params![height],
        )?;
        // Clear cached leaf positions on surviving unspent notes because the
        // Merkle frontier is dropped below and will be rebuilt on next sync.
        tx.execute("UPDATE notes SET leaf_position = NULL WHERE spent = 0", [])?;
        // The Merkle frontier included the orphaned blocks. Drop tree_state,
        // tree_applied_height, and merkle_from_genesis together so ensure_genesis_merkle
        // rebuilds cleanly from genesis instead of appending onto an empty/stale tree.
        tx.execute(
            "DELETE FROM wallet_meta WHERE key IN ('tree_state', 'tree_applied_height', ?1)",
            params![Self::META_MERKLE_FROM_GENESIS],
        )?;
        if anchors.is_empty() {
            tx.execute(
                "DELETE FROM wallet_meta WHERE key IN (?1, ?2)",
                params![Self::META_LAST_SYNCED_HASH, Self::META_SYNCED_BLOCK_ANCHORS],
            )?;
        } else {
            let mut encoded = Vec::with_capacity(anchors.len() * 36);
            for (h, bh) in &anchors {
                encoded.extend_from_slice(&h.to_le_bytes());
                encoded.extend_from_slice(bh);
            }
            tx.execute(
                "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES (?1, ?2)",
                params![Self::META_SYNCED_BLOCK_ANCHORS, encoded],
            )?;
            if let Some((last_h, last_bh)) = anchors.last() {
                let mut last = Vec::with_capacity(36);
                last.extend_from_slice(&last_h.to_le_bytes());
                last.extend_from_slice(last_bh);
                tx.execute(
                    "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES (?1, ?2)",
                    params![Self::META_LAST_SYNCED_HASH, last],
                )?;
            }
        }
        if let Some(bytes) = prev_trial {
            if bytes.len() == 4 {
                let current = u32::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 4]));
                if current > height {
                    tx.execute(
                        "INSERT OR REPLACE INTO wallet_meta (key, value) VALUES ('trial_synced_height', ?1)",
                        params![height.to_le_bytes().as_slice()],
                    )?;
                }
            }
        }
        tx.execute(
            "UPDATE sync_state SET last_synced_height = ?1, last_sync_timestamp = datetime('now') WHERE id = 1",
            params![height],
        )?;
        tx.execute("DELETE FROM dao_calls WHERE height > ?1", params![height])?;
        tx.execute("DELETE FROM func_events WHERE height > ?1", params![height])?;
        tx.execute(
            "UPDATE dao_proposals SET exec_height = NULL, exec_tx_hash = NULL WHERE exec_height > ?1",
            params![height],
        )?;
        tx.execute(
            "DELETE FROM dao_proposals WHERE mint_height > ?1 AND coin_attrs_bytes IS NULL",
            params![height],
        )?;
        tx.execute(
            "UPDATE dao_proposals SET mint_height = NULL, tx_hash = NULL WHERE mint_height > ?1 AND coin_attrs_bytes IS NOT NULL",
            params![height],
        )?;
        tx.commit()?;
        Ok((notes_deleted as u32, txs_deleted as u32))
    }

    pub fn delete_meta(&self, key: &str) -> SqlResult<()> {
        self.conn
            .execute("DELETE FROM wallet_meta WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// List unspent, unhooked wallet notes (excludes contract-hooked / DAO treasury notes).
    pub fn list_unspent(&self) -> SqlResult<Vec<(String, u32, i64, String)>> {
        let is_unhooked = Self::sql_note_unhooked("");
        let query = format!(
            "SELECT tx_hash, output_index, value_raw, token_id FROM notes \
             WHERE spent = 0 AND {is_unhooked} ORDER BY block_height"
        );
        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect()
    }

    // =========================================================================
    // Sync State
    // =========================================================================

    /// Get current sync state.
    pub fn get_sync_state(&self) -> SqlResult<(u32, u32)> {
        let mut stmt = self
            .conn
            .prepare("SELECT last_synced_height, birthday_height FROM sync_state WHERE id = 1")?;
        stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
    }

    /// Update sync progress.
    pub fn set_sync_height(&self, height: u32) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE sync_state SET last_synced_height = ?1, last_sync_timestamp = datetime('now') WHERE id = 1",
            params![height],
        )?;
        Ok(())
    }

    /// Set birthday height.
    pub fn set_birthday_height(&self, height: u32) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE sync_state SET birthday_height = ?1 WHERE id = 1",
            params![height],
        )?;
        Ok(())
    }

    // =========================================================================
    // Transactions
    // =========================================================================

    /// Promote a mempool (height 0) row once the compact block is scanned.
    pub fn confirm_transaction(&self, hash: &str, height: u32) -> SqlResult<usize> {
        if height == 0 {
            return Ok(0);
        }
        self.conn.execute(
            "UPDATE transactions SET block_height = ?1 WHERE hash = ?2 AND block_height = 0",
            params![height, hash],
        )
    }

    /// True if a note with `(tx_hash, commitment)` is already stored in `notes`.
    pub fn note_exists_by_commitment(&self, tx_hash: &str, commitment: &[u8]) -> SqlResult<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM notes WHERE tx_hash = ?1 AND commitment = ?2 LIMIT 1")?;
        let mut rows = stmt.query(params![tx_hash, commitment])?;
        Ok(rows.next()?.is_some())
    }

    /// Resolve a non-colliding `output_index` for `(tx_hash, preferred_idx, commitment)`.
    ///
    /// If `(tx_hash, preferred_idx)` is unoccupied (or occupied by the same commitment),
    /// returns `preferred_idx`. If occupied by a *different* commitment (e.g. a synthetic
    /// `idx = 0` from `GetCompactOutputsByFunc` colliding with a `FeeV1` output in the
    /// same transaction), returns `MAX(output_index) + 1` for `tx_hash`.
    pub fn resolve_note_output_index(
        &self,
        tx_hash: &str,
        preferred_idx: u32,
        commitment: Option<&[u8]>,
    ) -> SqlResult<u32> {
        let existing: Option<Option<Vec<u8>>> = {
            let mut stmt = self.conn.prepare(
                "SELECT commitment FROM notes WHERE tx_hash = ?1 AND output_index = ?2 LIMIT 1",
            )?;
            let mut rows = stmt.query(params![tx_hash, preferred_idx])?;
            if let Some(row) = rows.next()? {
                Some(row.get::<_, Option<Vec<u8>>>(0)?)
            } else {
                None
            }
        };
        let Some(existing_commitment) = existing else {
            return Ok(preferred_idx);
        };
        if let (Some(want), Some(have)) = (commitment, existing_commitment.as_deref()) {
            if want == have {
                return Ok(preferred_idx);
            }
            let max_idx: u32 = self.conn.query_row(
                "SELECT COALESCE(MAX(output_index), 0) FROM notes WHERE tx_hash = ?1",
                params![tx_hash],
                |row| row.get(0),
            )?;
            return Ok(max_idx.saturating_add(1));
        }
        Ok(preferred_idx)
    }

    /// Record or update an incoming transaction by summing ALL notes belonging to
    /// `(hash, token_id)` in `notes`.
    ///
    /// - Multi-output incoming txs (e.g. `--half-split`, batch payouts) reflect the
    ///   exact summed total rather than collapsing to output 0.
    /// - Idempotent across rescans (derives total directly from deduplicated `notes`).
    /// - Never overwrites an `"outgoing"` row (only confirms its `block_height`).
    pub fn upsert_incoming_transaction(
        &self,
        hash: &str,
        block_height: u32,
        fallback_value: i64,
        token_id: &str,
        memo: Option<&str>,
    ) -> SqlResult<()> {
        let summed: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(value_raw), 0) FROM notes WHERE tx_hash = ?1 AND token_id = ?2",
            params![hash, token_id],
            |row| row.get(0),
        )?;
        let total = if summed > 0 { summed } else { fallback_value };
        self.conn.execute(
            "INSERT INTO transactions (hash, block_height, direction, value_raw, token_id, counterparty, memo, kind)
             VALUES (?1, ?2, 'incoming', ?3, ?4, NULL, ?5, 'receive')
             ON CONFLICT(hash) DO UPDATE SET
               block_height = CASE
                 WHEN transactions.block_height = 0 AND excluded.block_height > 0 THEN excluded.block_height
                 ELSE transactions.block_height
               END,
               value_raw = CASE
                 WHEN transactions.direction = 'incoming' AND transactions.token_id = excluded.token_id THEN excluded.value_raw
                 ELSE transactions.value_raw
               END,
               memo = CASE
                 WHEN transactions.direction = 'incoming' AND (transactions.memo IS NULL OR transactions.memo = '') THEN excluded.memo
                 ELSE transactions.memo
               END",
            params![hash, block_height, total, token_id, memo],
        )?;
        Ok(())
    }

    /// Insert a transaction record.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_transaction(
        &self,
        hash: &str,
        block_height: u32,
        direction: &str,
        value_raw: i64,
        token_id: &str,
        counterparty: Option<&str>,
        memo: Option<&str>,
    ) -> SqlResult<()> {
        self.insert_typed(
            hash,
            block_height,
            direction,
            kind_from_direction(direction),
            value_raw,
            token_id,
            counterparty,
            memo,
        )
    }

    /// Insert a history row with an explicit kind (`send`, `token-mint`, `burn`, …).
    #[allow(clippy::too_many_arguments)]
    pub fn insert_typed(
        &self,
        hash: &str,
        block_height: u32,
        direction: &str,
        kind: &str,
        value_raw: i64,
        token_id: &str,
        counterparty: Option<&str>,
        memo: Option<&str>,
    ) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO transactions (hash, block_height, direction, value_raw, token_id, counterparty, memo, kind)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(hash) DO UPDATE SET
               block_height = excluded.block_height
             WHERE transactions.block_height = 0 AND excluded.block_height > 0",
            params![
                hash,
                block_height,
                direction,
                value_raw,
                token_id,
                counterparty,
                memo,
                kind
            ],
        )?;
        Ok(())
    }

    /// List transactions, most recent first.
    pub fn list_transactions(&self, limit: u32) -> SqlResult<Vec<TransactionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, block_height, direction, value_raw, token_id, counterparty, memo, timestamp, kind
             FROM transactions ORDER BY block_height DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(TransactionRow {
                hash: row.get(0)?,
                block_height: row.get(1)?,
                direction: row.get(2)?,
                value_raw: row.get(3)?,
                token_id: row.get(4)?,
                counterparty: row.get(5)?,
                memo: row.get(6)?,
                timestamp: row.get(7)?,
                kind: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    /// Get a single transaction by hash.
    pub fn get_transaction(&self, hash: &str) -> SqlResult<Option<TransactionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, block_height, direction, value_raw, token_id, counterparty, memo, timestamp, kind
             FROM transactions WHERE hash = ?1",
        )?;
        let mut rows = stmt.query(params![hash])?;
        if let Some(row) = rows.next()? {
            Ok(Some(TransactionRow {
                hash: row.get(0)?,
                block_height: row.get(1)?,
                direction: row.get(2)?,
                value_raw: row.get(3)?,
                token_id: row.get(4)?,
                counterparty: row.get(5)?,
                memo: row.get(6)?,
                timestamp: row.get(7)?,
                kind: row.get(8)?,
            }))
        } else {
            Ok(None)
        }
    }

    // =========================================================================
    // Pruning
    // =========================================================================

    /// Prune confirmed spent notes whose spend height is below `height` (data minimization).
    /// Unconfirmed reservations (`spent_height IS NULL`) and recently spent old coins are preserved.
    pub fn prune_spent_below(&self, height: u32) -> SqlResult<usize> {
        let rows = self.conn.execute(
            "DELETE FROM notes WHERE spent = 1 AND spent_height IS NOT NULL AND spent_height < ?1",
            params![height],
        )?;
        Ok(rows)
    }

    /// Vacuum the database to reclaim disk space.
    pub fn vacuum(&self) -> SqlResult<()> {
        self.conn.execute_batch("VACUUM")?;
        Ok(())
    }
}
