//! DAO create / mint / propose / vote / exec for Moonshine light wallet.

use crate::client::LightwalletClient;
use crate::db::WalletDb;
use crate::sync::{height_in_scan_window, require_padded_range, MAX_BLOCKS_PER_REQUEST};
use crate::tx_builder::{assert_witness_at_tip, select_coins_deterministic};
use darkfi::zk::halo2::Field;
use darkfi::{
    tx::{ContractCallLeaf, TransactionBuilder},
    zk::{proof::ProvingKey, vm::ZkCircuit, vm_heap::empty_witnesses},
    zkas::ZkBinary,
};
use darkfi_dao_contract::{
    blockwindow,
    client::{
        make_mint_call, DaoAuthMoneyTransferCall, DaoExecCall, DaoProposeCall,
        DaoProposeStakeInput, DaoVoteCall, DaoVoteInput,
    },
    model::{Dao, DaoAuthCall, DaoBulla, DaoProposal, DaoProposalBulla},
    DaoFunction, DAO_CONTRACT_ZKAS_AUTH_MONEY_TRANSFER_ENC_COIN_NS,
    DAO_CONTRACT_ZKAS_AUTH_MONEY_TRANSFER_NS, DAO_CONTRACT_ZKAS_EARLY_EXEC_NS,
    DAO_CONTRACT_ZKAS_EXEC_NS, DAO_CONTRACT_ZKAS_MINT_NS, DAO_CONTRACT_ZKAS_PROPOSE_INPUT_NS,
    DAO_CONTRACT_ZKAS_PROPOSE_MAIN_NS, DAO_CONTRACT_ZKAS_VOTE_INPUT_NS,
    DAO_CONTRACT_ZKAS_VOTE_MAIN_NS,
};
use darkfi_money_contract::{
    client::{
        transfer_v1::{TransferCallBuilder, TransferCallInput},
        MoneyNote, OwnCoin,
    },
    model::{CoinAttributes, Nullifier, TokenId, DARK_TOKEN_ID},
    MoneyFunction, MONEY_CONTRACT_ZKAS_BURN_NS_V1, MONEY_CONTRACT_ZKAS_MINT_NS_V1,
};
use darkfi_sdk::{
    bridgetree::Position,
    crypto::{
        contract_id::{DAO_CONTRACT_ID, MONEY_CONTRACT_ID},
        note::{AeadEncryptedNote, ElGamalEncryptedNote},
        pasta_prelude::PrimeField,
        poseidon_hash,
        smt::{MemoryStorageFp, PoseidonFp, SmtMemoryFp, EMPTY_NODES_FP},
        util::{fp_mod_fv, fp_to_u64},
        BaseBlind, Blind, FuncId, FuncRef, Keypair, MerkleNode, MerkleTree, PublicKey, SecretKey,
    },
    dark_tree::DarkTree,
    pasta::pallas,
    tx::ContractCall,
};
use darkfi_serial::{deserialize, serialize_async, AsyncEncodable, Decodable};
use futures::StreamExt;
use rand_core::OsRng;
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::str::FromStr;

const DAO_KIND_MINT: u32 = 0;
const DAO_KIND_PROPOSE: u32 = 1;
const DAO_KIND_VOTE: u32 = 2;

/// Parsed DAO parameters alongside any secret role keys present in the TOML.
#[derive(Debug, Clone)]
pub struct ParsedDao {
    pub dao: Dao,
    pub notes_sk: Option<SecretKey>,
    pub proposer_sk: Option<SecretKey>,
    pub proposals_sk: Option<SecretKey>,
    pub votes_sk: Option<SecretKey>,
    pub exec_sk: Option<SecretKey>,
    pub early_exec_sk: Option<SecretKey>,
}

/// Normalize a token identifier from `"DRK"`, wallet alias, Base58, or 64-char hex.
pub fn normalize_token_id(db: &WalletDb, input: &str) -> Result<TokenId, Box<dyn Error>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("gov_token_id must not be empty".into());
    }
    if WalletDb::is_drk_token(trimmed) {
        return Ok(*DARK_TOKEN_ID);
    }
    let resolved = db.resolve_token_id(trimmed)?;
    if WalletDb::is_drk_token(&resolved) {
        return Ok(*DARK_TOKEN_ID);
    }
    if let Ok(id) = TokenId::from_str(&resolved) {
        return Ok(id);
    }
    let clean_hex = resolved.trim_start_matches("0x").trim_start_matches("0X");
    if clean_hex.len() == 64 {
        if let Ok(bytes) = hex::decode(clean_hex) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                if let Ok(id) = TokenId::from_bytes(arr) {
                    return Ok(id);
                }
            }
        }
    }
    Err(format!(
        "invalid gov_token_id '{input}': expected DRK, known alias, Base58 TokenId, or 64-char hex"
    )
    .into())
}

/// Standard spend hook for the DarkFi DAO contract (Dao::Exec).
pub fn dao_spend_hook() -> FuncId {
    FuncRef {
        contract_id: *DAO_CONTRACT_ID,
        func_code: DaoFunction::Exec as u8,
    }
    .to_func_id()
}

/// Create DAO params (secrets) and store under `name`. Returns `drk`-compatible TOML text.
pub fn create_dao(
    db: &WalletDb,
    name: &str,
    proposer_limit: u64,
    quorum: u64,
    early_exec_quorum: u64,
    approval_ratio: f64,
    gov_token: &str,
) -> Result<String, Box<dyn Error>> {
    if !approval_ratio.is_finite() || !(0.0..=1.0).contains(&approval_ratio) {
        return Err("approval_ratio must be a finite number in 0.0..=1.0".into());
    }
    let gov_token_id = normalize_token_id(db, gov_token)?;
    let gov_token_b58 = gov_token_id.to_string();
    let escaped_name = toml::Value::String(name.to_string()).to_string();
    let notes = Keypair::random(&mut OsRng);
    let proposer = Keypair::random(&mut OsRng);
    let proposals = Keypair::random(&mut OsRng);
    let votes = Keypair::random(&mut OsRng);
    let exec = Keypair::random(&mut OsRng);
    let early_exec = Keypair::random(&mut OsRng);
    let bulla_blind = BaseBlind::random(&mut OsRng);

    let notes_sec_b58 = bs58::encode(darkfi_serial::serialize(&notes.secret)).into_string();
    let proposer_sec_b58 = bs58::encode(darkfi_serial::serialize(&proposer.secret)).into_string();
    let proposals_sec_b58 = bs58::encode(darkfi_serial::serialize(&proposals.secret)).into_string();
    let votes_sec_b58 = bs58::encode(darkfi_serial::serialize(&votes.secret)).into_string();
    let exec_sec_b58 = bs58::encode(darkfi_serial::serialize(&exec.secret)).into_string();
    let early_exec_sec_b58 =
        bs58::encode(darkfi_serial::serialize(&early_exec.secret)).into_string();
    let bulla_blind_b58 = bs58::encode(darkfi_serial::serialize(&bulla_blind)).into_string();

    let proposer_limit_str = crate::amount::format_drk_atomic(proposer_limit);
    let quorum_str = crate::amount::format_drk_atomic(quorum);
    let early_exec_quorum_str = crate::amount::format_drk_atomic(early_exec_quorum);
    // Debug formatting of f64 guarantees a decimal point (e.g. `1.0`) for drk's `as_float()`.
    let approval_ratio_str = format!("{approval_ratio:?}");
    let approval_ratio_base = 100u64;
    let approval_ratio_quot = (approval_ratio * approval_ratio_base as f64).round() as u64;

    // Emit canonical `drk::dao::DaoParams::from_toml_str` keys plus exact rational fields.
    let toml = format!(
        "# Moonshine DAO params — keep secret\n\
         name = {escaped_name}\n\
         proposer_limit = \"{proposer_limit_str}\"\n\
         quorum = \"{quorum_str}\"\n\
         early_exec_quorum = \"{early_exec_quorum_str}\"\n\
         approval_ratio = {approval_ratio_str}\n\
         approval_ratio_quot = {approval_ratio_quot}\n\
         approval_ratio_base = {approval_ratio_base}\n\
         gov_token_id = \"{gov_token_b58}\"\n\
         notes_secret_key = \"{notes_sec_b58}\"\n\
         notes_public_key = \"{}\"\n\
         proposer_secret_key = \"{proposer_sec_b58}\"\n\
         proposer_public_key = \"{}\"\n\
         proposals_secret_key = \"{proposals_sec_b58}\"\n\
         proposals_public_key = \"{}\"\n\
         votes_secret_key = \"{votes_sec_b58}\"\n\
         votes_public_key = \"{}\"\n\
         exec_secret_key = \"{exec_sec_b58}\"\n\
         exec_public_key = \"{}\"\n\
         early_exec_secret_key = \"{early_exec_sec_b58}\"\n\
         early_exec_public_key = \"{}\"\n\
         bulla_blind = \"{bulla_blind_b58}\"\n",
        notes.public,
        proposer.public,
        proposals.public,
        votes.public,
        exec.public,
        early_exec.public,
    );
    db.upsert_dao_record(name, &toml, None, None)?;
    Ok(toml)
}

pub fn sk_from_b58(s: &str) -> Result<SecretKey, Box<dyn Error>> {
    let bytes = bs58::decode(s).into_vec()?;
    Ok(darkfi_serial::deserialize(&bytes)?)
}

pub fn pk_from_b58(s: &str) -> Result<PublicKey, Box<dyn Error>> {
    if let Ok(pk) = PublicKey::from_str(s) {
        return Ok(pk);
    }
    let bytes = bs58::decode(s).into_vec()?;
    Ok(darkfi_serial::deserialize(&bytes)?)
}

pub fn blind_from_b58(s: &str) -> Result<BaseBlind, Box<dyn Error>> {
    let bytes = bs58::decode(s).into_vec()?;
    Ok(darkfi_serial::deserialize(&bytes)?)
}

fn parse_proposal_bulla(s: &str) -> Result<DaoProposalBulla, Box<dyn Error>> {
    let bytes = bs58::decode(s.trim())
        .into_vec()
        .map_err(|e| format!("invalid proposal_bulla: {e}"))?;
    let repr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "proposal_bulla must decode to 32 bytes")?;
    DaoProposalBulla::from_bytes(repr).map_err(|e| format!("invalid proposal_bulla: {e}").into())
}

/// Parse DAO parameters and any role secret keys from TOML (accepts both `drk`
/// format and legacy Moonshine integer format, with optional role secret keys).
pub fn parse_dao_with_roles(toml_str: &str, db: &WalletDb) -> Result<ParsedDao, Box<dyn Error>> {
    let value = toml::from_str::<toml::Value>(toml_str)?;
    let table = value.as_table().ok_or("DAO TOML root must be a table")?;

    let parse_role = |sec1: &str,
                      sec2: &str,
                      pub_k: &str|
     -> Result<(Option<SecretKey>, PublicKey), Box<dyn Error>> {
        let sk = if let Some(s) = table
            .get(sec1)
            .or_else(|| table.get(sec2))
            .and_then(|v| v.as_str())
        {
            Some(sk_from_b58(s)?)
        } else {
            None
        };
        let pk = if let Some(secret) = sk {
            Keypair::new(secret).public
        } else if let Some(p) = table.get(pub_k).and_then(|v| v.as_str()) {
            pk_from_b58(p)?
        } else {
            return Err(format!("DAO TOML missing {sec1} / {sec2} / {pub_k}").into());
        };
        Ok((sk, pk))
    };

    let (notes_sk, notes_public_key) =
        parse_role("notes_secret", "notes_secret_key", "notes_public_key")?;
    let (proposer_sk, proposer_public_key) = parse_role(
        "proposer_secret",
        "proposer_secret_key",
        "proposer_public_key",
    )?;
    let (proposals_sk, proposals_public_key) = parse_role(
        "proposals_secret",
        "proposals_secret_key",
        "proposals_public_key",
    )?;
    let (votes_sk, votes_public_key) =
        parse_role("votes_secret", "votes_secret_key", "votes_public_key")?;
    let (exec_sk, exec_public_key) =
        parse_role("exec_secret", "exec_secret_key", "exec_public_key")?;
    let (early_exec_sk, early_exec_public_key) = parse_role(
        "early_exec_secret",
        "early_exec_secret_key",
        "early_exec_public_key",
    )?;
    let bulla_blind = blind_from_b58(
        table
            .get("bulla_blind")
            .and_then(|v| v.as_str())
            .ok_or("bulla_blind")?,
    )?;

    let parse_u64_or_str = |k: &str| -> Result<u64, Box<dyn Error>> {
        if let Some(v) = table.get(k) {
            if let Some(i) = v.as_integer() {
                if i < 0 {
                    return Err(format!("{k} in DAO TOML must be non-negative (got {i})").into());
                }
                return Ok(i as u64);
            }
            if let Some(s) = v.as_str() {
                if let Ok(atomic) = crate::amount::parse_drk_atomic(s) {
                    return Ok(atomic);
                }
                if let Ok(n) = s.parse::<u64>() {
                    return Ok(n);
                }
            }
        }
        Err(format!("invalid or missing {k} in DAO TOML").into())
    };

    let proposer_limit = parse_u64_or_str("proposer_limit")?;
    let quorum = parse_u64_or_str("quorum")?;
    let early_exec_quorum = parse_u64_or_str("early_exec_quorum")?;

    let (approval_ratio_quot, approval_ratio_base) = match (
        table
            .get("approval_ratio_quot")
            .and_then(|v| v.as_integer()),
        table
            .get("approval_ratio_base")
            .and_then(|v| v.as_integer()),
    ) {
        (Some(q), Some(b)) => {
            if b <= 0 || q < 0 || q > b {
                return Err("approval_ratio_quot/base out of bounds (expected 0 <= quot <= base and base > 0)".into());
            }
            (q as u64, b as u64)
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(
                "DAO TOML must provide both approval_ratio_quot and approval_ratio_base".into(),
            );
        }
        (None, None) => {
            let approval_ratio = match table.get("approval_ratio") {
                Some(v) if v.as_float().is_some() => v.as_float().unwrap(),
                Some(v) if v.as_integer().is_some() => v.as_integer().unwrap() as f64,
                _ => return Err("approval_ratio".into()),
            };
            if !approval_ratio.is_finite() || !(0.0..=1.0).contains(&approval_ratio) {
                return Err("approval_ratio must be a finite number in 0.0..=1.0".into());
            }
            let base = 100u64;
            let quot = (approval_ratio * base as f64).round() as u64;
            (quot, base)
        }
    };

    let raw_gov_token = table
        .get("gov_token_id")
        .and_then(|v| v.as_str())
        .ok_or("gov_token_id")?;
    let gov_token_id = normalize_token_id(db, raw_gov_token)?;

    Ok(ParsedDao {
        dao: Dao {
            proposer_limit,
            quorum,
            early_exec_quorum,
            approval_ratio_quot,
            approval_ratio_base,
            gov_token_id,
            notes_public_key,
            proposer_public_key,
            proposals_public_key,
            votes_public_key,
            exec_public_key,
            early_exec_public_key,
            bulla_blind,
        },
        notes_sk,
        proposer_sk,
        proposals_sk,
        votes_sk,
        exec_sk,
        early_exec_sk,
    })
}

/// Parse `Dao` model from a TOML string.
pub fn parse_dao_params(toml_str: &str, db: &WalletDb) -> Result<Dao, Box<dyn Error>> {
    Ok(parse_dao_with_roles(toml_str, db)?.dao)
}

/// Mint a stored DAO on-chain (`Dao::Mint`). Caller attaches fee + broadcasts.
pub async fn build_mint_builder(
    db: &WalletDb,
    name: &str,
    zkas_bins: &[(String, Vec<u8>)],
) -> Result<(TransactionBuilder, String), Box<dyn Error>> {
    let Some(toml) = db.get_dao_toml(name)? else {
        return Err(format!("DAO '{name}' not found — create or import first").into());
    };
    let parsed = parse_dao_with_roles(&toml, db)?;
    let notes_sk = parsed.notes_sk.ok_or("DAO TOML missing notes_secret_key")?;
    let proposer_sk = parsed
        .proposer_sk
        .ok_or("DAO TOML missing proposer_secret_key")?;
    let proposals_sk = parsed
        .proposals_sk
        .ok_or("DAO TOML missing proposals_secret_key")?;
    let votes_sk = parsed.votes_sk.ok_or("DAO TOML missing votes_secret_key")?;
    let exec_sk = parsed.exec_sk.ok_or("DAO TOML missing exec_secret_key")?;
    let early_exec_sk = parsed
        .early_exec_sk
        .ok_or("DAO TOML missing early_exec_secret_key")?;

    let mint_bytes = decode_zkas(zkas_bins, DAO_CONTRACT_ZKAS_MINT_NS, "DAO Mint")?;
    let (dao_mint_zkbin, dao_mint_pk) = compile_zkbin(&mint_bytes)?;

    let (params, proofs) = make_mint_call(
        &parsed.dao,
        &notes_sk,
        &proposer_sk,
        &proposals_sk,
        &votes_sk,
        &exec_sk,
        &early_exec_sk,
        &dao_mint_zkbin,
        &dao_mint_pk,
    )?;
    let bulla = params.dao_bulla.to_string();
    let mut data = vec![DaoFunction::Mint as u8];
    params.encode_async(&mut data).await?;
    let call = ContractCall {
        contract_id: *DAO_CONTRACT_ID,
        data,
    };
    let tx_builder =
        TransactionBuilder::new(ContractCallLeaf::new(call, proofs, vec![notes_sk]), vec![])?;
    db.upsert_dao_record(name, &toml, Some(&bulla), None)?;
    Ok((tx_builder, bulla))
}

/// Propose a treasury transfer (`Dao::Propose`) on-chain. Caller attaches fee + broadcasts.
#[allow(clippy::too_many_arguments)]
pub async fn build_propose_builder(
    db: &WalletDb,
    client: &mut LightwalletClient,
    dao_name: &str,
    recipient_pk: PublicKey,
    amount: u64,
    token_id: TokenId,
    duration_blockwindows: u64,
    dao_zkas: &[(String, Vec<u8>)],
) -> Result<(TransactionBuilder, String, String, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    if amount == 0 {
        return Err("proposal transfer amount must be > 0".into());
    }
    if duration_blockwindows == 0 {
        return Err("duration_blockwindows must be > 0".into());
    }
    let Some(toml) = db.get_dao_toml(dao_name)? else {
        return Err(format!("DAO '{dao_name}' not found — create or import first").into());
    };
    let parsed = parse_dao_with_roles(&toml, db)?;
    let proposer_sk = parsed
        .proposer_sk
        .ok_or("DAO TOML missing proposer_secret_key (needed to create proposals)")?;
    let dao = parsed.dao;
    let dao_bulla = dao.to_bulla();

    // Check DAO treasury balance covers the proposed transfer amount.
    let spend_hook = dao_spend_hook();
    let treasury_coins =
        decode_unspent_dao_coins(db, &spend_hook.to_bytes(), &dao_bulla.inner().to_repr())?;
    let treasury_avail: u64 = treasury_coins
        .iter()
        .filter(|c| c.note.token_id == token_id)
        .map(|c| c.note.value)
        .sum();
    if treasury_avail < amount {
        return Err(format!(
            "DAO '{dao_name}' treasury has {treasury_avail} atomic of {token_id}, need {amount}"
        )
        .into());
    }

    // Reconstruct the DAO Merkle tree from synced compact DAO Mint records.
    let (daos_tree, dao_leaf_position) = build_daos_merkle_tree(db, &dao_bulla)?;
    let dao_merkle_root = daos_tree
        .root(0)
        .ok_or("DAO Merkle tree has no root — sync first")?;
    let dao_merkle_path = daos_tree
        .witness(dao_leaf_position, 0)
        .map_err(|_| "DAO Merkle witness missing — sync and rebuild DAO state")?;

    let info = client.get_light_info().await?;
    let tip = info.block_height;
    let block_target = info.block_target.max(1);

    let money_tree = load_tip_money_tree(db)?;
    let money_merkle_coin_root = money_tree
        .root(0)
        .ok_or("Money Merkle tree root missing — sync with --rebuild-merkle")?;

    let gov_all = decode_unspent_regular_coins(db, Some(dao.gov_token_id))?;
    let gov_spendable: Vec<OwnCoin> = gov_all
        .into_iter()
        .filter(|c| {
            assert_witness_at_tip(
                &money_tree,
                MerkleNode::from(c.coin.inner()),
                c.leaf_position,
            )
            .is_ok()
        })
        .collect();
    let (gov_selected, _) = select_coins_deterministic(&gov_spendable, dao.proposer_limit)
        .map_err(|e| {
            format!(
                "insufficient governance token {} for proposer_limit ({}): {e}",
                dao.gov_token_id, dao.proposer_limit
            )
        })?;

    let money_null_smt = build_money_nullifier_smt(client, tip, tip).await?;

    let inputs: Vec<DaoProposeStakeInput> = gov_selected
        .into_iter()
        .map(|coin| {
            let merkle_path = money_tree
                .witness(coin.leaf_position, 0)
                .map_err(|_| "governance coin Merkle witness missing")?;
            Ok::<_, Box<dyn Error>>(DaoProposeStakeInput {
                secret: coin.secret,
                note: coin.note,
                leaf_position: coin.leaf_position,
                merkle_path,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let proposal_coinattrs = CoinAttributes {
        public_key: recipient_pk,
        value: amount,
        token_id,
        spend_hook: FuncId::none(),
        user_data: pallas::Base::ZERO,
        blind: Blind::random(&mut OsRng),
    };
    let proposal_coins = vec![proposal_coinattrs.to_coin()];
    let mut auth_data = Vec::new();
    proposal_coins.encode_async(&mut auth_data).await?;

    let creation_blockwindow = blockwindow(tip.saturating_add(1), block_target);
    let proposal = DaoProposal {
        auth_calls: vec![
            DaoAuthCall {
                contract_id: *DAO_CONTRACT_ID,
                function_code: DaoFunction::AuthMoneyTransfer as u8,
                auth_data,
            },
            DaoAuthCall {
                contract_id: *MONEY_CONTRACT_ID,
                function_code: MoneyFunction::TransferV1 as u8,
                auth_data: vec![],
            },
        ],
        creation_blockwindow,
        duration_blockwindows,
        user_data: pallas::Base::ZERO,
        dao_bulla,
        blind: Blind::random(&mut OsRng),
    };

    let (propose_in_zkbin, propose_in_pk) = compile_zkbin(&decode_zkas(
        dao_zkas,
        DAO_CONTRACT_ZKAS_PROPOSE_INPUT_NS,
        "ProposeInput",
    )?)?;
    let (propose_main_zkbin, propose_main_pk) = compile_zkbin(&decode_zkas(
        dao_zkas,
        DAO_CONTRACT_ZKAS_PROPOSE_MAIN_NS,
        "ProposeMain",
    )?)?;

    let (params, proofs, signature_secrets) = DaoProposeCall {
        money_merkle_coin_root,
        money_null_smt: &money_null_smt,
        inputs,
        proposal: proposal.clone(),
        dao,
        dao_leaf_position,
        dao_merkle_path,
        dao_merkle_root,
    }
    .make(
        &proposer_sk,
        &propose_in_zkbin,
        &propose_in_pk,
        &propose_main_zkbin,
        &propose_main_pk,
    )?;

    let mut data = vec![DaoFunction::Propose as u8];
    params.encode_async(&mut data).await?;
    let call = ContractCall {
        contract_id: *DAO_CONTRACT_ID,
        data,
    };
    let tx_builder = TransactionBuilder::new(
        ContractCallLeaf::new(call, proofs, signature_secrets),
        vec![],
    )?;

    let proposal_bytes = serialize_async(&proposal).await;
    let coin_attrs_bytes = serialize_async(&proposal_coinattrs).await;
    Ok((
        tx_builder,
        proposal.to_bulla().to_string(),
        dao_bulla.to_string(),
        proposal_bytes,
        coin_attrs_bytes,
    ))
}

/// Cast a full-weight yes/no vote on a DAO proposal (`Dao::Vote`). Caller attaches fee + broadcasts.
pub async fn build_vote_builder(
    db: &WalletDb,
    client: &mut LightwalletClient,
    dao_name: &str,
    proposal_bulla_str: &str,
    vote_option: bool,
    dao_zkas: &[(String, Vec<u8>)],
) -> Result<TransactionBuilder, Box<dyn Error>> {
    let Some(toml) = db.get_dao_toml(dao_name)? else {
        return Err(format!("DAO '{dao_name}' not found — create or import first").into());
    };
    let parsed = parse_dao_with_roles(&toml, db)?;
    let dao = parsed.dao.clone();
    let dao_bulla = dao.to_bulla();
    let proposal_bulla = parse_proposal_bulla(proposal_bulla_str)?;
    let (proposal, _coin_attrs, mint_height, exec_tx) =
        resolve_proposal(db, &parsed, &dao_bulla, &proposal_bulla)?;
    if let Some(eh) = exec_tx {
        return Err(format!("Proposal already executed in tx {eh}").into());
    }

    let info = client.get_light_info().await?;
    let tip = info.block_height;
    let block_target = info.block_target.max(1);
    let current_blockwindow = blockwindow(tip.saturating_add(1), block_target);
    if current_blockwindow
        >= proposal
            .creation_blockwindow
            .saturating_add(proposal.duration_blockwindows)
    {
        return Err("Proposal voting window has already closed".into());
    }

    let snap_height = mint_height.map(|h| h.min(tip)).unwrap_or(tip);

    // Check prior votes for duplicate vote nullifiers if we hold the votes secret key.
    let mut prior_vote_nullifiers: HashSet<[u8; 32]> = HashSet::new();
    if let Some(votes_sk) = parsed.votes_sk {
        for v in decode_votes_for_proposal(db, &proposal_bulla, &votes_sk)? {
            for nf in v.nullifiers {
                prior_vote_nullifiers.insert(nf.inner().to_repr());
            }
        }
    }

    let gov_coins = decode_unspent_regular_coins(db, Some(dao.gov_token_id))?;
    if gov_coins.is_empty() {
        return Err(format!(
            "No governance token {} coins in wallet to vote with",
            dao.gov_token_id
        )
        .into());
    }
    let owned_cm: HashSet<[u8; 32]> = gov_coins.iter().map(|c| c.coin.to_bytes()).collect();

    let (snapshot_tree, money_null_smt) = if snap_height == tip {
        (
            load_tip_money_tree(db)?,
            build_money_nullifier_smt(client, tip, tip).await?,
        )
    } else {
        // Proposal snapshots Money before/at block `mint_height`; use `mint_height.saturating_sub(1)`.
        let h = snap_height.saturating_sub(1);
        (
            build_money_tree_at_height(client, h, tip, &owned_cm).await?,
            build_money_nullifier_smt(client, h, tip).await?,
        )
    };

    let mut inputs = Vec::new();
    for gov in gov_coins {
        let Ok(merkle_path) = snapshot_tree.witness(gov.leaf_position, 0) else {
            continue;
        };
        let nullifier = poseidon_hash([gov.secret.inner(), gov.coin.inner()]);
        let vote_nf: [u8; 32] =
            poseidon_hash([nullifier, gov.secret.inner(), proposal_bulla.inner()]).to_repr();
        if prior_vote_nullifiers.contains(&vote_nf) {
            return Err("At least one governance coin already voted on this proposal".into());
        }
        inputs.push(DaoVoteInput {
            secret: gov.secret,
            note: gov.note,
            leaf_position: gov.leaf_position,
            merkle_path,
        });
    }
    if inputs.is_empty() {
        return Err("No governance coins existed at the proposal snapshot height".into());
    }

    let (vote_in_zkbin, vote_in_pk) = compile_zkbin(&decode_zkas(
        dao_zkas,
        DAO_CONTRACT_ZKAS_VOTE_INPUT_NS,
        "VoteInput",
    )?)?;
    let (vote_main_zkbin, vote_main_pk) = compile_zkbin(&decode_zkas(
        dao_zkas,
        DAO_CONTRACT_ZKAS_VOTE_MAIN_NS,
        "VoteMain",
    )?)?;

    let (params, proofs, signature_secrets) = DaoVoteCall {
        money_null_smt: &money_null_smt,
        inputs,
        vote_option,
        proposal,
        dao,
        current_blockwindow,
    }
    .make(&vote_in_zkbin, &vote_in_pk, &vote_main_zkbin, &vote_main_pk)?;

    let mut data = vec![DaoFunction::Vote as u8];
    params.encode_async(&mut data).await?;
    let call = ContractCall {
        contract_id: *DAO_CONTRACT_ID,
        data,
    };
    Ok(TransactionBuilder::new(
        ContractCallLeaf::new(call, proofs, signature_secrets),
        vec![],
    )?)
}

/// Execute an approved DAO transfer proposal (`Dao::Exec` + `Dao::AuthMoneyTransfer` + `Money::TransferV1`).
/// Returns the TransactionBuilder and the spent treasury nullifiers (plus tx_builder).
pub async fn build_exec_builder(
    db: &WalletDb,
    client: &mut LightwalletClient,
    dao_name: &str,
    proposal_bulla_str: &str,
    early_flag: Option<bool>,
    dao_zkas: &[(String, Vec<u8>)],
    money_zkas: &[(String, Vec<u8>)],
) -> Result<(TransactionBuilder, Vec<Vec<u8>>), Box<dyn Error>> {
    let Some(toml) = db.get_dao_toml(dao_name)? else {
        return Err(format!("DAO '{dao_name}' not found — create or import first").into());
    };
    let parsed = parse_dao_with_roles(&toml, db)?;
    let exec_sk = parsed
        .exec_sk
        .ok_or("DAO TOML missing exec_secret_key (needed to execute proposals)")?;
    let votes_sk = parsed
        .votes_sk
        .ok_or("DAO TOML missing votes_secret_key (needed to tally encrypted votes)")?;
    let dao = parsed.dao.clone();
    let dao_bulla = dao.to_bulla();
    let proposal_bulla = parse_proposal_bulla(proposal_bulla_str)?;
    let (proposal, coin_attrs_opt, _mint_height, exec_tx) =
        resolve_proposal(db, &parsed, &dao_bulla, &proposal_bulla)?;
    if let Some(eh) = exec_tx {
        return Err(format!("Proposal already executed in tx {eh}").into());
    }
    let proposal_coinattrs = coin_attrs_opt.ok_or(
        "Proposal plaintext CoinAttributes missing (only the proposing wallet stores recipient/value/blind locally)",
    )?;

    let info = client.get_light_info().await?;
    let current_blockwindow = blockwindow(
        info.block_height.saturating_add(1),
        info.block_target.max(1),
    );
    let window_end = proposal
        .creation_blockwindow
        .saturating_add(proposal.duration_blockwindows);
    let early = match early_flag {
        Some(v) => v,
        None => current_blockwindow < window_end,
    };
    if early && parsed.early_exec_sk.is_none() {
        return Err(
            "Voting window is still open; early execution requires early_exec_secret_key".into(),
        );
    }
    if !early && current_blockwindow < window_end {
        return Err(format!(
            "Voting window is still open ({current_blockwindow} < {window_end}); pass --early if quorum reached early"
        )
        .into());
    }

    // Tally encrypted votes from synced `dao_calls`.
    let votes = decode_votes_for_proposal(db, &proposal_bulla, &votes_sk)?;
    let mut yes_vote_value = 0u64;
    let mut yes_vote_blind = Blind::ZERO;
    let mut all_vote_value = 0u64;
    let mut all_vote_blind = Blind::ZERO;
    for v in votes {
        if v.option {
            yes_vote_value = yes_vote_value.saturating_add(v.all_vote_value);
        }
        yes_vote_blind += v.yes_vote_blind;
        all_vote_value = all_vote_value.saturating_add(v.all_vote_value);
        all_vote_blind += v.all_vote_blind;
    }
    if all_vote_value < dao.quorum {
        return Err(format!("Quorum not reached ({all_vote_value} < {})", dao.quorum).into());
    }
    if early && all_vote_value < dao.early_exec_quorum {
        return Err(format!(
            "Early execution quorum not reached ({all_vote_value} < {})",
            dao.early_exec_quorum
        )
        .into());
    }
    if all_vote_value == 0
        || (yes_vote_value as u128) * (dao.approval_ratio_base as u128)
            < (all_vote_value as u128) * (dao.approval_ratio_quot as u128)
    {
        return Err("Proposal has not met the DAO approval ratio".into());
    }

    let dao_spend_hook = dao_spend_hook();
    let money_tree = load_tip_money_tree(db)?;
    let all_treasury =
        decode_unspent_dao_coins(db, &dao_spend_hook.to_bytes(), &dao_bulla.inner().to_repr())?;
    let token_pool: Vec<OwnCoin> = all_treasury
        .into_iter()
        .filter(|c| {
            c.note.token_id == proposal_coinattrs.token_id
                && assert_witness_at_tip(
                    &money_tree,
                    MerkleNode::from(c.coin.inner()),
                    c.leaf_position,
                )
                .is_ok()
        })
        .collect();
    let (spent_coins, change_value) =
        select_coins_deterministic(&token_pool, proposal_coinattrs.value)
            .map_err(|e| format!("insufficient DAO treasury balance: {e}"))?;

    let (mint_zkbin, mint_pk) = compile_zkbin(&decode_zkas(
        money_zkas,
        MONEY_CONTRACT_ZKAS_MINT_NS_V1,
        "Money Mint",
    )?)?;
    let (burn_zkbin, burn_pk) = compile_zkbin(&decode_zkas(
        money_zkas,
        MONEY_CONTRACT_ZKAS_BURN_NS_V1,
        "Money Burn",
    )?)?;
    let exec_ns = if early {
        DAO_CONTRACT_ZKAS_EARLY_EXEC_NS
    } else {
        DAO_CONTRACT_ZKAS_EXEC_NS
    };
    let (dao_exec_zkbin, dao_exec_pk) =
        compile_zkbin(&decode_zkas(dao_zkas, exec_ns, "DAO Exec")?)?;
    let (auth_xfer_zkbin, auth_xfer_pk) = compile_zkbin(&decode_zkas(
        dao_zkas,
        DAO_CONTRACT_ZKAS_AUTH_MONEY_TRANSFER_NS,
        "DAO AuthMoneyTransfer",
    )?)?;
    let (auth_enc_zkbin, auth_enc_pk) = compile_zkbin(&decode_zkas(
        dao_zkas,
        DAO_CONTRACT_ZKAS_AUTH_MONEY_TRANSFER_ENC_COIN_NS,
        "DAO AuthMoneyTransferEncCoin",
    )?)?;

    let input_user_data_blind = Blind::random(&mut OsRng);
    let mut inputs = Vec::with_capacity(spent_coins.len());
    let mut spent_nullifiers = Vec::with_capacity(spent_coins.len());
    for coin in &spent_coins {
        spent_nullifiers.push(coin.nullifier().inner().to_repr().to_vec());
        inputs.push(TransferCallInput {
            coin: coin.clone(),
            merkle_path: money_tree
                .witness(coin.leaf_position, 0)
                .map_err(|_| "treasury coin Merkle witness missing")?,
            user_data_blind: input_user_data_blind,
        });
    }

    let dao_coin_attrs = CoinAttributes {
        public_key: dao.notes_public_key,
        value: change_value,
        token_id: proposal_coinattrs.token_id,
        spend_hook: dao_spend_hook,
        user_data: dao_bulla.inner(),
        blind: Blind::random(&mut OsRng),
    };
    let (transfer_params, transfer_secrets) = TransferCallBuilder {
        clear_inputs: vec![],
        inputs,
        outputs: vec![proposal_coinattrs.clone(), dao_coin_attrs.clone()],
        mint_zkbin,
        mint_pk,
        burn_zkbin,
        burn_pk,
        output_memos: vec![],
    }
    .build()?;
    let mut transfer_data = vec![MoneyFunction::TransferV1 as u8];
    transfer_params.encode_async(&mut transfer_data).await?;
    let transfer_call = ContractCall {
        contract_id: *MONEY_CONTRACT_ID,
        data: transfer_data,
    };

    let exec_signature_secret = SecretKey::random(&mut OsRng);
    let early_sk_opt = if early { parsed.early_exec_sk } else { None };
    let (exec_params, exec_proofs) = DaoExecCall {
        proposal: proposal.clone(),
        dao: dao.clone(),
        yes_vote_value,
        all_vote_value,
        yes_vote_blind,
        all_vote_blind,
        signature_secret: exec_signature_secret,
        current_blockwindow,
    }
    .make(&exec_sk, &early_sk_opt, &dao_exec_zkbin, &dao_exec_pk)?;
    let mut exec_data = vec![DaoFunction::Exec as u8];
    exec_params.encode_async(&mut exec_data).await?;
    let exec_call = ContractCall {
        contract_id: *DAO_CONTRACT_ID,
        data: exec_data,
    };

    let (auth_params, auth_proofs) = DaoAuthMoneyTransferCall {
        proposal,
        proposal_coinattrs: vec![proposal_coinattrs],
        dao,
        input_user_data_blind,
        dao_coin_attrs,
    }
    .make(
        &auth_xfer_zkbin,
        &auth_xfer_pk,
        &auth_enc_zkbin,
        &auth_enc_pk,
    )?;
    let mut auth_data = vec![DaoFunction::AuthMoneyTransfer as u8];
    auth_params.encode_async(&mut auth_data).await?;
    let auth_call = ContractCall {
        contract_id: *DAO_CONTRACT_ID,
        data: auth_data,
    };

    let tx_builder = TransactionBuilder::new(
        ContractCallLeaf::new(exec_call, exec_proofs, vec![exec_signature_secret]),
        vec![
            DarkTree::new(
                ContractCallLeaf::new(auth_call, auth_proofs, vec![]),
                vec![],
                None,
                None,
            ),
            DarkTree::new(
                ContractCallLeaf::new(
                    transfer_call,
                    transfer_secrets.proofs,
                    transfer_secrets.signature_secrets,
                ),
                vec![],
                None,
                None,
            ),
        ],
    )?;

    Ok((tx_builder, spent_nullifiers))
}

struct DecodedVote {
    option: bool,
    yes_vote_blind: darkfi_sdk::crypto::ScalarBlind,
    all_vote_value: u64,
    all_vote_blind: darkfi_sdk::crypto::ScalarBlind,
    nullifiers: Vec<Nullifier>,
}

fn decode_votes_for_proposal(
    db: &WalletDb,
    proposal_bulla: &DaoProposalBulla,
    votes_sk: &SecretKey,
) -> Result<Vec<DecodedVote>, Box<dyn Error>> {
    let target = proposal_bulla.inner().to_repr();
    let mut out = Vec::new();
    for (_h, _tx, kind, bulla, payload) in db.list_all_dao_calls_asc()? {
        if kind != DAO_KIND_VOTE || bulla.as_slice() != target.as_slice() {
            continue;
        }
        let (note, nullifiers): (ElGamalEncryptedNote<4>, Vec<Nullifier>) =
            deserialize(&payload).map_err(|e| format!("vote payload decode: {e}"))?;
        let Ok(opened) = note.decrypt_unsafe(votes_sk) else {
            continue;
        };
        let Some(opt) = fp_to_u64(opened[0]) else {
            continue;
        };
        let Some(all_val) = fp_to_u64(opened[2]) else {
            continue;
        };
        if opt > 1 {
            continue;
        }
        out.push(DecodedVote {
            option: opt != 0,
            yes_vote_blind: Blind(fp_mod_fv(opened[1])),
            all_vote_value: all_val,
            all_vote_blind: Blind(fp_mod_fv(opened[3])),
            nullifiers,
        });
    }
    Ok(out)
}

#[allow(clippy::type_complexity)]
fn resolve_proposal(
    db: &WalletDb,
    parsed: &ParsedDao,
    dao_bulla: &DaoBulla,
    proposal_bulla: &DaoProposalBulla,
) -> Result<
    (
        DaoProposal,
        Option<CoinAttributes>,
        Option<u32>,
        Option<String>,
    ),
    Box<dyn Error>,
> {
    let b58 = proposal_bulla.to_string();
    if let Some((_pb, db_str, prop_bytes, attrs_bytes, mut mint_h, _tx_h, _exec_h, exec_tx)) =
        db.get_dao_proposal(&b58)?
    {
        let proposal: DaoProposal = deserialize(&prop_bytes)?;
        let attrs = attrs_bytes
            .as_deref()
            .map(deserialize::<CoinAttributes>)
            .transpose()?;
        if mint_h.is_none() {
            let target = proposal_bulla.inner().to_repr();
            for (h, _tx, kind, bulla, _payload) in db.list_all_dao_calls_asc()? {
                if kind == DAO_KIND_PROPOSE && bulla.as_slice() == target.as_slice() {
                    mint_h = Some(h);
                    break;
                }
            }
        }
        let _ = db_str;
        return Ok((proposal, attrs, mint_h, exec_tx));
    }

    // Fallback: decrypt proposal from synced `dao_calls` using `proposals_sk`.
    let proposals_sk = parsed.proposals_sk.ok_or(
        "Proposal not found locally and DAO TOML has no proposals_secret_key to decrypt on-chain proposals",
    )?;
    let target = proposal_bulla.inner().to_repr();
    for (h, tx, kind, bulla, payload) in db.list_all_dao_calls_asc()? {
        if kind != DAO_KIND_PROPOSE || bulla.as_slice() != target.as_slice() {
            continue;
        }
        let (_token_commit, note): (pallas::Base, AeadEncryptedNote) =
            deserialize(&payload).map_err(|e| format!("propose payload decode: {e}"))?;
        let proposal = note
            .decrypt::<DaoProposal>(&proposals_sk)
            .map_err(|_| "failed to decrypt proposal with proposals_secret_key")?;
        let prop_bytes = darkfi_serial::serialize(&proposal);
        let tx_hex = hex::encode(&tx);
        db.upsert_dao_proposal(
            &b58,
            &dao_bulla.to_string(),
            &prop_bytes,
            None,
            Some(h),
            Some(&tx_hex),
        )?;
        return Ok((proposal, None, Some(h), None));
    }
    Err(format!("DAO proposal '{b58}' not found locally or in synced dao_calls").into())
}

/// Reconstruct the DAO Merkle tree in chain order and locate `target_dao`'s leaf position.
pub fn build_daos_merkle_tree(
    db: &WalletDb,
    target_dao: &DaoBulla,
) -> Result<(MerkleTree, Position), Box<dyn Error>> {
    let calls = db.list_all_dao_calls_asc()?;
    build_daos_merkle_tree_from_calls(&calls, target_dao)
}

pub(crate) fn build_daos_merkle_tree_from_calls(
    calls: &[crate::db::DaoCallFullRow],
    target_dao: &DaoBulla,
) -> Result<(MerkleTree, Position), Box<dyn Error>> {
    let mut daos_tree = MerkleTree::new(u32::MAX as usize);
    let mut target_pos = None;
    for (_h, _tx, kind, bulla_bytes, _payload) in calls {
        if *kind != DAO_KIND_MINT || bulla_bytes.len() != 32 {
            continue;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bulla_bytes);
        let bulla = DaoBulla::from_bytes(arr)
            .map_err(|e| format!("invalid DAO bulla in dao_calls: {e}"))?;
        daos_tree.append(MerkleNode::from(bulla.inner()));
        if &bulla == target_dao {
            target_pos = daos_tree.mark();
        }
    }
    let pos = target_pos.ok_or_else(|| {
        format!("DAO bulla {target_dao} not found in synced DAO Mint records — run `moonshine sync` first")
    })?;
    Ok((daos_tree, pos))
}

fn load_tip_money_tree(db: &WalletDb) -> Result<MerkleTree, Box<dyn Error>> {
    let tree_bytes = db
        .get_meta("tree_state")?
        .ok_or("Money Merkle tree missing — run: moonshine sync --rebuild-merkle")?;
    Ok(Decodable::decode(&mut std::io::Cursor::new(&tree_bytes))?)
}

async fn build_money_nullifier_smt(
    client: &mut LightwalletClient,
    end_height: u32,
    tip: u32,
) -> Result<SmtMemoryFp, Box<dyn Error>> {
    let mut leaves: Vec<(pallas::Base, pallas::Base)> = Vec::new();
    let mut start = 0u32;
    let bound = end_height.min(tip);
    while start <= bound {
        let end = start.saturating_add(MAX_BLOCKS_PER_REQUEST - 1).min(bound);
        let (pad_start, pad_end) = require_padded_range(start, end, tip)?;
        let mut stream = client.get_nullifiers(pad_start, pad_end).await?;
        while let Some(nf_res) = stream.next().await {
            let upd = nf_res?;
            if !height_in_scan_window(upd.height, start, end) {
                continue;
            }
            for nf in upd.nullifiers {
                let Ok(arr) = <[u8; 32]>::try_from(nf.as_slice()) else {
                    continue;
                };
                if let Some(f) = pallas::Base::from_repr(arr).into_option() {
                    leaves.push((f, f));
                }
            }
        }
        start = end.saturating_add(1);
        if start == 0 {
            break;
        }
    }
    let mut smt = SmtMemoryFp::new(MemoryStorageFp::new(), PoseidonFp::new(), &EMPTY_NODES_FP);
    smt.insert_batch(leaves)?;
    Ok(smt)
}

async fn build_money_tree_at_height(
    client: &mut LightwalletClient,
    end_height: u32,
    tip: u32,
    owned_commitments: &HashSet<[u8; 32]>,
) -> Result<MerkleTree, Box<dyn Error>> {
    let mut tree = MerkleTree::new(u32::MAX as usize);
    tree.append(MerkleNode::from(pallas::Base::from(0u64)));
    let _ = tree.mark();

    let mut start = 0u32;
    let bound = end_height.min(tip);
    while start <= bound {
        let end = start.saturating_add(MAX_BLOCKS_PER_REQUEST - 1).min(bound);
        let (pad_start, pad_end) = require_padded_range(start, end, tip)?;
        let mut stream = client.get_note_commitments(pad_start, pad_end).await?;
        let mut by_h: BTreeMap<u32, Vec<Vec<u8>>> = BTreeMap::new();
        while let Some(nc_res) = stream.next().await {
            let nc = nc_res?;
            if !height_in_scan_window(nc.height, start, end) {
                continue;
            }
            by_h.entry(nc.height).or_default().extend(nc.coins);
        }
        for (_h, coins) in by_h {
            for coin in coins {
                let Ok(arr) = <[u8; 32]>::try_from(coin.as_slice()) else {
                    continue;
                };
                let Some(node) = MerkleNode::from_bytes(arr) else {
                    continue;
                };
                tree.append(node);
                if owned_commitments.contains(&arr) {
                    let _ = tree.mark();
                }
            }
        }
        start = end.saturating_add(1);
        if start == 0 {
            break;
        }
    }
    Ok(tree)
}

fn decode_unspent_regular_coins(
    db: &WalletDb,
    token_filter: Option<TokenId>,
) -> Result<Vec<OwnCoin>, Box<dyn Error>> {
    let rows = db.list_unspent_full()?;
    decode_coin_rows(rows, token_filter, true)
}

fn decode_unspent_dao_coins(
    db: &WalletDb,
    spend_hook: &[u8],
    dao_bulla: &[u8],
) -> Result<Vec<OwnCoin>, Box<dyn Error>> {
    let rows = db.list_unspent_dao_full(spend_hook, dao_bulla)?;
    decode_coin_rows(rows, None, false)
}

#[allow(clippy::type_complexity)]
fn decode_coin_rows(
    rows: Vec<(
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
    token_filter: Option<TokenId>,
    require_unhooked: bool,
) -> Result<Vec<OwnCoin>, Box<dyn Error>> {
    let mut out = Vec::new();
    for (
        _tx,
        _idx,
        val,
        tok_id,
        coin_b,
        val_b,
        tok_b,
        hook,
        udata,
        lpos,
        commitment,
        owner_secret,
    ) in rows
    {
        let Ok(val_u64) = u64::try_from(val) else {
            continue;
        };
        if coin_b.len() != 32
            || val_b.len() != 32
            || tok_b.len() != 32
            || udata.len() != 32
            || commitment.len() != 32
            || owner_secret.len() < 32
        {
            continue;
        }
        let Ok(coin_blind) = pallas::Base::decode(&mut std::io::Cursor::new(coin_b.as_slice()))
        else {
            continue;
        };
        let Ok(value_blind) = pallas::Scalar::decode(&mut std::io::Cursor::new(val_b.as_slice()))
        else {
            continue;
        };
        let Ok(token_blind) = pallas::Base::decode(&mut std::io::Cursor::new(tok_b.as_slice()))
        else {
            continue;
        };
        let Ok(user_data) = pallas::Base::decode(&mut std::io::Cursor::new(udata.as_slice()))
        else {
            continue;
        };
        let Ok(tok_raw) = hex::decode(&tok_id) else {
            continue;
        };
        let Ok(tok_arr) = <[u8; 32]>::try_from(tok_raw.as_slice()) else {
            continue;
        };
        let Ok(note_token_id) = TokenId::from_bytes(tok_arr) else {
            continue;
        };
        if let Some(req_tok) = token_filter {
            if note_token_id != req_tok {
                continue;
            }
        }
        let mut hook_bytes = [0u8; 32];
        if hook.len() == 32 {
            hook_bytes.copy_from_slice(&hook);
        } else if !hook.is_empty() {
            hook_bytes[0] = hook[0];
        }
        let Ok(spend_hook) = FuncId::from_bytes(hook_bytes) else {
            continue;
        };
        if require_unhooked && spend_hook != FuncId::none() {
            continue;
        }
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&owner_secret[..32]);
        let secret = SecretKey::from_bytes(sk_arr)
            .map_err(|e| format!("Invalid note owner secret: {e:?}"))?;
        let derived = CoinAttributes {
            public_key: PublicKey::from_secret(secret),
            value: val_u64,
            token_id: note_token_id,
            spend_hook,
            user_data,
            blind: Blind(coin_blind),
        }
        .to_coin();
        if derived.to_bytes().as_slice() != commitment.as_slice() {
            continue;
        }
        out.push(OwnCoin {
            coin: derived,
            note: MoneyNote {
                value: val_u64,
                token_id: note_token_id,
                coin_blind: Blind(coin_blind),
                value_blind: Blind(value_blind),
                token_blind: Blind(token_blind),
                spend_hook,
                user_data,
                memo: Vec::new(),
            },
            secret,
            leaf_position: Position::from(lpos as u64),
        });
    }
    Ok(out)
}

fn decode_zkas(
    bins: &[(String, Vec<u8>)],
    ns: &str,
    label: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    bins.iter()
        .find(|x| x.0 == ns)
        .map(|x| x.1.clone())
        .ok_or_else(|| format!("{label} circuit ({ns}) missing from lightwalletd").into())
}

fn compile_zkbin(bytes: &[u8]) -> Result<(ZkBinary, ProvingKey), Box<dyn Error>> {
    let zkbin = ZkBinary::decode(bytes, false)?;
    let pk = ProvingKey::build(zkbin.k, &ZkCircuit::new(empty_witnesses(&zkbin)?, &zkbin));
    Ok((zkbin, pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_dao_emits_drk_compatible_decimal_strings_and_roundtrips() {
        let db = WalletDb::in_memory().unwrap();
        let toml = create_dao(
            &db,
            "My \"Quoted\" DAO",
            200_000_000,
            100_000_000,
            150_000_000,
            0.67,
            "DRK",
        )
        .unwrap();
        assert!(toml.contains("proposer_limit = \"2\""), "got:\n{toml}");
        assert!(toml.contains("quorum = \"1\""), "got:\n{toml}");
        assert!(toml.contains("early_exec_quorum = \"1.5\""), "got:\n{toml}");
        assert!(toml.contains("approval_ratio = 0.67"), "got:\n{toml}");
        assert!(toml.contains("notes_secret_key = "));
        assert!(
            toml.contains(&format!("gov_token_id = \"{}\"", *DARK_TOKEN_ID)),
            "expected canonical Base58 DARK_TOKEN_ID in TOML, got:\n{toml}"
        );

        let val: toml::Value = toml::from_str(&toml).unwrap();
        assert!(val["proposer_limit"].is_str());
        assert!(val["approval_ratio"].is_float());

        let parsed = parse_dao_params(&toml, &db).unwrap();
        assert_eq!(parsed.gov_token_id, *DARK_TOKEN_ID);
        assert_eq!(parsed.proposer_limit, 200_000_000);
        assert_eq!(parsed.quorum, 100_000_000);
        assert_eq!(parsed.early_exec_quorum, 150_000_000);
        assert_eq!(parsed.approval_ratio_quot, 67);
        assert_eq!(parsed.approval_ratio_base, 100);
    }

    #[test]
    fn create_dao_with_hex_token_and_exact_ratio_float() {
        let db = WalletDb::in_memory().unwrap();
        let hex_drk = WalletDb::dark_token_id_hex();
        let toml = create_dao(&db, "HexDAO", 5, 5, 5, 1.0, &hex_drk).unwrap();
        let val: toml::Value = toml::from_str(&toml).unwrap();
        assert!(
            val["approval_ratio"].is_float(),
            "1.0 must serialize as TOML float"
        );
        let parsed = parse_dao_params(&toml, &db).unwrap();
        assert_eq!(parsed.gov_token_id, *DARK_TOKEN_ID);
        assert_eq!(parsed.approval_ratio_quot, 100);

        assert!(create_dao(&db, "BadNaN", 1, 1, 1, f64::NAN, "DRK").is_err());
        assert!(create_dao(&db, "BadInf", 1, 1, 1, f64::INFINITY, "DRK").is_err());
        assert!(create_dao(&db, "BadNeg", 1, 1, 1, -0.1, "DRK").is_err());
        assert!(create_dao(&db, "BadHi", 1, 1, 1, 1.01, "DRK").is_err());
    }

    #[test]
    fn parse_dao_params_accepts_optional_roles_and_rational_fields() {
        let db = WalletDb::in_memory().unwrap();
        let toml = create_dao(&db, "RoleDAO", 10, 20, 30, 0.5, "DRK").unwrap();
        // Strip all *_secret_key lines and explicit rational keys to verify public-only role parsing.
        let public_only: String = toml
            .lines()
            .filter(|l| !l.contains("_secret") && !l.starts_with("approval_ratio_"))
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = parse_dao_with_roles(&public_only, &db).unwrap();
        assert!(parsed.notes_sk.is_none());
        assert!(parsed.early_exec_sk.is_none());
        assert_eq!(parsed.dao.approval_ratio_quot, 50);
        assert_eq!(parsed.dao.approval_ratio_base, 100);

        // Exact rational override (e.g. 2/3) overrides float.
        let rational = format!("{public_only}\napproval_ratio_quot = 2\napproval_ratio_base = 3\n");
        let parsed_r = parse_dao_params(&rational, &db).unwrap();
        assert_eq!(parsed_r.approval_ratio_quot, 2);
        assert_eq!(parsed_r.approval_ratio_base, 3);

        let negative_quorum = public_only.replace("quorum = \"0.0000002\"", "quorum = -5");
        assert!(parse_dao_params(&negative_quorum, &db).is_err());

        let bad_ratio = public_only.replace("approval_ratio = 0.5", "approval_ratio = 2.0");
        assert!(parse_dao_params(&bad_ratio, &db).is_err());
    }

    #[test]
    fn build_daos_merkle_tree_tracks_leaf_and_witness() {
        let b1 = DaoBulla::from_bytes([1u8; 32]).unwrap();
        let b2 = DaoBulla::from_bytes([2u8; 32]).unwrap();
        let calls = vec![
            (10, vec![0u8; 32], 0, b1.inner().to_repr().to_vec(), vec![]),
            (11, vec![1u8; 32], 1, vec![9u8; 32], vec![]), // Propose (ignored in daos_tree)
            (12, vec![2u8; 32], 0, b2.inner().to_repr().to_vec(), vec![]),
        ];
        let (tree, pos) = build_daos_merkle_tree_from_calls(&calls, &b2).unwrap();
        assert_eq!(u64::from(pos), 1);
        assert!(tree.witness(pos, 0).is_ok());
    }
}
