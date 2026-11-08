//! DAO create / mint for Moonshine light wallet.

use crate::db::WalletDb;
use darkfi::{
    tx::{ContractCallLeaf, TransactionBuilder},
    zk::{proof::ProvingKey, vm::ZkCircuit, vm_heap::empty_witnesses},
    zkas::ZkBinary,
};
use darkfi_dao_contract::{
    client::make_mint_call, model::Dao, DaoFunction, DAO_CONTRACT_ZKAS_MINT_NS,
};
use darkfi_sdk::{
    crypto::{contract_id::DAO_CONTRACT_ID, BaseBlind, FuncId, FuncRef, Keypair, SecretKey},
    tx::ContractCall,
};
use darkfi_serial::AsyncEncodable;
use rand_core::OsRng;
use std::error::Error;
use std::str::FromStr;

/// Standard spend hook for the DarkFi DAO contract (Dao::Exec).
pub fn dao_spend_hook() -> FuncId {
    FuncRef {
        contract_id: *DAO_CONTRACT_ID,
        func_code: DaoFunction::Exec as u8,
    }
    .to_func_id()
}

/// Create DAO params (secrets) and store under `name`. Returns TOML text.
pub fn create_dao(
    db: &WalletDb,
    name: &str,
    proposer_limit: u64,
    quorum: u64,
    early_exec_quorum: u64,
    approval_ratio: f64,
    gov_token: &str,
) -> Result<String, Box<dyn Error>> {
    if !(0.0..=1.0).contains(&approval_ratio) {
        return Err("approval_ratio must be in 0.0..=1.0".into());
    }
    let resolved_token_hex = db.resolve_token_id(gov_token)?;
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
    let early_exec_sec_b58 = bs58::encode(darkfi_serial::serialize(&early_exec.secret)).into_string();
    let bulla_blind_b58 = bs58::encode(darkfi_serial::serialize(&bulla_blind)).into_string();

    // Emit both drk-compatible keys (*_secret_key, *_public_key) and Moonshine keys
    let toml = format!(
        "# Moonshine DAO params — keep secret\n\
         name = \"{name}\"\n\
         proposer_limit = {proposer_limit}\n\
         quorum = {quorum}\n\
         early_exec_quorum = {early_exec_quorum}\n\
         approval_ratio = {approval_ratio}\n\
         gov_token_id = \"{resolved_token_hex}\"\n\
         notes_secret = \"{notes_sec_b58}\"\n\
         notes_secret_key = \"{notes_sec_b58}\"\n\
         notes_public_key = \"{}\"\n\
         proposer_secret = \"{proposer_sec_b58}\"\n\
         proposer_secret_key = \"{proposer_sec_b58}\"\n\
         proposer_public_key = \"{}\"\n\
         proposals_secret = \"{proposals_sec_b58}\"\n\
         proposals_secret_key = \"{proposals_sec_b58}\"\n\
         proposals_public_key = \"{}\"\n\
         votes_secret = \"{votes_sec_b58}\"\n\
         votes_secret_key = \"{votes_sec_b58}\"\n\
         votes_public_key = \"{}\"\n\
         exec_secret = \"{exec_sec_b58}\"\n\
         exec_secret_key = \"{exec_sec_b58}\"\n\
         exec_public_key = \"{}\"\n\
         early_exec_secret = \"{early_exec_sec_b58}\"\n\
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

pub fn blind_from_b58(s: &str) -> Result<BaseBlind, Box<dyn Error>> {
    let bytes = bs58::decode(s).into_vec()?;
    Ok(darkfi_serial::deserialize(&bytes)?)
}

/// Parse Dao model from a TOML string (supports both drk format and Moonshine format).
pub fn parse_dao_params(toml_str: &str, db: &WalletDb) -> Result<Dao, Box<dyn Error>> {
    let value = toml::from_str::<toml::Value>(toml_str)?;
    let table = value.as_table().ok_or("DAO TOML root must be a table")?;

    let get_str = |k1: &str, k2: &str| -> Result<&str, Box<dyn Error>> {
        if let Some(v) = table.get(k1).and_then(|v| v.as_str()) {
            return Ok(v);
        }
        if let Some(v) = table.get(k2).and_then(|v| v.as_str()) {
            return Ok(v);
        }
        Err(format!("DAO TOML missing {k1} / {k2}").into())
    };

    let notes_sk = sk_from_b58(get_str("notes_secret", "notes_secret_key")?)?;
    let proposer_sk = sk_from_b58(get_str("proposer_secret", "proposer_secret_key")?)?;
    let proposals_sk = sk_from_b58(get_str("proposals_secret", "proposals_secret_key")?)?;
    let votes_sk = sk_from_b58(get_str("votes_secret", "votes_secret_key")?)?;
    let exec_sk = sk_from_b58(get_str("exec_secret", "exec_secret_key")?)?;
    let early_exec_sk = sk_from_b58(get_str("early_exec_secret", "early_exec_secret_key")?)?;
    let bulla_blind = blind_from_b58(
        table
            .get("bulla_blind")
            .and_then(|v| v.as_str())
            .ok_or("bulla_blind")?,
    )?;

    let parse_u64_or_str = |k: &str| -> Result<u64, Box<dyn Error>> {
        if let Some(v) = table.get(k) {
            if let Some(i) = v.as_integer() {
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
    let approval_ratio = table
        .get("approval_ratio")
        .and_then(|v| v.as_float())
        .ok_or("approval_ratio")?;

    let raw_gov_token = table
        .get("gov_token_id")
        .and_then(|v| v.as_str())
        .ok_or("gov_token_id")?;
    let resolved_gov_token = db.resolve_token_id(raw_gov_token)?;
    let gov_token_id = darkfi_money_contract::model::TokenId::from_str(&resolved_gov_token)
        .map_err(|e| format!("gov_token_id: {e}"))?;

    // Approval ratio: base = 100, quot = ratio * 100 (matching drk).
    let approval_ratio_base = 100u64;
    let approval_ratio_quot = (approval_ratio * approval_ratio_base as f64).round() as u64;

    Ok(Dao {
        proposer_limit,
        quorum,
        early_exec_quorum,
        approval_ratio_quot,
        approval_ratio_base,
        gov_token_id,
        notes_public_key: Keypair::new(notes_sk).public,
        proposer_public_key: Keypair::new(proposer_sk).public,
        proposals_public_key: Keypair::new(proposals_sk).public,
        votes_public_key: Keypair::new(votes_sk).public,
        exec_public_key: Keypair::new(exec_sk).public,
        early_exec_public_key: Keypair::new(early_exec_sk).public,
        bulla_blind,
    })
}

/// Mint a stored DAO on-chain (Dao::Mint). Caller attaches fee + broadcasts.
pub async fn build_mint_builder(
    db: &WalletDb,
    name: &str,
    zkas_bins: &[(String, Vec<u8>)],
) -> Result<(TransactionBuilder, String), Box<dyn Error>> {
    let Some(toml) = db.get_dao_toml(name)? else {
        return Err(format!("DAO '{name}' not found — create or import first").into());
    };
    let value = toml::from_str::<toml::Value>(&toml)?;
    let table = value.as_table().ok_or("DAO TOML root must be a table")?;
    let get_str = |k1: &str, k2: &str| -> Result<&str, Box<dyn Error>> {
        if let Some(v) = table.get(k1).and_then(|v| v.as_str()) {
            return Ok(v);
        }
        if let Some(v) = table.get(k2).and_then(|v| v.as_str()) {
            return Ok(v);
        }
        Err(format!("DAO TOML missing {k1} / {k2}").into())
    };

    let notes_sk = sk_from_b58(get_str("notes_secret", "notes_secret_key")?)?;
    let proposer_sk = sk_from_b58(get_str("proposer_secret", "proposer_secret_key")?)?;
    let proposals_sk = sk_from_b58(get_str("proposals_secret", "proposals_secret_key")?)?;
    let votes_sk = sk_from_b58(get_str("votes_secret", "votes_secret_key")?)?;
    let exec_sk = sk_from_b58(get_str("exec_secret", "exec_secret_key")?)?;
    let early_exec_sk = sk_from_b58(get_str("early_exec_secret", "early_exec_secret_key")?)?;

    let dao = parse_dao_params(&toml, db)?;

    let mint_bytes = &zkas_bins
        .iter()
        .find(|x| x.0 == DAO_CONTRACT_ZKAS_MINT_NS)
        .ok_or("DAO Mint circuit missing from lightwalletd")?
        .1;
    let dao_mint_zkbin = ZkBinary::decode(mint_bytes, false)?;
    let dao_mint_pk = ProvingKey::build(
        dao_mint_zkbin.k,
        &ZkCircuit::new(empty_witnesses(&dao_mint_zkbin)?, &dao_mint_zkbin),
    );

    let (params, proofs) = make_mint_call(
        &dao,
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
