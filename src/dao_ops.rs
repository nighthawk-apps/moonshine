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
    crypto::{contract_id::DAO_CONTRACT_ID, BaseBlind, Keypair, SecretKey},
    tx::ContractCall,
};
use darkfi_serial::AsyncEncodable;
use rand_core::OsRng;
use std::error::Error;
use std::str::FromStr;

/// Create DAO params (secrets) and store under `name`. Returns TOML text.
pub fn create_dao(
    db: &WalletDb,
    name: &str,
    proposer_limit: u64,
    quorum: u64,
    early_exec_quorum: u64,
    approval_ratio: f64,
    gov_token_id: &str,
) -> Result<String, Box<dyn Error>> {
    if !(0.0..=1.0).contains(&approval_ratio) {
        return Err("approval_ratio must be in 0.0..=1.0".into());
    }
    let notes = Keypair::random(&mut OsRng);
    let proposer = Keypair::random(&mut OsRng);
    let proposals = Keypair::random(&mut OsRng);
    let votes = Keypair::random(&mut OsRng);
    let exec = Keypair::random(&mut OsRng);
    let early_exec = Keypair::random(&mut OsRng);
    let bulla_blind = BaseBlind::random(&mut OsRng);

    // Encode secrets as base58 blobs for the TOML (same idea as drk).
    let toml = format!(
        "# Moonshine DAO params — keep secret\n\
         name = \"{name}\"\n\
         proposer_limit = {proposer_limit}\n\
         quorum = {quorum}\n\
         early_exec_quorum = {early_exec_quorum}\n\
         approval_ratio = {approval_ratio}\n\
         gov_token_id = \"{gov_token_id}\"\n\
         notes_secret = \"{}\"\n\
         proposer_secret = \"{}\"\n\
         proposals_secret = \"{}\"\n\
         votes_secret = \"{}\"\n\
         exec_secret = \"{}\"\n\
         early_exec_secret = \"{}\"\n\
         bulla_blind = \"{}\"\n",
        bs58::encode(darkfi_serial::serialize(&notes.secret)).into_string(),
        bs58::encode(darkfi_serial::serialize(&proposer.secret)).into_string(),
        bs58::encode(darkfi_serial::serialize(&proposals.secret)).into_string(),
        bs58::encode(darkfi_serial::serialize(&votes.secret)).into_string(),
        bs58::encode(darkfi_serial::serialize(&exec.secret)).into_string(),
        bs58::encode(darkfi_serial::serialize(&early_exec.secret)).into_string(),
        bs58::encode(darkfi_serial::serialize(&bulla_blind)).into_string(),
    );
    db.upsert_dao_record(name, &toml, None, None)?;
    Ok(toml)
}

fn sk_from_b58(s: &str) -> Result<SecretKey, Box<dyn Error>> {
    let bytes = bs58::decode(s).into_vec()?;
    Ok(darkfi_serial::deserialize(&bytes)?)
}

fn blind_from_b58(s: &str) -> Result<BaseBlind, Box<dyn Error>> {
    let bytes = bs58::decode(s).into_vec()?;
    Ok(darkfi_serial::deserialize(&bytes)?)
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
    let get = |k: &str| -> Result<&str, Box<dyn Error>> {
        table
            .get(k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("DAO TOML missing {k}").into())
    };
    let notes_sk = sk_from_b58(get("notes_secret")?)?;
    let proposer_sk = sk_from_b58(get("proposer_secret")?)?;
    let proposals_sk = sk_from_b58(get("proposals_secret")?)?;
    let votes_sk = sk_from_b58(get("votes_secret")?)?;
    let exec_sk = sk_from_b58(get("exec_secret")?)?;
    let early_exec_sk = sk_from_b58(get("early_exec_secret")?)?;
    let bulla_blind = blind_from_b58(get("bulla_blind")?)?;
    let proposer_limit = table
        .get("proposer_limit")
        .and_then(|v| v.as_integer())
        .ok_or("proposer_limit")? as u64;
    let quorum = table.get("quorum").and_then(|v| v.as_integer()).ok_or("quorum")? as u64;
    let early_exec_quorum = table
        .get("early_exec_quorum")
        .and_then(|v| v.as_integer())
        .ok_or("early_exec_quorum")? as u64;
    let approval_ratio = table
        .get("approval_ratio")
        .and_then(|v| v.as_float())
        .ok_or("approval_ratio")?;
    let gov_token = get("gov_token_id")?;
    let gov_token_id = darkfi_money_contract::model::TokenId::from_str(gov_token)
        .map_err(|e| format!("gov_token_id: {e}"))?;

    // Match drk: approval_ratio is stored as (quot, base) integers in Dao.
    let approval_ratio_quot = 100u64;
    let approval_ratio_base = (approval_ratio * approval_ratio_quot as f64).round() as u64;

    let dao = Dao {
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
    };

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
