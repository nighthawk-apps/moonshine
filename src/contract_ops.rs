//! Deployooor contract authority + deploy / lock.

use crate::db::WalletDb;
use darkfi::tx::{ContractCallLeaf, TransactionBuilder};
use darkfi_deployooor_contract::{
    client::{deploy_v1::DeployCallBuilder, lock_v1::LockCallBuilder},
    DeployFunction,
};
use darkfi_sdk::{
    crypto::{ContractId, Keypair, PublicKey, SecretKey, DEPLOYOOOR_CONTRACT_ID},
    tx::ContractCall,
};
use darkfi_serial::{deserialize, serialize, AsyncEncodable};
use rand_core::OsRng;
use std::error::Error;
use std::path::Path;
use std::str::FromStr;

/// Generate a deploy authority and store it.
pub fn generate_deploy(db: &WalletDb) -> Result<String, Box<dyn Error>> {
    let secret_key = SecretKey::random(&mut OsRng);
    let contract_id = ContractId::derive_public(PublicKey::from_secret(secret_key));
    let id = contract_id.to_string();
    db.insert_deploy_auth(&id, &serialize(&secret_key))?;
    Ok(id)
}

pub async fn build_deploy_builder(
    db: &WalletDb,
    deploy_auth: &str,
    wasm_path: &Path,
    deploy_ix: Option<&Path>,
) -> Result<TransactionBuilder, Box<dyn Error>> {
    let Some((sk_bytes, locked)) = db.get_deploy_auth(deploy_auth)? else {
        return Err(format!("unknown deploy authority '{deploy_auth}'").into());
    };
    if locked {
        return Err("contract is locked".into());
    }
    let secret: SecretKey = deserialize(&sk_bytes)?;
    let deploy_keypair = Keypair::new(secret);
    let auth_secret = deploy_keypair.secret;
    let wasm_bincode = std::fs::read(wasm_path)?;
    let deploy_ix = match deploy_ix {
        Some(p) => std::fs::read(p)?,
        None => Vec::new(),
    };
    let deploy_debris = DeployCallBuilder {
        deploy_keypair,
        wasm_bincode,
        deploy_ix,
    }
    .build()
    .map_err(|e| format!("deploy build: {e}"))?;
    let mut data = vec![DeployFunction::DeployV1 as u8];
    deploy_debris.params.encode_async(&mut data).await?;
    let call = ContractCall {
        contract_id: *DEPLOYOOOR_CONTRACT_ID,
        data,
    };
    Ok(TransactionBuilder::new(
        ContractCallLeaf::new(call, vec![], vec![auth_secret]),
        vec![],
    )?)
}

pub async fn build_lock_builder(
    db: &WalletDb,
    deploy_auth: &str,
) -> Result<TransactionBuilder, Box<dyn Error>> {
    let cid = ContractId::from_str(deploy_auth).map_err(|e| format!("contract id: {e}"))?;
    let Some((sk_bytes, locked)) = db.get_deploy_auth(&cid.to_string())? else {
        return Err(format!("unknown deploy authority '{deploy_auth}'").into());
    };
    if locked {
        return Err("contract already locked".into());
    }
    let secret: SecretKey = deserialize(&sk_bytes)?;
    let deploy_keypair = Keypair::new(secret);
    let auth_secret = deploy_keypair.secret;
    let lock_debris = LockCallBuilder { deploy_keypair }
        .build()
        .map_err(|e| format!("lock build: {e}"))?;
    let mut data = vec![DeployFunction::LockV1 as u8];
    lock_debris.params.encode_async(&mut data).await?;
    let call = ContractCall {
        contract_id: *DEPLOYOOOR_CONTRACT_ID,
        data,
    };
    Ok(TransactionBuilder::new(
        ContractCallLeaf::new(call, vec![], vec![auth_secret]),
        vec![],
    )?)
}
