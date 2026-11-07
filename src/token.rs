//! Money token mint / freeze — light-client builders via lightwalletd zkas.

use crate::db::WalletDb;
use darkfi::{
    tx::{ContractCallLeaf, TransactionBuilder},
    zk::{proof::ProvingKey, vm::ZkCircuit, vm_heap::empty_witnesses},
    zkas::ZkBinary,
};
use darkfi_money_contract::{
    client::{
        auth_token_freeze_v1::AuthTokenFreezeCallBuilder,
        auth_token_mint_v1::AuthTokenMintCallBuilder, token_mint_v1::TokenMintCallBuilder,
    },
    model::{CoinAttributes, TokenAttributes, TokenId},
    MoneyFunction, MONEY_CONTRACT_ZKAS_AUTH_TOKEN_FREEZE_NS_V1,
    MONEY_CONTRACT_ZKAS_AUTH_TOKEN_MINT_NS_V1, MONEY_CONTRACT_ZKAS_TOKEN_MINT_NS_V1,
};
use darkfi::zk::halo2::Field;
use darkfi_sdk::{
    crypto::{
        contract_id::MONEY_CONTRACT_ID, poseidon_hash, BaseBlind, Blind, FuncId, FuncRef, Keypair,
        PublicKey, SecretKey,
    },
    dark_tree::DarkTree,
    pasta::pallas,
    tx::ContractCall,
};
use darkfi_serial::{deserialize, serialize, AsyncEncodable};
use rand_core::OsRng;
use std::error::Error;
use std::str::FromStr;

pub fn derive_token_attributes(
    mint_authority: SecretKey,
    token_blind: BaseBlind,
) -> TokenAttributes {
    let auth_func_id = FuncRef {
        contract_id: *MONEY_CONTRACT_ID,
        func_code: MoneyFunction::AuthTokenMintV1 as u8,
    }
    .to_func_id();
    let (mint_auth_x, mint_auth_y) = PublicKey::from_secret(mint_authority).xy();
    TokenAttributes {
        auth_parent: auth_func_id,
        user_data: poseidon_hash([mint_auth_x, mint_auth_y]),
        blind: token_blind,
    }
}

/// Create a new mint authority and store it in the wallet.
pub fn generate_mint(db: &WalletDb, alias: Option<&str>) -> Result<TokenId, Box<dyn Error>> {
    let mint_authority = SecretKey::random(&mut OsRng);
    let token_blind = BaseBlind::random(&mut OsRng);
    let attrs = derive_token_attributes(mint_authority, token_blind);
    let token_id = attrs.to_token_id();
    db.insert_token_mint(
        &token_id.to_string(),
        &serialize(&mint_authority),
        &serialize(&token_blind),
        alias,
    )?;
    Ok(token_id)
}

pub fn import_mint(
    db: &WalletDb,
    secret_hex_or_b58: &str,
    blind_hex_or_b58: &str,
    alias: Option<&str>,
) -> Result<TokenId, Box<dyn Error>> {
    let mint_authority = parse_secret(secret_hex_or_b58)?;
    let token_blind = parse_base_blind(blind_hex_or_b58)?;
    let attrs = derive_token_attributes(mint_authority, token_blind);
    let token_id = attrs.to_token_id();
    db.insert_token_mint(
        &token_id.to_string(),
        &serialize(&mint_authority),
        &serialize(&token_blind),
        alias,
    )?;
    Ok(token_id)
}

fn parse_secret(s: &str) -> Result<SecretKey, Box<dyn Error>> {
    if let Ok(bytes) = bs58::decode(s).into_vec() {
        if let Ok(sk) = deserialize::<SecretKey>(&bytes) {
            return Ok(sk);
        }
    }
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    Ok(deserialize(&bytes)?)
}

fn parse_base_blind(s: &str) -> Result<BaseBlind, Box<dyn Error>> {
    if let Ok(bytes) = bs58::decode(s).into_vec() {
        if let Ok(b) = deserialize::<BaseBlind>(&bytes) {
            return Ok(b);
        }
    }
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    Ok(deserialize(&bytes)?)
}

fn load_authority(
    db: &WalletDb,
    token_or_alias: &str,
) -> Result<(TokenId, SecretKey, BaseBlind), Box<dyn Error>> {
    let Some((tid, auth_bytes, blind_bytes, frozen)) = db.get_token_mint(token_or_alias)? else {
        return Err(format!("unknown token mint '{token_or_alias}' — generate-mint or import first").into());
    };
    if frozen {
        return Err(format!("token mint '{tid}' is frozen in this wallet").into());
    }
    let mint_authority: SecretKey = deserialize(&auth_bytes)?;
    let token_blind: BaseBlind = deserialize(&blind_bytes)?;
    let token_id = TokenId::from_str(&tid).map_err(|e| format!("bad token id in wallet: {e}"))?;
    Ok((token_id, mint_authority, token_blind))
}

/// Build AuthTokenMint + TokenMint leaves. Caller attaches fee and broadcasts.
pub async fn build_mint_builder(
    db: &WalletDb,
    token_or_alias: &str,
    amount_atomic: u64,
    recipient: PublicKey,
    spend_hook: Option<FuncId>,
    user_data: Option<pallas::Base>,
    zkas_bins: &[(String, Vec<u8>)],
) -> Result<(TransactionBuilder, TokenId), Box<dyn Error>> {
    let (token_id, mint_sk, token_blind) = load_authority(db, token_or_alias)?;
    let token_attrs = derive_token_attributes(mint_sk, token_blind);
    let mint_authority = Keypair::new(mint_sk);
    assert_eq!(token_id, token_attrs.to_token_id());

    let mint_zkbin_bytes = &zkas_bins
        .iter()
        .find(|x| x.0 == MONEY_CONTRACT_ZKAS_TOKEN_MINT_NS_V1)
        .ok_or("TokenMint circuit missing from lightwalletd")?
        .1;
    let auth_zkbin_bytes = &zkas_bins
        .iter()
        .find(|x| x.0 == MONEY_CONTRACT_ZKAS_AUTH_TOKEN_MINT_NS_V1)
        .ok_or("AuthTokenMint circuit missing from lightwalletd")?
        .1;
    let mint_zkbin = ZkBinary::decode(mint_zkbin_bytes, false)?;
    let auth_mint_zkbin = ZkBinary::decode(auth_zkbin_bytes, false)?;
    let mint_pk = ProvingKey::build(
        mint_zkbin.k,
        &ZkCircuit::new(empty_witnesses(&mint_zkbin)?, &mint_zkbin),
    );
    let auth_mint_pk = ProvingKey::build(
        auth_mint_zkbin.k,
        &ZkCircuit::new(empty_witnesses(&auth_mint_zkbin)?, &auth_mint_zkbin),
    );

    let coin_attrs = CoinAttributes {
        public_key: recipient,
        value: amount_atomic,
        token_id,
        spend_hook: spend_hook.unwrap_or(FuncId::none()),
        user_data: user_data.unwrap_or(pallas::Base::ZERO),
        blind: Blind::random(&mut OsRng),
    };

    let auth_debris = AuthTokenMintCallBuilder {
        coin_attrs: coin_attrs.clone(),
        token_attrs: token_attrs.clone(),
        mint_keypair: mint_authority,
        auth_mint_zkbin,
        auth_mint_pk,
    }
    .build()?;
    let mut auth_data = vec![MoneyFunction::AuthTokenMintV1 as u8];
    auth_debris.params.encode_async(&mut auth_data).await?;
    let auth_call = ContractCall {
        contract_id: *MONEY_CONTRACT_ID,
        data: auth_data,
    };

    let mint_debris = TokenMintCallBuilder {
        coin_attrs,
        token_attrs,
        mint_zkbin,
        mint_pk,
    }
    .build()?;
    let mut mint_data = vec![MoneyFunction::TokenMintV1 as u8];
    mint_debris.params.encode_async(&mut mint_data).await?;
    let mint_call = ContractCall {
        contract_id: *MONEY_CONTRACT_ID,
        data: mint_data,
    };

    let tx_builder = TransactionBuilder::new(
        ContractCallLeaf::new(mint_call, mint_debris.proofs, vec![]),
        vec![DarkTree::new(
            ContractCallLeaf::new(auth_call, auth_debris.proofs, vec![mint_authority.secret]),
            vec![],
            None,
            None,
        )],
    )?;
    Ok((tx_builder, token_id))
}

pub async fn build_freeze_builder(
    db: &WalletDb,
    token_or_alias: &str,
    zkas_bins: &[(String, Vec<u8>)],
) -> Result<(TransactionBuilder, TokenId), Box<dyn Error>> {
    let (token_id, mint_sk, token_blind) = load_authority(db, token_or_alias)?;
    let token_attrs = derive_token_attributes(mint_sk, token_blind);
    let mint_authority = Keypair::new(mint_sk);

    let auth_freeze_bytes = &zkas_bins
        .iter()
        .find(|x| x.0 == MONEY_CONTRACT_ZKAS_AUTH_TOKEN_FREEZE_NS_V1)
        .ok_or("AuthTokenFreeze circuit missing from lightwalletd")?
        .1;
    let auth_freeze_zkbin = ZkBinary::decode(auth_freeze_bytes, false)?;
    let auth_freeze_pk = ProvingKey::build(
        auth_freeze_zkbin.k,
        &ZkCircuit::new(empty_witnesses(&auth_freeze_zkbin)?, &auth_freeze_zkbin),
    );

    let freeze_debris = AuthTokenFreezeCallBuilder {
        mint_keypair: mint_authority,
        token_attrs,
        auth_freeze_zkbin,
        auth_freeze_pk,
    }
    .build()?;
    let mut data = vec![MoneyFunction::AuthTokenFreezeV1 as u8];
    freeze_debris.params.encode_async(&mut data).await?;
    let freeze_call = ContractCall {
        contract_id: *MONEY_CONTRACT_ID,
        data,
    };
    let tx_builder = TransactionBuilder::new(
        ContractCallLeaf::new(freeze_call, freeze_debris.proofs, vec![mint_authority.secret]),
        vec![],
    )?;
    Ok((tx_builder, token_id))
}
