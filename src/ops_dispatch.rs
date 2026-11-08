//! CLI dispatch for token / DAO / contract / synced-event views.

use crate::amount;
use crate::client::LightwalletClient;
use crate::config::Config;
use crate::fee_attach;
use crate::wallet::Wallet;
use crate::{contract_ops, dao_ops, token};
use clap::Subcommand;
use darkfi_money_contract::client::OwnCoin;
use darkfi_sdk::bridgetree::Position;
use darkfi::zk::halo2::Field;
use darkfi_sdk::crypto::keypair::Address;
use darkfi_sdk::crypto::{pasta_prelude::PrimeField, FuncId, PublicKey, SecretKey};
use darkfi_sdk::pasta::pallas;
use darkfi_serial::Decodable;
use std::error::Error;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Subcommand, Debug)]
pub enum TokenSubcommand {
    /// Create a mint authority (Money contract — not a WASM deploy)
    GenerateMint {
        #[arg(long)]
        alias: Option<String>,
    },
    Import {
        secret: String,
        token_blind: String,
        #[arg(long)]
        alias: Option<String>,
    },
    List,
    Mint {
        token: String,
        amount: String,
        recipient: String,
        #[arg(long, default_value_t = 5_000_000)]
        fee: u64,
        #[arg(long)]
        spend_hook: Option<String>,
        #[arg(long)]
        user_data: Option<String>,
    },
    Freeze {
        token: String,
        #[arg(long, default_value_t = 5_000_000)]
        fee: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum DaoSubcommand {
    /// Create DAO params and store them in the wallet
    Create {
        name: String,
        proposer_limit: String,
        quorum: String,
        early_exec_quorum: String,
        approval_ratio: f64,
        gov_token: String,
    },
    Import {
        name: String,
        #[arg(long)]
        file: PathBuf,
    },
    List,
    /// Print standard DAO execution spend hook (Dao::Exec)
    SpendHook,
    /// Check unspent treasury balance for a stored DAO
    Balance {
        name: String,
    },
    /// List compact DAO calls observed during sync
    Calls {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// View stored DAO details, bulla, and treasury payment address
    View { name: String },
    /// List synced DAO calls and proposals
    Proposals {
        name: Option<String>,
    },
    Mint {
        name: String,
        #[arg(long, default_value_t = 5_000_000)]
        fee: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum ContractSubcommand {
    GenerateDeploy,
    List,
    /// List synced Money/DAO/deploy function markers
    Events {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    Deploy {
        deploy_auth: String,
        wasm: PathBuf,
        #[arg(long)]
        deploy_ix: Option<PathBuf>,
        #[arg(long, default_value_t = 5_000_000)]
        fee: u64,
    },
    Lock {
        deploy_auth: String,
        #[arg(long, default_value_t = 5_000_000)]
        fee: u64,
    },
}

pub async fn run_token(
    w: &Wallet,
    config: &Config,
    sub: TokenSubcommand,
) -> Result<(), Box<dyn Error>> {
    match sub {
        TokenSubcommand::GenerateMint { alias } => {
            let tid = token::generate_mint(&w.db, alias.as_deref())?;
            println!("Mint authority stored.");
            println!("Token ID: {tid}");
            if let Some(a) = alias {
                println!("Alias:   {a}");
            }
        }
        TokenSubcommand::Import {
            secret,
            token_blind,
            alias,
        } => {
            let tid = token::import_mint(&w.db, &secret, &token_blind, alias.as_deref())?;
            println!("Imported mint authority for {tid}");
        }
        TokenSubcommand::List => {
            let rows = w.db.list_token_mints()?;
            if rows.is_empty() {
                println!("No token mint authorities. Try: moonshine token generate-mint --alias ANON");
                return Ok(());
            }
            for (tid, _, _, alias, frozen, fh) in rows {
                let a = alias.unwrap_or_else(|| "-".into());
                let st = if frozen {
                    format!("frozen{}", fh.map(|h| format!("@{h}")).unwrap_or_default())
                } else {
                    "mintable".into()
                };
                println!("{a:16} {tid}  ({st})");
            }
        }
        TokenSubcommand::Mint {
            token: tok,
            amount,
            recipient,
            fee,
            spend_hook,
            user_data,
        } => {
            let atomic = amount::parse_drk_atomic(&amount).map_err(|e| e.to_string())?;
            let recipient_pk = parse_address_pubkey(&recipient)?;
            let hook = spend_hook
                .as_deref()
                .map(parse_func_id)
                .transpose()?;
            let ud = user_data
                .as_deref()
                .map(parse_user_data)
                .transpose()?;
            let mut client = LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                .with_tor(config.use_tor);
            let zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            let (builder, tid) = token::build_mint_builder(
                &w.db,
                &tok,
                atomic,
                recipient_pk,
                hook,
                ud,
                &zkas,
            )
            .await?;
            broadcast_builder(w, config, builder, fee, &zkas).await?;
            println!("Minted token id: {tid}");
        }
        TokenSubcommand::Freeze { token: tok, fee } => {
            let mut client = LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                .with_tor(config.use_tor);
            let zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            let (builder, tid) = token::build_freeze_builder(&w.db, &tok, &zkas).await?;
            broadcast_builder(w, config, builder, fee, &zkas).await?;
            w.db.set_token_frozen(&tid.to_string(), None)?;
            println!("Marked {tid} frozen in wallet (confirm on-chain with sync).");
        }
    }
    Ok(())
}

pub async fn run_dao(
    w: &Wallet,
    config: &Config,
    sub: DaoSubcommand,
) -> Result<(), Box<dyn Error>> {
    match sub {
        DaoSubcommand::Create {
            name,
            proposer_limit,
            quorum,
            early_exec_quorum,
            approval_ratio,
            gov_token,
        } => {
            let parse_amount = |s: &str| -> Result<u64, Box<dyn Error>> {
                if let Ok(a) = amount::parse_drk_atomic(s) {
                    return Ok(a);
                }
                if let Ok(n) = s.parse::<u64>() {
                    return Ok(n);
                }
                Err(format!("invalid amount or atomic integer '{s}'").into())
            };
            let p_limit = parse_amount(&proposer_limit)?;
            let q = parse_amount(&quorum)?;
            let eq = parse_amount(&early_exec_quorum)?;
            let toml = dao_ops::create_dao(
                &w.db,
                &name,
                p_limit,
                q,
                eq,
                approval_ratio,
                &gov_token,
            )?;
            println!("{toml}");
            println!("Stored DAO '{name}' in wallet.");
        }
        DaoSubcommand::Import { name, file } => {
            let toml = std::fs::read_to_string(&file)?;
            w.db.upsert_dao_record(&name, &toml, None, None)?;
            println!("Imported DAO '{name}' from {}", file.display());
        }
        DaoSubcommand::List => {
            let rows = w.db.list_dao_records()?;
            if rows.is_empty() {
                println!("No DAOs stored. Try: moonshine dao create …");
                return Ok(());
            }
            for (name, bulla, tx) in rows {
                println!(
                    "{name:16} bulla={} tx={}",
                    bulla.unwrap_or_else(|| "-".into()),
                    tx.unwrap_or_else(|| "-".into())
                );
            }
        }
        DaoSubcommand::SpendHook => {
            let hook = dao_ops::dao_spend_hook();
            println!("DAO Exec Spend Hook: {hook}");
        }
        DaoSubcommand::Balance { name } => {
            let Some(toml_str) = w.db.get_dao_toml(&name)? else {
                return Err(format!("DAO '{name}' not found").into());
            };
            let dao = dao_ops::parse_dao_params(&toml_str, &w.db)?;
            let dao_bulla = dao.to_bulla();
            let dao_spend_hook = dao_ops::dao_spend_hook();
            let coins = w.db.list_unspent_for_dao(
                &dao_spend_hook.to_bytes(),
                &dao_bulla.inner().to_repr(),
            )?;
            if coins.is_empty() {
                println!("DAO '{name}' treasury has no unspent coins recorded.");
                println!("Bulla: {dao_bulla}");
                println!("Spend Hook: {dao_spend_hook}");
                let network = if config.network == "mainnet" {
                    darkfi_sdk::crypto::keypair::Network::Mainnet
                } else {
                    darkfi_sdk::crypto::keypair::Network::Testnet
                };
                let std_addr = darkfi_sdk::crypto::keypair::Address::from(
                    darkfi_sdk::crypto::keypair::StandardAddress::from_public(
                        network,
                        dao.notes_public_key,
                    ),
                );
                println!("Treasury Address: {std_addr}");
                return Ok(());
            }
            println!("DAO '{name}' Treasury Balance (Bulla: {dao_bulla}):");
            let mut by_token: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for (_tx, _idx, val, tok) in coins {
                *by_token.entry(tok).or_insert(0) += val as u64;
            }
            for (tok, total) in by_token {
                let is_drk = crate::db::WalletDb::is_drk_token(&tok);
                if is_drk {
                    println!("  DRK:   {} DRK ({total} atomic)", amount::format_drk_atomic(total));
                } else {
                    println!("  {tok}: {total} atomic units");
                }
            }
        }
        DaoSubcommand::Calls { limit } => {
            let rows = w.db.list_dao_calls(limit)?;
            if rows.is_empty() {
                println!("No compact DAO calls stored yet. Sync first.");
                return Ok(());
            }
            for (h, tx, kind, bulla) in rows {
                println!(
                    "h={h} kind={kind} bulla={} tx={}",
                    bs58::encode(&bulla).into_string(),
                    hex::encode(&tx)
                );
            }
        }
        DaoSubcommand::View { name } => {
            let Some(toml_str) = w.db.get_dao_toml(&name)? else {
                return Err(format!("DAO '{name}' not found").into());
            };
            if let Ok(dao) = dao_ops::parse_dao_params(&toml_str, &w.db) {
                let dao_bulla = dao.to_bulla();
                let dao_spend_hook = dao_ops::dao_spend_hook();
                let network = if config.network == "mainnet" {
                    darkfi_sdk::crypto::keypair::Network::Mainnet
                } else {
                    darkfi_sdk::crypto::keypair::Network::Testnet
                };
                let std_addr = darkfi_sdk::crypto::keypair::Address::from(
                    darkfi_sdk::crypto::keypair::StandardAddress::from_public(
                        network,
                        dao.notes_public_key,
                    ),
                );
                println!("DAO: {name}");
                println!("  Bulla:             {dao_bulla}");
                println!("  Spend Hook:        {dao_spend_hook}");
                println!("  Treasury Address:  {std_addr}");
                println!("  Gov Token:         {}", dao.gov_token_id);
                println!("  Proposer Limit:    {} atomic", dao.proposer_limit);
                println!("  Quorum:            {} atomic", dao.quorum);
                println!("  Early Exec Quorum: {} atomic", dao.early_exec_quorum);
                println!(
                    "  Approval Ratio:    {:.2}% ({}/{})",
                    (dao.approval_ratio_quot as f64 / dao.approval_ratio_base as f64) * 100.0,
                    dao.approval_ratio_quot,
                    dao.approval_ratio_base
                );
                println!("\nStored TOML:\n{toml_str}");
            } else {
                println!("{toml_str}");
            }
        }
        DaoSubcommand::Proposals { name: _ } => {
            let calls = w.db.list_dao_calls_full(100)?;
            if calls.is_empty() {
                println!("No compact DAO calls observed yet. Run `moonshine sync` first.");
                return Ok(());
            }
            println!("Observed DAO Calls & Proposals ({} total synced calls):", calls.len());
            for (h, tx, kind, bulla, payload) in calls {
                let kind_str = match kind {
                    0 => "Mint",
                    1 => "Propose",
                    2 => "Vote",
                    3 => "Exec",
                    _ => "Unknown",
                };
                let bulla_b58 = bs58::encode(&bulla).into_string();
                let tx_hex = hex::encode(&tx);
                println!("  [Block {h}] Kind: {kind_str:7} | Bulla: {bulla_b58} | TX: {tx_hex} (payload: {} bytes)", payload.len());
            }
        }
        DaoSubcommand::Mint { name, fee } => {
            let mut client = LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                .with_tor(config.use_tor);
            let zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::DAO_CONTRACT_ID.to_string())
                    .await?,
            );
            let (builder, bulla) = dao_ops::build_mint_builder(&w.db, &name, &zkas).await?;
            let money_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            broadcast_builder(w, config, builder, fee, &money_zkas).await?;
            println!("DAO bulla: {bulla}");
        }
    }
    Ok(())
}

pub async fn run_contract(
    w: &Wallet,
    config: &Config,
    sub: ContractSubcommand,
) -> Result<(), Box<dyn Error>> {
    match sub {
        ContractSubcommand::GenerateDeploy => {
            let id = contract_ops::generate_deploy(&w.db)?;
            println!("Deploy authority created.");
            println!("Contract ID: {id}");
        }
        ContractSubcommand::List => {
            let rows = w.db.list_deploy_auths()?;
            if rows.is_empty() {
                println!("No deploy authorities. Try: moonshine contract generate-deploy");
                return Ok(());
            }
            for (id, locked, h) in rows {
                let st = if locked {
                    format!("locked{}", h.map(|x| format!("@{x}")).unwrap_or_default())
                } else {
                    "unlocked".into()
                };
                println!("{id}  ({st})");
            }
        }
        ContractSubcommand::Events { limit } => {
            let rows = w.db.list_func_events(limit)?;
            if rows.is_empty() {
                println!("No func events stored yet. Sync first.");
                return Ok(());
            }
            for (h, tx, code) in rows {
                println!("h={h} func={code} tx={}", hex::encode(&tx));
            }
        }
        ContractSubcommand::Deploy {
            deploy_auth,
            wasm,
            deploy_ix,
            fee,
        } => {
            let builder = contract_ops::build_deploy_builder(
                &w.db,
                &deploy_auth,
                &wasm,
                deploy_ix.as_deref(),
            )
            .await?;
            let mut client = LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                .with_tor(config.use_tor);
            let money_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            broadcast_builder(w, config, builder, fee, &money_zkas).await?;
        }
        ContractSubcommand::Lock { deploy_auth, fee } => {
            let builder = contract_ops::build_lock_builder(&w.db, &deploy_auth).await?;
            let mut client = LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                .with_tor(config.use_tor);
            let money_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            broadcast_builder(w, config, builder, fee, &money_zkas).await?;
            w.db.set_deploy_locked(&deploy_auth, None)?;
            println!("Marked {deploy_auth} locked in wallet (confirm on-chain with sync).");
        }
    }
    Ok(())
}

async fn broadcast_builder(
    w: &Wallet,
    config: &Config,
    builder: darkfi::tx::TransactionBuilder,
    fee: u64,
    money_zkas: &[(String, Vec<u8>)],
) -> Result<(), Box<dyn Error>> {
    let (tx, nf) = if fee == 0 {
        let mut builder = builder;
        (builder.build_signed()?, Vec::new())
    } else {
        let wallet_secret = SecretKey::from_bytes(w.wallet_secret_bytes()?)
            .map_err(|e| format!("Invalid wallet secret: {e:?}"))?;
        // Prefer tx-local TransferV1 change (drk/0f985c7cf); only pick a wallet
        // DRK coin when that path cannot cover the fee.
        let fallback = pick_fee_coin(w, fee).ok();
        let (fee_coin, tree) = match &fallback {
            Some((c, t)) => (Some(c.clone()), Some(t)),
            None => (None, None),
        };
        let (tx, _cm, nf) = fee_attach::finish_with_native_fee(
            builder,
            fee,
            fee_coin,
            tree,
            money_zkas,
            &[wallet_secret],
        )
        .await?;
        (tx, nf)
    };
    let mut raw = Vec::new();
    darkfi_serial::Encodable::encode(&tx, &mut raw)?;
    let last_tx_path = Wallet::write_last_tx(&w.name, &raw);
    let mut client = LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
        .with_tor(config.use_tor);
    let resp = client
        .send_transaction(raw, Vec::new(), Vec::new(), Vec::new())
        .await?;
    if !resp.error.is_empty() && resp.error != "0" {
        return Err(format!("SendTransaction error: {}", resp.error).into());
    }
    if !nf.is_empty() {
        let _ = w.db.mark_note_spent(&nf);
    }
    let tx_hash = format!("{}", tx.hash());
    println!("✅ Broadcast via lightwalletd");
    println!("TX hash: {tx_hash}");
    println!("Explorer: {}/tx/{tx_hash}", config.explorer_base_url());
    println!("Last tx hex: {}", last_tx_path.display());
    Ok(())
}

fn pick_fee_coin(
    w: &Wallet,
    fee: u64,
) -> Result<(OwnCoin, darkfi_sdk::crypto::MerkleTree), Box<dyn Error>> {
    let tree_bytes = w
        .db
        .get_meta("tree_state")?
        .ok_or("Money Merkle tree missing — run: moonshine sync --rebuild-merkle")?;
    let tree: darkfi_sdk::crypto::MerkleTree =
        Decodable::decode(&mut std::io::Cursor::new(&tree_bytes))?;
    let unspent = w.db.list_unspent_full()?;
    let mut best: Option<OwnCoin> = None;
    for (_tx, _idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner_secret) in unspent {
        if (val as u64) < fee || !crate::db::WalletDb::is_drk_token(&tok) {
            continue;
        }
        if owner_secret.len() < 32 || cb.len() < 32 || vb.len() < 32 || tb.len() < 32 {
            continue;
        }
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&owner_secret[..32]);
        let secret = SecretKey::from_bytes(sk_arr)
            .map_err(|e| format!("Invalid note owner secret: {e:?}"))?;
        let coin_blind = {
            let mut a = [0u8; 32];
            a.copy_from_slice(&cb[..32]);
            pallas::Base::from_repr(a)
                .into_option()
                .ok_or("bad coin_blind")?
        };
        let value_blind = {
            let mut a = [0u8; 32];
            a.copy_from_slice(&vb[..32]);
            pallas::Scalar::from_repr(a)
                .into_option()
                .ok_or("bad value_blind")?
        };
        let token_blind = {
            let mut a = [0u8; 32];
            a.copy_from_slice(&tb[..32]);
            pallas::Base::from_repr(a)
                .into_option()
                .ok_or("bad token_blind")?
        };
        let token_id = darkfi_money_contract::model::TokenId::from_bytes(
            hex::decode(&tok)?.as_slice().try_into().map_err(|_| "token id len")?,
        )?;
        let mut hook_bytes = [0u8; 32];
        if hook.len() == 32 {
            hook_bytes.copy_from_slice(&hook);
        } else if !hook.is_empty() {
            hook_bytes[0] = hook[0];
        }
        let spend_hook = FuncId::from_bytes(hook_bytes)?;
        let user_data = if ud.len() == 32 {
            let mut a = [0u8; 32];
            a.copy_from_slice(&ud);
            pallas::Base::from_repr(a)
                .into_option()
                .unwrap_or(pallas::Base::ZERO)
        } else {
            pallas::Base::ZERO
        };
        let note = darkfi_money_contract::client::MoneyNote {
            value: val as u64,
            token_id,
            coin_blind: darkfi_sdk::crypto::Blind(coin_blind),
            value_blind: darkfi_sdk::crypto::Blind(value_blind),
            token_blind: darkfi_sdk::crypto::Blind(token_blind),
            spend_hook,
            user_data,
            memo: Vec::new(),
        };
        let derived = darkfi_money_contract::model::CoinAttributes {
            public_key: PublicKey::from_secret(secret),
            value: val as u64,
            token_id,
            spend_hook,
            user_data,
            blind: darkfi_sdk::crypto::Blind(coin_blind),
        }
        .to_coin();
        if derived.to_bytes().as_slice() != commitment.as_slice() {
            continue;
        }
        let coin = OwnCoin {
            coin: derived,
            note,
            secret,
            leaf_position: Position::from(lpos as u64),
        };
        if best.as_ref().map(|c| c.note.value).unwrap_or(0) < coin.note.value {
            best = Some(coin);
        }
    }
    let coin = best.ok_or_else(|| {
        format!(
            "no DRK coin covering fee {fee}. Sync/rebuild-merkle, or lower --fee"
        )
    })?;
    Ok((coin, tree))
}


fn zkas_pairs(resp: crate::client::proto::ZkasResponse) -> Vec<(String, Vec<u8>)> {
    resp.bincodes
        .into_iter()
        .map(|kv| (kv.namespace, kv.bincode))
        .collect()
}

fn parse_address_pubkey(s: &str) -> Result<PublicKey, Box<dyn Error>> {
    let addr = Address::from_str(s).map_err(|e| format!("address: {e}"))?;
    Ok(*addr.public_key())
}

pub fn parse_func_id(s: &str) -> Result<FuncId, Box<dyn Error>> {
    FuncId::from_str(s).map_err(|e| format!("spend_hook: {e}").into())
}

pub fn parse_user_data(s: &str) -> Result<pallas::Base, Box<dyn Error>> {
    if let Ok(n) = s.parse::<u64>() {
        return Ok(pallas::Base::from(n));
    }
    // Try base58 (standard encoding for Bullas in drk and deploy-a-dao guide)
    if let Ok(bytes) = bs58::decode(s).into_vec() {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            if let Some(f) = pallas::Base::from_repr(arr).into_option() {
                return Ok(f);
            }
        }
    }
    // Try hex (with or without 0x prefix)
    let clean_hex = s.trim_start_matches("0x");
    if let Ok(bytes) = hex::decode(clean_hex) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            if let Some(f) = pallas::Base::from_repr(arr).into_option() {
                return Ok(f);
            }
        }
    }
    Err("user_data must be u64 integer, 32-byte base58 bulla, or 32-byte hex".into())
}
