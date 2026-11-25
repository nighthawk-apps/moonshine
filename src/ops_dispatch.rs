//! CLI dispatch for token / DAO / contract / synced-event views.

use crate::amount;
use crate::client::LightwalletClient;
use crate::config::Config;
use crate::fee_attach;
use crate::tx_status;
use crate::wallet::Wallet;
use crate::{contract_ops, dao_ops, token};
use clap::Subcommand;
use darkfi::zk::halo2::Field;
use darkfi_money_contract::client::OwnCoin;
use darkfi_sdk::bridgetree::Position;
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
    View {
        name: String,
    },
    /// List synced DAO calls and proposals
    Proposals {
        name: Option<String>,
    },
    Mint {
        name: String,
        #[arg(long, default_value_t = 5_000_000)]
        fee: u64,
    },
    /// Create and broadcast a DAO treasury transfer proposal
    Propose {
        name: String,
        recipient: String,
        amount: String,
        #[arg(long, default_value = "DRK")]
        token: String,
        #[arg(long, default_value_t = 1)]
        duration_blockwindows: u64,
        #[arg(long, default_value_t = 5_000_000)]
        fee: u64,
    },
    /// Vote yes or no on a DAO proposal
    Vote {
        name: String,
        proposal_bulla: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        no: bool,
        #[arg(long, default_value_t = 5_000_000)]
        fee: u64,
    },
    /// Execute an approved DAO transfer proposal
    Exec {
        name: String,
        proposal_bulla: String,
        #[arg(long)]
        early: Option<bool>,
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
            tx_status::begin("asset-create", "local");
            let tid = token::generate_mint(&w.db, alias.as_deref())?;
            tx_status::emit(
                "asset-create",
                "local",
                "success",
                "local",
                "",
                None,
                &tid.to_string(),
                None,
                "mint-authority",
                "",
            );
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
            tx_status::begin("asset-create", "import");
            let tid = token::import_mint(&w.db, &secret, &token_blind, alias.as_deref())?;
            tx_status::emit(
                "asset-create",
                "import",
                "success",
                "local",
                "",
                None,
                &tid.to_string(),
                None,
                "mint-authority",
                "",
            );
            println!("Imported mint authority for {tid}");
        }
        TokenSubcommand::List => {
            let rows = w.db.list_token_mints()?;
            if rows.is_empty() {
                println!(
                    "No token mint authorities. Try: moonshine token generate-mint --alias ANON"
                );
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
            tx_status::begin("token-mint", "build");
            let atomic = amount::parse_drk_atomic(&amount).map_err(|e| e.to_string())?;
            let recipient_pk = parse_address_pubkey_for_network(&recipient, &config.network)?;
            let hook = spend_hook.as_deref().map(parse_func_id).transpose()?;
            let ud = user_data.as_deref().map(parse_user_data).transpose()?;
            let mut client =
                LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            crate::sync::preflight_server(&mut client, &w.db, &config.server_url, &config.network)
                .await?;
            let zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            let (builder, tid) =
                token::build_mint_builder(&w.db, &tok, atomic, recipient_pk, hook, ud, &zkas)
                    .await?;
            broadcast_builder(
                w,
                config,
                builder,
                fee,
                &zkas,
                "token-mint",
                &tid.to_string(),
                atomic,
                "",
                Some(recipient_pk),
                &[],
            )
            .await?;
            println!("Minted token id: {tid}");
        }
        TokenSubcommand::Freeze { token: tok, fee } => {
            tx_status::begin("burn", "build");
            let mut client =
                LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            crate::sync::preflight_server(&mut client, &w.db, &config.server_url, &config.network)
                .await?;
            let zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            let (builder, tid) = token::build_freeze_builder(&w.db, &tok, &zkas).await?;
            broadcast_builder(
                w,
                config,
                builder,
                fee,
                &zkas,
                "burn",
                &tid.to_string(),
                0,
                "freeze-mint-authority",
                None,
                &[],
            )
            .await?;
            w.db.set_token_frozen(&tid.to_string(), None)?;
            println!("Marked {tid} frozen in wallet (confirm on-chain with sync).");
            tx_status::emit(
                "burn",
                "local",
                "success",
                "confirming",
                "",
                None,
                &tid.to_string(),
                None,
                "freeze-marked-locally",
                "",
            );
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
            tx_status::begin("dao-create", "sign");
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
            let toml =
                dao_ops::create_dao(&w.db, &name, p_limit, q, eq, approval_ratio, &gov_token)?;
            println!("{toml}");
            println!("Stored DAO '{name}' in wallet.");
            tx_status::emit(
                "dao-create",
                "sign",
                "success",
                "local",
                "",
                None,
                &gov_token,
                None,
                "signing-keys",
                "",
            );
            tx_status::emit(
                "dao-sign",
                "sign",
                "success",
                "local",
                "",
                None,
                &gov_token,
                None,
                &format!("dao={name}"),
                "",
            );
        }
        DaoSubcommand::Import { name, file } => {
            tx_status::begin("dao-create", "import");
            let toml = std::fs::read_to_string(&file)?;
            w.db.upsert_dao_record(&name, &toml, None, None)?;
            println!("Imported DAO '{name}' from {}", file.display());
            tx_status::emit(
                "dao-create",
                "import",
                "success",
                "local",
                "",
                None,
                "",
                None,
                &format!("dao={name}"),
                "",
            );
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
            let coins = w
                .db
                .list_unspent_for_dao(&dao_spend_hook.to_bytes(), &dao_bulla.inner().to_repr())?;
            if coins.is_empty() {
                println!("DAO '{name}' treasury has no unspent coins recorded.");
                println!("Bulla: {dao_bulla}");
                println!("Spend Hook: {dao_spend_hook}");
                let network = Wallet::sdk_network(&config.network);
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
            let mut by_token: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for (_tx, _idx, val, tok) in coins {
                let val_u64 = u64::try_from(val).unwrap_or(0);
                let entry = by_token.entry(tok).or_insert(0);
                *entry = entry.saturating_add(val_u64);
            }
            for (tok, total) in by_token {
                let is_drk = crate::db::WalletDb::is_drk_token(&tok);
                if is_drk {
                    println!(
                        "  DRK:   {} DRK ({total} atomic)",
                        amount::format_drk_atomic(total)
                    );
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
                let network = Wallet::sdk_network(&config.network);
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
        DaoSubcommand::Proposals { name } => {
            let filter_bulla: Option<([u8; 32], String)> = if let Some(ref dao_name) = name {
                let Some(toml_str) = w.db.get_dao_toml(dao_name)? else {
                    return Err(format!("DAO '{dao_name}' not found").into());
                };
                let dao = dao_ops::parse_dao_params(&toml_str, &w.db)?;
                let bulla = dao.to_bulla();
                Some((bulla.inner().to_repr(), bulla.to_string()))
            } else {
                None
            };
            let mut calls = w.db.list_dao_calls_full(100)?;
            if let Some((ref target_bytes, ref target_b58)) = filter_bulla {
                calls.retain(|(_, _, _, bulla, _)| {
                    bulla.as_slice() == target_bytes.as_slice()
                        || bs58::encode(bulla).into_string() == *target_b58
                });
            }
            if calls.is_empty() {
                if let Some(dao_name) = name {
                    println!(
                        "No compact DAO calls observed for '{dao_name}'. Run `moonshine sync` first."
                    );
                } else {
                    println!("No compact DAO calls observed yet. Run `moonshine sync` first.");
                }
                return Ok(());
            }
            println!(
                "Observed DAO Calls & Proposals ({} total synced calls):",
                calls.len()
            );
            for (h, tx, kind, bulla, payload) in calls {
                let kind_str = match kind {
                    0 => "Mint",
                    1 => "Propose",
                    2 => "Vote",
                    3 => "Exec",
                    4 => "AuthMoneyTransfer",
                    _ => "Unknown",
                };
                let bulla_b58 = bs58::encode(&bulla).into_string();
                let tx_hex = hex::encode(&tx);
                println!("  [Block {h}] Kind: {kind_str:17} | Bulla: {bulla_b58} | TX: {tx_hex} (payload: {} bytes)", payload.len());
            }
        }
        DaoSubcommand::Mint { name, fee } => {
            tx_status::begin("dao-mint", "build");
            let mut client =
                LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            crate::sync::preflight_server(&mut client, &w.db, &config.server_url, &config.network)
                .await?;
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
            let tx_hash = broadcast_builder(
                w,
                config,
                builder,
                fee,
                &money_zkas,
                "dao-mint",
                "",
                0,
                &format!("dao={name}"),
                None,
                &[],
            )
            .await?;
            if let Some(toml) = w.db.get_dao_toml(&name)? {
                w.db.upsert_dao_record(&name, &toml, Some(&bulla), Some(&tx_hash))?;
            }
            println!("DAO bulla: {bulla}");
        }
        DaoSubcommand::Propose {
            name,
            recipient,
            amount: amount_str,
            token,
            duration_blockwindows,
            fee,
        } => {
            tx_status::begin("dao-propose", "build");
            let recipient_pk = parse_address_pubkey_for_network(&recipient, &config.network)?;
            let atomic = amount::parse_drk_atomic(&amount_str).map_err(|e| e.to_string())?;
            let token_id = dao_ops::normalize_token_id(&w.db, &token)?;
            let mut client =
                LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            crate::sync::preflight_server(&mut client, &w.db, &config.server_url, &config.network)
                .await?;
            let dao_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::DAO_CONTRACT_ID.to_string())
                    .await?,
            );
            let (builder, prop_bulla, dao_bulla, prop_bytes, coin_attrs_bytes) =
                dao_ops::build_propose_builder(
                    &w.db,
                    &mut client,
                    &name,
                    recipient_pk,
                    atomic,
                    token_id,
                    duration_blockwindows,
                    &dao_zkas,
                )
                .await?;
            let money_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            let tx_hash = broadcast_builder(
                w,
                config,
                builder,
                fee,
                &money_zkas,
                "dao-propose",
                &token_id.to_string(),
                atomic,
                &format!("dao={name}"),
                None,
                &[],
            )
            .await?;
            w.db.upsert_dao_proposal(
                &prop_bulla,
                &dao_bulla,
                &prop_bytes,
                Some(&coin_attrs_bytes),
                None,
                Some(&tx_hash),
            )?;
            println!("Proposal bulla: {prop_bulla}");
        }
        DaoSubcommand::Vote {
            name,
            proposal_bulla,
            yes,
            no,
            fee,
        } => {
            if yes == no {
                return Err("Specify exactly one of --yes or --no".into());
            }
            tx_status::begin("dao-vote", "build");
            let mut client =
                LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            crate::sync::preflight_server(&mut client, &w.db, &config.server_url, &config.network)
                .await?;
            let dao_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::DAO_CONTRACT_ID.to_string())
                    .await?,
            );
            let builder = dao_ops::build_vote_builder(
                &w.db,
                &mut client,
                &name,
                &proposal_bulla,
                yes,
                &dao_zkas,
            )
            .await?;
            let money_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            broadcast_builder(
                w,
                config,
                builder,
                fee,
                &money_zkas,
                "dao-vote",
                "",
                0,
                &format!("dao={name},vote={}", if yes { "yes" } else { "no" }),
                None,
                &[],
            )
            .await?;
        }
        DaoSubcommand::Exec {
            name,
            proposal_bulla,
            early,
            fee,
        } => {
            tx_status::begin("dao-exec", "build");
            let mut client =
                LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            crate::sync::preflight_server(&mut client, &w.db, &config.server_url, &config.network)
                .await?;
            let dao_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::DAO_CONTRACT_ID.to_string())
                    .await?,
            );
            let money_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            let (builder, spent_treasury_nfs) = dao_ops::build_exec_builder(
                &w.db,
                &mut client,
                &name,
                &proposal_bulla,
                early,
                &dao_zkas,
                &money_zkas,
            )
            .await?;
            let tx_hash = broadcast_builder(
                w,
                config,
                builder,
                fee,
                &money_zkas,
                "dao-exec",
                "",
                0,
                &format!("dao={name}"),
                None,
                &spent_treasury_nfs,
            )
            .await?;
            w.db.set_dao_proposal_executed(proposal_bulla.trim(), None, Some(&tx_hash))?;
            println!("Executed DAO proposal: {proposal_bulla}");
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
            tx_status::begin("asset-create", "local");
            let id = contract_ops::generate_deploy(&w.db)?;
            tx_status::emit(
                "asset-create",
                "local",
                "success",
                "local",
                "",
                None,
                &id.to_string(),
                None,
                "deploy-authority",
                "",
            );
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
            tx_status::begin("contract-deploy", "build");
            let builder = contract_ops::build_deploy_builder(
                &w.db,
                &deploy_auth,
                &wasm,
                deploy_ix.as_deref(),
            )
            .await?;
            let mut client =
                LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            crate::sync::preflight_server(&mut client, &w.db, &config.server_url, &config.network)
                .await?;
            let money_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            broadcast_builder(
                w,
                config,
                builder,
                fee,
                &money_zkas,
                "contract-deploy",
                &deploy_auth,
                0,
                "",
                None,
                &[],
            )
            .await?;
        }
        ContractSubcommand::Lock { deploy_auth, fee } => {
            tx_status::begin("contract-lock", "build");
            let builder = contract_ops::build_lock_builder(&w.db, &deploy_auth).await?;
            let mut client =
                LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            crate::sync::preflight_server(&mut client, &w.db, &config.server_url, &config.network)
                .await?;
            let money_zkas = zkas_pairs(
                client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?,
            );
            broadcast_builder(
                w,
                config,
                builder,
                fee,
                &money_zkas,
                "contract-lock",
                &deploy_auth,
                0,
                "",
                None,
                &[],
            )
            .await?;
            w.db.set_deploy_locked(&deploy_auth, None)?;
            println!("Marked {deploy_auth} locked in wallet (confirm on-chain with sync).");
        }
    }
    Ok(())
}

fn collect_wallet_secrets(w: &Wallet) -> Result<Vec<SecretKey>, Box<dyn Error>> {
    let mut secrets = Vec::new();
    for raw in w.db.get_all_secrets()? {
        if raw.len() >= 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw[..32]);
            if let Ok(sk) = SecretKey::from_bytes(arr) {
                secrets.push(sk);
            }
        }
    }
    if secrets.is_empty() {
        let primary = SecretKey::from_bytes(w.wallet_secret_bytes()?)
            .map_err(|e| format!("Invalid wallet secret: {e:?}"))?;
        secrets.push(primary);
    }
    Ok(secrets)
}

async fn visible_money_output_notes(
    tx: &darkfi::tx::Transaction,
) -> Result<Vec<(u32, darkfi_sdk::crypto::note::AeadEncryptedNote)>, Box<dyn Error>> {
    use darkfi_money_contract::{
        model::{MoneyFeeParamsV1, MoneyTokenMintParamsV1, MoneyTransferParamsV1},
        MoneyFunction,
    };
    use darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID;
    use darkfi_serial::deserialize_async;

    let mut out = Vec::new();
    let mut idx = 0u32;
    for call in &tx.calls {
        if call.data.contract_id != *MONEY_CONTRACT_ID || call.data.data.is_empty() {
            continue;
        }
        let data = &call.data.data;
        let notes = match MoneyFunction::try_from(data[0]) {
            Ok(MoneyFunction::TransferV1) => {
                let p = deserialize_async::<MoneyTransferParamsV1>(&data[1..]).await?;
                p.outputs
                    .into_iter()
                    .filter(|o| !o.tx_local)
                    .map(|o| o.note)
                    .collect()
            }
            Ok(MoneyFunction::FeeV1) => {
                if data.len() < 10 {
                    Vec::new()
                } else {
                    let p = deserialize_async::<MoneyFeeParamsV1>(&data[9..]).await?;
                    if p.output.tx_local {
                        Vec::new()
                    } else {
                        vec![p.output.note]
                    }
                }
            }
            Ok(MoneyFunction::TokenMintV1) => {
                let p = deserialize_async::<MoneyTokenMintParamsV1>(&data[1..]).await?;
                vec![p.enc_note]
            }
            _ => Vec::new(),
        };
        for note in notes {
            out.push((idx, note));
            idx = idx.saturating_add(1);
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn broadcast_builder(
    w: &Wallet,
    config: &Config,
    builder: darkfi::tx::TransactionBuilder,
    fee: u64,
    money_zkas: &[(String, Vec<u8>)],
    kind: &str,
    token: &str,
    amount: u64,
    detail: &str,
    recipient_pk: Option<PublicKey>,
    extra_spent_nullifiers: &[Vec<u8>],
) -> Result<String, Box<dyn Error>> {
    tx_status::phase("sign");
    let wallet_secrets = collect_wallet_secrets(w)?;
    let (tx, nf) = if fee == 0 {
        let mut builder = builder;
        (builder.build_signed()?, Vec::new())
    } else {
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
            &wallet_secrets,
        )
        .await?;
        (tx, nf)
    };
    let tx_hash = format!("{}", tx.hash());
    tx_status::emit(
        kind,
        "sign",
        "success",
        "waiting",
        &tx_hash,
        None,
        token,
        Some(amount),
        detail,
        "",
    );
    let mut raw = Vec::new();
    darkfi_serial::Encodable::encode(&tx, &mut raw)?;
    let last_tx_path = Wallet::write_last_tx(&w.name, &raw);
    tx_status::phase("broadcast");
    let mut client = LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
        .with_tor(config.use_tor);

    // Attach UnifOMR clues for FeeV1 change / TokenMintV1 / DAO treasury change when enabled.
    let (primary_clue, extra_clues, payment_index) = if config.experimental_unifomr {
        let outputs = visible_money_output_notes(&tx).await?;
        let total_outputs = outputs.len() as u32;
        let own_indexes: Vec<u32> = outputs
            .iter()
            .filter(|(_idx, note)| {
                wallet_secrets.iter().any(|s| {
                    note.decrypt::<darkfi_money_contract::client::MoneyNote>(s)
                        .is_ok()
                })
            })
            .map(|(idx, _)| *idx)
            .collect();
        let p_idx = (0..total_outputs)
            .find(|idx| !own_indexes.contains(idx))
            .unwrap_or(0);
        let own_clue_pk = w.wallet_secret_bytes().ok().and_then(|sb| {
            darkfi_lightwalletd::unifomr::clue_keypair_from_wallet(
                &sb,
                Wallet::network_byte(&config.network),
            )
            .ok()
            .map(|(_sk, pk)| pk)
        });
        let primary = if let (Some(rpk), false) = (recipient_pk, own_indexes.contains(&p_idx)) {
            let net_byte = Wallet::network_byte(&config.network);
            let rpk_bytes = rpk.to_bytes();
            match (
                client.get_light_info().await,
                client.get_clue_public_key(rpk_bytes.to_vec()).await,
            ) {
                (Ok(info), Ok(resp)) if info.directory_attest_pubkey.len() == 32 => {
                    match darkfi_lightwalletd::unifomr::verify_directory_attestation(
                        &info.directory_attest_pubkey,
                        net_byte,
                        resp.key_version,
                        &rpk_bytes,
                        &resp.clue_public_key,
                        &resp.ownership_proof,
                    )
                    .and_then(|_| {
                        darkfi_lightwalletd::unifomr::deserialize_public_key(&resp.clue_public_key)
                    }) {
                        Ok(pk) => darkfi_lightwalletd::unifomr::build_omr_clue_from_pk(&pk),
                        Err(e) => {
                            eprintln!("Warning: skipping recipient UnifOMR clue ({e})");
                            Vec::new()
                        }
                    }
                }
                _ => Vec::new(),
            }
        } else if own_indexes.contains(&p_idx) {
            own_clue_pk
                .as_ref()
                .map(darkfi_lightwalletd::unifomr::build_omr_clue_from_pk)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let extra = match &own_clue_pk {
            Some(pk) => own_indexes
                .iter()
                .copied()
                .filter(|idx| *idx != p_idx)
                .map(|output_index| crate::client::proto::OutputOmrClue {
                    output_index,
                    omr_clue: darkfi_lightwalletd::unifomr::build_omr_clue_from_pk(pk),
                })
                .collect(),
            None => Vec::new(),
        };
        (primary, extra, p_idx)
    } else {
        (Vec::new(), Vec::new(), 0)
    };

    let resp = client
        .send_transaction(raw, primary_clue, Vec::new(), extra_clues, payment_index)
        .await?;
    if !resp.error.is_empty() && resp.error != "0" {
        return Err(format!("SendTransaction error: {}", resp.error).into());
    }
    let confirm_hash: [u8; 32] = if resp.tx_hash.len() == 32 {
        resp.tx_hash
            .clone()
            .try_into()
            .unwrap_or(*tx.hash().inner())
    } else {
        *tx.hash().inner()
    };
    client
        .confirm_transaction_in_mempool(&confirm_hash)
        .await
        .map_err(|e| {
            eprintln!("TX hex written to {}", last_tx_path.display());
            format!(
                "Transaction not confirmed in lightwalletd mempool ({e}). Refusing to mark as Broadcasted."
            )
        })?;
    let reserved_at = w.db.get_sync_state().map(|(h, _)| h).unwrap_or(0);
    if !nf.is_empty() {
        let _ = w.db.reserve_note(&nf, reserved_at);
    }
    for extra_nf in extra_spent_nullifiers {
        if !extra_nf.is_empty() {
            let _ = w.db.reserve_note(extra_nf, reserved_at);
        }
    }
    let _ = w.db.insert_typed(
        &tx_hash,
        0,
        "outgoing",
        kind,
        amount as i64,
        token,
        None,
        None,
    );
    println!("Broadcasted (confirmed in lightwalletd mempool; awaiting block confirmation).");
    println!("TX hash: {tx_hash}");
    tx_status::emit(
        kind,
        "broadcast",
        "success",
        "confirming",
        &tx_hash,
        Some(0),
        token,
        Some(amount),
        detail,
        "",
    );
    println!("Explorer: {}/tx/{tx_hash}", config.explorer_base_url());
    println!("Last tx hex: {}", last_tx_path.display());
    Ok(tx_hash)
}

fn pick_fee_coin(
    w: &Wallet,
    fee: u64,
) -> Result<(OwnCoin, darkfi_sdk::crypto::MerkleTree), Box<dyn Error>> {
    let tree_bytes =
        w.db.get_meta("tree_state")?
            .ok_or("Money Merkle tree missing — run: moonshine sync --rebuild-merkle")?;
    let tree: darkfi_sdk::crypto::MerkleTree =
        Decodable::decode(&mut std::io::Cursor::new(&tree_bytes))?;
    let unspent = w.db.list_unspent_full()?;
    let mut best: Option<OwnCoin> = None;
    for (_tx, _idx, val, tok, cb, vb, tb, hook, ud, lpos, commitment, owner_secret) in unspent {
        let Ok(val_u64) = u64::try_from(val) else {
            continue;
        };
        if val_u64 < fee || !crate::db::WalletDb::is_drk_token(&tok) {
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
            hex::decode(&tok)?
                .as_slice()
                .try_into()
                .map_err(|_| "token id len")?,
        )?;
        let mut hook_bytes = [0u8; 32];
        if hook.len() == 32 {
            hook_bytes.copy_from_slice(&hook);
        } else if !hook.is_empty() {
            hook_bytes[0] = hook[0];
        }
        let spend_hook = FuncId::from_bytes(hook_bytes)?;
        if spend_hook != FuncId::none() {
            continue;
        }
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
            value: val_u64,
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
            value: val_u64,
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
        format!("no DRK coin covering fee {fee}. Sync/rebuild-merkle, or lower --fee")
    })?;
    Ok((coin, tree))
}

fn zkas_pairs(resp: crate::client::proto::ZkasResponse) -> Vec<(String, Vec<u8>)> {
    resp.bincodes
        .into_iter()
        .map(|kv| (kv.namespace, kv.bincode))
        .collect()
}

fn parse_address_pubkey_for_network(s: &str, network: &str) -> Result<PublicKey, Box<dyn Error>> {
    let addr = Address::from_str(s).map_err(|e| format!("address: {e}"))?;
    let expected = Wallet::sdk_network(network);
    if addr.network() != expected {
        return Err(format!(
            "Recipient address network ({:?}) does not match configured network '{}' ({:?})",
            addr.network(),
            network,
            expected
        )
        .into());
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::WalletDb;
    use crate::wallet::Wallet;
    use darkfi_sdk::crypto::pasta_prelude::PrimeField;
    use darkfi_sdk::crypto::Keypair;

    #[test]
    fn collect_wallet_secrets_returns_all_derived_addresses() {
        let db = WalletDb::in_memory().unwrap();
        let kp1 = Keypair::random(&mut rand_core::OsRng);
        let kp2 = Keypair::random(&mut rand_core::OsRng);
        db.set_meta("seed_hash", &[1u8; 32]).unwrap();
        db.insert_address("addr1", &kp1.secret.inner().to_repr())
            .unwrap();
        db.insert_address("addr2", &kp2.secret.inner().to_repr())
            .unwrap();
        let w = Wallet {
            name: "test".into(),
            db,
        };
        let secrets = collect_wallet_secrets(&w).unwrap();
        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].inner().to_repr(), kp1.secret.inner().to_repr());
        assert_eq!(secrets[1].inner().to_repr(), kp2.secret.inner().to_repr());
    }

    #[tokio::test]
    async fn visible_money_output_notes_counts_token_mint_outputs() {
        use darkfi::tx::{ContractCallLeaf, Transaction, TransactionBuilder};
        use darkfi_money_contract::client::MoneyNote;
        use darkfi_money_contract::model::{Coin, MoneyTokenMintParamsV1, DARK_TOKEN_ID};
        use darkfi_money_contract::MoneyFunction;
        use darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID;
        use darkfi_sdk::crypto::note::AeadEncryptedNote;
        use darkfi_sdk::crypto::Blind;
        use darkfi_sdk::pasta::pallas;
        use darkfi_serial::AsyncEncodable;

        let empty = Transaction {
            calls: vec![],
            proofs: vec![],
            signatures: vec![],
        };
        assert!(visible_money_output_notes(&empty).await.unwrap().is_empty());

        let kp = Keypair::random(&mut rand_core::OsRng);
        let note = MoneyNote {
            value: 42,
            token_id: *DARK_TOKEN_ID,
            coin_blind: Blind::random(&mut rand_core::OsRng),
            value_blind: Blind::random(&mut rand_core::OsRng),
            token_blind: Blind::random(&mut rand_core::OsRng),
            spend_hook: darkfi_sdk::crypto::FuncId::none(),
            user_data: pallas::Base::ZERO,
            memo: Vec::new(),
        };
        let enc_note =
            AeadEncryptedNote::encrypt(&note, &kp.public, &mut rand_core::OsRng).unwrap();
        let params = MoneyTokenMintParamsV1 {
            coin: Coin::from(pallas::Base::from(7u64)),
            enc_note,
        };
        let mut data = vec![MoneyFunction::TokenMintV1 as u8];
        params.encode_async(&mut data).await.unwrap();
        let call = darkfi_sdk::tx::ContractCall {
            contract_id: *MONEY_CONTRACT_ID,
            data,
        };
        let tx = TransactionBuilder::new(ContractCallLeaf::new(call, vec![], vec![]), vec![])
            .unwrap()
            .build()
            .unwrap();
        let visible = visible_money_output_notes(&tx).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].0, 0);
        let decrypted = visible[0].1.decrypt::<MoneyNote>(&kp.secret).unwrap();
        assert_eq!(decrypted.value, 42);
    }
}
