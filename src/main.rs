/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use clap::{Parser, Subcommand};
use std::error::Error;
use std::io::IsTerminal;
use std::str::FromStr;

mod block_cache;
mod client;
mod config;
mod db;
mod memo;
mod mnemonic;
mod pruning;
mod secret_wrap;
mod sync;
mod tor;
mod tx_builder;
mod wallet;

#[derive(Parser, Debug)]
#[command(
    name = "moonshine",
    about = "Moonshine: A lightweight, private CLI wallet for DarkFi utilizing OMR/OMD"
)]
struct Cli {
    #[arg(short, long, default_value = "main")]
    wallet_name: String,

    #[arg(
        short = 's',
        long = "server",
        help = "gRPC lightwalletd server endpoint override"
    )]
    server: Option<String>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage wallet lifecycle
    Wallet {
        #[command(subcommand)]
        sub: WalletSubcommand,
    },

    /// Manage payment addresses
    Address {
        #[command(subcommand)]
        sub: AddressSubcommand,
    },

    /// Show account balances
    Balance,

    /// Manage coins and unspent notes
    Coins {
        #[command(subcommand)]
        sub: CoinsSubcommand,
    },

    /// Transaction operations
    Tx {
        #[command(subcommand)]
        sub: TxSubcommand,
    },

    /// Synchronize wallet with lightwalletd
    Sync {
        #[arg(long, help = "Force trial decryption, skip OMR")]
        force_trial: bool,
        #[arg(
            long,
            help = "Permit trial-decrypt fallback (leaks the scan window to LWD). \
                    Default is UnifOMR-strict: OMR failure does not advance the tip."
        )]
        allow_trial: bool,
        #[arg(
            long,
            hide = true,
            help = "Deprecated: strict UnifOMR is now the default"
        )]
        strict_omr: bool,
        /// Rebuild the Money Merkle tree from LWD `GetNoteCommitments` (height 0..=tip).
        /// Required before spend if the wallet birthday skipped earlier commitments.
        #[arg(long)]
        rebuild_merkle: bool,
    },

    /// Rescan chain from birthday height
    Rescan,

    /// Display synchronization status
    Status,

    /// Run diagnostic checks
    Doctor,

    /// Manually trigger block data pruning
    Prune,

    /// Manage wallet server configuration
    Config {
        #[arg(long, help = "Set lightwalletd server URL")]
        server_url: Option<String>,
        #[arg(long, help = "Set network (mainnet/testnet)")]
        network: Option<String>,
    },

    /// Show version info
    Version,
}

#[derive(Subcommand, Debug)]
enum WalletSubcommand {
    Create {
        name: String,
    },
    Import {
        name: String,
        /// Optional 22 mnemonic words on the CLI (preferred for scripts).
        /// If omitted, words are read interactively from a TTY stdin.
        #[arg(num_args = 0..=22, value_name = "WORD")]
        words: Vec<String>,
        /// Wallet birthday height. Sync/rescan start here instead of genesis,
        /// avoiding a full-chain scan for a freshly restored wallet.
        #[arg(long)]
        birthday: Option<u32>,
    },
    Export,
    Delete,
    List,
    Info,
}

#[derive(Subcommand, Debug)]
enum AddressSubcommand {
    /// List all wallet addresses
    List,
    /// Generate a new address
    New,
    /// Show default address
    Default,
    /// Display the default address for receiving payments
    Receive,
    /// Validate a DarkFi address
    Validate { address: String },
}

#[derive(Subcommand, Debug)]
enum CoinsSubcommand {
    List,
}

#[derive(Subcommand, Debug)]
enum TxSubcommand {
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: f64,
        #[arg(long, default_value = "DRK")]
        token: String,
        #[arg(long)]
        memo: Option<String>,
        /// Fee in atomic units (1 DRK = 1e8). Must cover gas (`compute_fee`);
        /// overpay is accepted. Default is a conservative testnet overpay.
        #[arg(long, default_value_t = 5_000_000)]
        fee: u64,
    },
    List,
    Show {
        hash: String,
    },
    Broadcast {
        hex: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let mut config = config::Config::load();
    if let Some(ref s) = args.server {
        config.server_url = s.clone();
    }

    println!("Moonshine CLI Wallet v{}", env!("CARGO_PKG_VERSION"));

    match args.cmd {
        Command::Wallet { sub } => match sub {
            WalletSubcommand::Create { name } => {
                wallet::Wallet::create(&name, &config.network)?;
            }
            WalletSubcommand::Import {
                name,
                words: arg_words,
                birthday,
            } => {
                let words = if arg_words.len() == 22 {
                    arg_words
                } else {
                    // Interactive paste: require a TTY so mnemonics are not slurped
                    // from pipes/redirects into process history unintentionally.
                    if !std::io::stdin().is_terminal() {
                        return Err("Refusing non-interactive mnemonic import from stdin. \
                             Pass the 22 words as arguments, or run in a TTY."
                            .into());
                    }
                    println!(
                        "Import wallet '{}' — enter your 22-word DarkFi mnemonic:",
                        name
                    );
                    println!("(Paste all words on one line, separated by spaces)");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    input.split_whitespace().map(|s| s.to_string()).collect()
                };
                if words.len() != 22 {
                    eprintln!(
                        "Error: Expected 22-word DarkFi mnemonic, got {}.",
                        words.len()
                    );
                } else {
                    wallet::Wallet::import(&name, &words, &config.network)?;
                    if let Some(height) = birthday {
                        let w = wallet::Wallet::open(&name)?;
                        w.db.set_birthday_height(height)?;
                        // Start syncing from the birthday, not genesis.
                        w.db.set_sync_height(height.saturating_sub(1))?;
                        println!("Set wallet birthday to height {}.", height);
                    }
                }
            }
            WalletSubcommand::Export => {
                let w = wallet::Wallet::open(&args.wallet_name)?;
                let dk = w.derive_unifomr_detection_key(&config.network)?;
                println!("UnifOMR detection key (hex): {}", hex::encode(&dk));
                println!("⚠️  Full seed export requires manual backup.");
            }
            WalletSubcommand::Delete => {
                wallet::Wallet::delete(&args.wallet_name)?;
            }
            WalletSubcommand::List => {
                let wallets = wallet::Wallet::list_wallets()?;
                if wallets.is_empty() {
                    println!(
                        "No wallets found. Use `moonshine wallet create <name>` to create one."
                    );
                } else {
                    println!("Local wallets:");
                    for name in wallets {
                        let marker = if name == args.wallet_name {
                            " (active)"
                        } else {
                            ""
                        };
                        println!("  • {}{}", name, marker);
                    }
                }
            }
            WalletSubcommand::Info => {
                let w = wallet::Wallet::open(&args.wallet_name)?;
                let (sync_h, birthday) = w.db.get_sync_state()?;
                let addrs = w.db.list_addresses()?;
                println!("Wallet: {}", w.name);
                println!("  Addresses: {}", addrs.len());
                println!("  Synced to: {}", sync_h);
                println!("  Birthday:  {}", birthday);
            }
        },
        Command::Address { sub } => {
            let w = wallet::Wallet::open(&args.wallet_name)?;
            match sub {
                AddressSubcommand::List => {
                    let addrs = w.db.list_addresses()?;
                    println!("Payment Addresses:");
                    for (pk, is_default) in addrs {
                        let marker = if is_default { " ★" } else { "" };
                        println!("  {}{}", pk, marker);
                    }
                }
                AddressSubcommand::New => {
                    w.generate_address()?;
                }
                AddressSubcommand::Default => match w.db.get_default_address()? {
                    Some(addr) => println!("Default address: {}", addr),
                    None => println!("No default address set."),
                },
                AddressSubcommand::Validate { address } => {
                    match darkfi_sdk::crypto::keypair::Address::from_str(&address) {
                        Ok(addr) => {
                            let net = match addr.network() {
                                darkfi_sdk::crypto::keypair::Network::Mainnet => "mainnet",
                                darkfi_sdk::crypto::keypair::Network::Testnet => "testnet",
                            };
                            println!("✓ Valid DarkFi address ({net})");
                        }
                        Err(e) => println!("✗ Invalid address: {e}"),
                    }
                }
                AddressSubcommand::Receive => match w.db.get_default_address()? {
                    Some(addr) => {
                        println!("\n  ╔══════════════════════════════════════════════════════════════════════╗");
                        println!("  ║  Your DarkFi Receive Address                                      ║");
                        println!("  ╠══════════════════════════════════════════════════════════════════════╣");
                        println!("  ║  {}  ║", addr);
                        println!("  ╚══════════════════════════════════════════════════════════════════════╝");
                        println!("\n  Share this address to receive DRK payments.");
                        println!("  All DarkFi addresses are fully shielded by default.");
                    }
                    None => println!("No default address set. Run: moonshine address new"),
                },
            }
        }
        Command::Balance => {
            let w = wallet::Wallet::open(&args.wallet_name)?;
            let balance = w.db.confirmed_balance("DRK")?;
            let drk_amount = balance as f64 / 100_000_000.0; // 8 decimal places (1 DRK = 10^8 atomic)
            println!("Balance: {:.8} DRK", drk_amount);
            println!("  Raw:   {} atomic units", balance);
        }
        Command::Coins { sub } => {
            let w = wallet::Wallet::open(&args.wallet_name)?;
            match sub {
                CoinsSubcommand::List => {
                    let unspent = w.db.list_unspent()?;
                    if unspent.is_empty() {
                        println!("No unspent coins.");
                    } else {
                        println!("Unspent coins:");
                        for (tx_hash, idx, value, token) in unspent {
                            println!("  {}:{} — {} {}", &tx_hash[..8], idx, value, token);
                        }
                    }
                }
            }
        }
        Command::Tx { sub } => match sub {
            TxSubcommand::Send {
                to,
                amount,
                token,
                memo,
                fee,
            } => {
                let w = wallet::Wallet::open(&args.wallet_name)?;

                // Validate recipient as a DarkFi Address (base58 with checksum).
                let recipient_addr = match darkfi_sdk::crypto::keypair::Address::from_str(&to) {
                    Ok(addr) => addr,
                    Err(e) => {
                        eprintln!("Error: Invalid DarkFi address '{to}': {e}");
                        return Ok(());
                    }
                };
                let to_bytes = recipient_addr.public_key().to_bytes().to_vec();

                // Convert amount to atomic units (1 DRK = 10^8 atomic)
                let amount_atomic = (amount * 1e8) as u64;
                let fee_atomic = fee;
                if amount_atomic == 0 {
                    eprintln!("Error: Amount must be greater than 0.");
                    return Ok(());
                }

                // Check balance
                let balance = w.db.confirmed_balance(&token)?;
                let total_needed = amount_atomic + fee_atomic;
                if (balance as u64) < total_needed {
                    eprintln!(
                        "Error: Insufficient funds. Have {} atomic, need {} ({} + {} fee).",
                        balance, total_needed, amount_atomic, fee_atomic
                    );
                    return Ok(());
                }

                // Select inputs (greedy coin selection)
                let unspent = w.db.list_unspent()?;
                let mut selected_inputs = Vec::new();
                let mut input_total = 0u64;

                for (tx_hash, idx, value, ref token_id) in &unspent {
                    if crate::db::WalletDb::is_drk_token(&token)
                        && crate::db::WalletDb::is_drk_token(token_id)
                        || token_id == &token
                    {
                        selected_inputs.push((tx_hash.clone(), *idx, *value));
                        input_total += *value as u64;
                        if input_total >= total_needed {
                            break;
                        }
                    }
                }

                if input_total < total_needed {
                    eprintln!(
                        "Error: Cannot select enough coins. Selected {} from {} UTXOs, need {}.",
                        input_total,
                        selected_inputs.len(),
                        total_needed
                    );
                    return Ok(());
                }

                let change = input_total - total_needed;

                // UnifOMR only: clue from directory PK (GetCluePublicKey → build_omr_clue_from_pk).
                let mut recipient_pk = [0u8; 32];
                recipient_pk.copy_from_slice(&to_bytes);

                // Strict UnifOMR: fail closed unless GetClue ownership verifies
                // (decoys look like valid PKs without this check).
                let network_byte = wallet::Wallet::network_byte(&config.network);
                let omr_clue = {
                    let mut lookup = crate::client::LightwalletClient::new(
                        &config.server_url,
                        config.tls_pin_sha256.clone(),
                    )
                    .with_tor(config.use_tor);
                    let info = match lookup.get_light_info().await {
                        Ok(info) => info,
                        Err(e) => {
                            eprintln!(
                                "Error: GetLightInfo failed: {}",
                                sync::redact_sync_error(&e.to_string())
                            );
                            return Ok(());
                        }
                    };
                    match lookup.get_clue_public_key(recipient_pk.to_vec()).await {
                        Ok(resp) => match verified_unifomr_clue(
                            network_byte,
                            &recipient_pk,
                            &resp,
                            &info.directory_attest_pubkey,
                        ) {
                            Ok(clue) => clue,
                            Err(e) => {
                                eprintln!(
                                    "Error: UnifOMR clue rejected ({e}). \
                                     Recipient may be unregistered — moonshine \
                                     is strict UnifOMR (no trial-decrypt send). \
                                     Ask the recipient to register, or they can \
                                     `moonshine sync --force-trial` after a \
                                     clearnet send from another wallet."
                                );
                                return Ok(());
                            }
                        },
                        Err(e) => {
                            eprintln!(
                                "Error: UnifOMR clue PK lookup failed: {}",
                                sync::redact_sync_error(&e.to_string())
                            );
                            return Ok(());
                        }
                    }
                };

                println!("╔════════════════════════════════════════════════╗");
                println!("║         TRANSACTION SUMMARY                   ║");
                println!("╠════════════════════════════════════════════════╣");
                println!("║  To:      {}...  ║", &to[..24]);
                println!(
                    "║  Amount:  {} {} ({} atomic)           ║",
                    amount, token, amount_atomic
                );
                println!(
                    "║  Fee:     {} DRK ({} atomic)              ║",
                    fee_atomic as f64 / 1e8,
                    fee_atomic
                );
                println!(
                    "║  Inputs:  {} UTXOs ({} atomic)                ║",
                    selected_inputs.len(),
                    input_total
                );
                if change > 0 {
                    println!("║  Change:  {} atomic                           ║", change);
                }
                if let Some(ref m) = memo {
                    println!(
                        "║  Memo:    {}                               ║",
                        &m[..m.len().min(32)]
                    );
                }
                println!("║  OMR:     UnifOMR (0x05) ✓                    ║");
                println!("╠════════════════════════════════════════════════╣");
                println!("╚════════════════════════════════════════════════╝");

                println!("\nGenerating Halo2 Zero-Knowledge Proofs...");
                println!("This may take up to 60 seconds on mobile devices.");

                // 1. Fetch ZK circuits from lightwalletd
                let mut client = crate::client::LightwalletClient::new(
                    &config.server_url,
                    config.tls_pin_sha256.clone(),
                )
                .with_tor(config.use_tor);
                let zkas_bins = client
                    .lookup_zkas(&darkfi_sdk::crypto::contract_id::MONEY_CONTRACT_ID.to_string())
                    .await?
                    .bincodes;

                // 2. Fetch local Merkle Tree
                let tree_bytes =
                    w.db.get_meta("tree_state")?
                        .ok_or("Merkle tree not found. Sync first.")?;
                let tree: darkfi_sdk::crypto::MerkleTree =
                    darkfi_serial::Decodable::decode(&mut std::io::Cursor::new(&tree_bytes))
                        .map_err(|e| format!("Failed to decode MerkleTree: {}", e))?;

                // 3. Build OwnCoin list from full unspent list
                let unspent_full = w.db.list_unspent_full()?;
                let mut all_coins = Vec::new();
                for (
                    _,
                    _,
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
                ) in unspent_full
                {
                    use darkfi_sdk::pasta::pallas;
                    use darkfi_serial::Decodable;
                    let mut coin_arr = [0u8; 32];
                    coin_arr.copy_from_slice(&coin_b);
                    let mut val_arr = [0u8; 32];
                    val_arr.copy_from_slice(&val_b);
                    let mut tok_arr = [0u8; 32];
                    tok_arr.copy_from_slice(&tok_b);
                    let mut udata_arr = [0u8; 32];
                    udata_arr.copy_from_slice(&udata);

                    let coin_blind =
                        pallas::Base::decode(&mut std::io::Cursor::new(&coin_arr)).unwrap();
                    let value_blind =
                        pallas::Scalar::decode(&mut std::io::Cursor::new(&val_arr)).unwrap();
                    let token_blind =
                        pallas::Base::decode(&mut std::io::Cursor::new(&tok_arr)).unwrap();
                    let user_data =
                        pallas::Base::decode(&mut std::io::Cursor::new(&udata_arr)).unwrap();

                    let note = darkfi_money_contract::client::MoneyNote {
                        value: val as u64,
                        token_id: darkfi_money_contract::model::TokenId::from_bytes(
                            hex::decode(&tok_id).unwrap().try_into().unwrap(),
                        )
                        .unwrap(),
                        coin_blind: darkfi_sdk::crypto::Blind(coin_blind),
                        value_blind: darkfi_sdk::crypto::Blind(value_blind),
                        token_blind: darkfi_sdk::crypto::Blind(token_blind),
                        spend_hook: darkfi_sdk::crypto::FuncId::from_bytes([
                            hook, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ])
                        .unwrap(),
                        user_data,
                        memo: Vec::new(),
                    };

                    // OwnCoin.coin must be the note commitment (compact output.coin), not serial.
                    let mut commit_arr = [0u8; 32];
                    commit_arr.copy_from_slice(&commitment);
                    let coin = darkfi_money_contract::model::Coin::from_bytes(commit_arr)
                        .map_err(|e| format!("Invalid coin commitment: {e:?}"))?;
                    let mut sk_arr = [0u8; 32];
                    if owner_secret.len() < 32 {
                        return Err("Stored owner secret too short".into());
                    }
                    sk_arr.copy_from_slice(&owner_secret[..32]);
                    let secret = darkfi_sdk::crypto::SecretKey::from_bytes(sk_arr)
                        .map_err(|e| format!("Invalid note owner secret: {e:?}"))?;

                    all_coins.push(darkfi_money_contract::client::OwnCoin {
                        coin,
                        note,
                        secret,
                        leaf_position: (lpos as u64).into(),
                    });
                }

                // Filter to requested token (DRK aliases native token hex).
                let want_drk = crate::db::WalletDb::is_drk_token(&token);
                let all_coins: Vec<_> = all_coins
                    .into_iter()
                    .filter(|c| {
                        let hex = hex::encode(c.note.token_id.to_bytes());
                        if want_drk {
                            crate::db::WalletDb::is_drk_token(&hex)
                        } else {
                            token == hex
                        }
                    })
                    .collect();

                let recipient_pubkey = darkfi_sdk::crypto::PublicKey::from_bytes({
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&to_bytes);
                    a
                })
                .unwrap();
                let token_id = *darkfi_money_contract::model::DARK_TOKEN_ID;
                // Change/output signing key: default address secret (not seed_hash).
                let wallet_secret =
                    darkfi_sdk::crypto::SecretKey::from_bytes(w.wallet_secret_bytes()?)
                        .map_err(|e| format!("Invalid wallet secret: {e:?}"))?;

                // Build OMR metadata (plaintext) and encrypt for the recipient.
                let omr_metadata_enc = {
                    use darkfi_sdk::crypto::pasta_prelude::PrimeField;
                    let secret_bytes: [u8; 32] = wallet_secret.inner().to_repr();
                    let recipient_pk_bytes = recipient_pubkey.to_bytes();
                    let metadata = crate::memo::build_omr_memo(
                        &secret_bytes,
                        &recipient_pk_bytes,
                        memo.as_deref(),
                        Some(crate::memo::SCHEME_UNIFOMR),
                    )?;
                    crate::memo::encrypt_omr_metadata(&metadata, &recipient_pubkey)?
                };

                // MoneyNote::memo = plain user text only (no OMR framing).
                let payment_memo = memo
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.as_bytes().to_vec());

                let tx: darkfi::tx::Transaction = crate::tx_builder::build_transaction(
                    amount_atomic,
                    fee_atomic,
                    token_id,
                    recipient_pubkey,
                    wallet_secret,
                    all_coins,
                    tree,
                    zkas_bins
                        .into_iter()
                        .map(|kv| (kv.namespace, kv.bincode))
                        .collect(),
                    payment_memo,
                )
                .await?;

                use darkfi_serial::Encodable;
                let mut tx_data = Vec::new();
                tx.encode(&mut tx_data).unwrap();

                println!("\n✅ ZK Transaction Generated!");
                println!("TX size: {} bytes", tx_data.len());

                // Auto-broadcast via lightwalletd
                println!("\nBroadcasting transaction...");
                if omr_clue.is_empty() {
                    println!("(No OMR clue — recipient will trial-decrypt)");
                } else {
                    println!(
                        "UnifOMR clue built from directory PK ({} bytes)",
                        omr_clue.len()
                    );
                }

                let mut broadcast_client = crate::client::LightwalletClient::new(
                    &config.server_url,
                    config.tls_pin_sha256.clone(),
                )
                .with_tor(config.use_tor);
                match broadcast_client
                    .send_transaction(tx_data.clone(), omr_clue.clone(), omr_metadata_enc)
                    .await
                {
                    Ok(resp) => {
                        if !resp.error.is_empty() && resp.error != "0" {
                            return Err(format!(
                                "lightwalletd SendTransaction error: {}. \
                                 Refusing manual/darkfid fallback so the UnifOMR clue hint stays live.",
                                resp.error
                            )
                            .into());
                        }
                        if !omr_clue.is_empty() && !resp.clue_accepted {
                            return Err(
                                "lightwalletd accepted the tx but rejected the UnifOMR clue \
                                 (clue_accepted=false). Refusing to treat this as success."
                                    .into(),
                            );
                        }
                        println!("✅ Transaction broadcast successfully via lightwalletd!");
                        if resp.clue_accepted {
                            println!(
                                "UnifOMR clue hint stored (24h TTL) — confirm while LWD indexes."
                            );
                        }
                    }
                    Err(e) => {
                        return Err(format!(
                            "Broadcast via lightwalletd failed: {}. \
                             UnifOMR requires SendTransaction so the clue hint is stored (24h TTL).",
                            sync::redact_sync_error(&e.to_string())
                        )
                        .into());
                    }
                }

                // Record sent transaction in wallet DB
                let tx_hash = format!("{}", tx.hash());
                if let Err(e) = w.db.insert_transaction(
                    &tx_hash,
                    0, // block height unknown until confirmed
                    "outgoing",
                    amount_atomic as i64,
                    &token,
                    Some(&to), // counterparty = recipient
                    memo.as_deref(),
                ) {
                    eprintln!("Warning: failed to record transaction locally: {}", e);
                }

                println!("TX hash: {}", tx_hash);
                let explorer_base = if config.network.eq_ignore_ascii_case("mainnet") {
                    "https://explorer.dark.fi"
                } else {
                    "https://explorer.testnet.dark.fi"
                };
                println!("Explorer: {}/tx/{}", explorer_base, tx_hash);
            }
            TxSubcommand::List => {
                let w = wallet::Wallet::open(&args.wallet_name)?;
                let txs = w.db.list_transactions(100)?;
                if txs.is_empty() {
                    println!("No transactions found.");
                    println!("  Sync first with: moonshine sync");
                } else {
                    println!("Transaction History ({} transactions):", txs.len());
                    println!(
                        "{:<10} {:<10} {:>16} {:<6} {:<20} Hash",
                        "Height", "Direction", "Amount", "Token", "Time"
                    );
                    println!("{}", "-".repeat(90));
                    for tx in &txs {
                        let drk_amount = tx.value_raw as f64 / 100_000_000.0;
                        let dir_icon = if tx.direction == "incoming" {
                            "⬇ recv"
                        } else {
                            "⬆ send"
                        };
                        let hash_short = if tx.hash.len() > 12 {
                            &tx.hash[..12]
                        } else {
                            &tx.hash
                        };
                        println!(
                            "{:<10} {:<10} {:>15.8} {:<6} {:<20} {}…",
                            tx.block_height,
                            dir_icon,
                            drk_amount,
                            tx.token_id,
                            tx.timestamp,
                            hash_short
                        );
                        if let Some(memo) = &tx.memo {
                            if !memo.is_empty() {
                                println!("           memo: {}", memo);
                            }
                        }
                    }
                }
            }
            TxSubcommand::Show { hash } => {
                let w = wallet::Wallet::open(&args.wallet_name)?;
                match w.db.get_transaction(&hash)? {
                    Some(tx) => {
                        let drk_amount = tx.value_raw as f64 / 100_000_000.0;
                        println!("Transaction Details");
                        println!("  Hash:         {}", tx.hash);
                        println!("  Block Height: {}", tx.block_height);
                        println!("  Direction:    {}", tx.direction);
                        println!(
                            "  Amount:       {:.8} {} ({} atomic)",
                            drk_amount, tx.token_id, tx.value_raw
                        );
                        println!("  Time:         {}", tx.timestamp);
                        if let Some(cp) = &tx.counterparty {
                            println!("  Counterparty: {}", cp);
                        }
                        if let Some(memo) = &tx.memo {
                            if !memo.is_empty() {
                                println!("  Memo:         {}", memo);
                            }
                        }
                        let explorer_base = if config.network == "mainnet" {
                            "https://explorer.dark.fi"
                        } else {
                            "https://explorer.testnet.dark.fi"
                        };
                        println!("  Explorer:     {}/tx/{}", explorer_base, tx.hash);
                    }
                    None => {
                        println!("Transaction not found: {}", hash);
                    }
                }
            }
            TxSubcommand::Broadcast { hex } => {
                let mut client = client::LightwalletClient::new(
                    &config.server_url,
                    config.tls_pin_sha256.clone(),
                )
                .with_tor(config.use_tor);
                match hex::decode(&hex) {
                    Ok(raw_tx) => {
                        let omr_clue = match parse_stub_recipient_pubkey(&raw_tx) {
                            Some(recipient_pk) => {
                                let info = match client.get_light_info().await {
                                    Ok(info) => info,
                                    Err(e) => {
                                        eprintln!(
                                            "Error: GetLightInfo failed: {}",
                                            sync::redact_sync_error(&e.to_string())
                                        );
                                        return Ok(());
                                    }
                                };
                                match client.get_clue_public_key(recipient_pk.to_vec()).await {
                                    Ok(resp) => {
                                        let network_byte =
                                            wallet::Wallet::network_byte(&config.network);
                                        match verified_unifomr_clue(
                                            network_byte,
                                            &recipient_pk,
                                            &resp,
                                            &info.directory_attest_pubkey,
                                        ) {
                                            Ok(clue) => {
                                                println!(
                                                    "UnifOMR clue from verified directory PK ({} bytes)",
                                                    clue.len()
                                                );
                                                clue
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "Error: UnifOMR clue rejected ({e}). \
                                                     No PerfOMR fallback."
                                                );
                                                return Ok(());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Error: UnifOMR clue PK lookup failed: {}",
                                            sync::redact_sync_error(&e.to_string())
                                        );
                                        return Ok(());
                                    }
                                }
                            }
                            None => {
                                eprintln!(
                                    "Error: could not parse recipient for UnifOMR clue; \
                                     refusing broadcast without lightwalletd clue hint (24h TTL)."
                                );
                                return Ok(());
                            }
                        };
                        match client.send_transaction(raw_tx, omr_clue, vec![]).await {
                            Ok(resp) => {
                                if resp.error.is_empty() || resp.error == "0" {
                                    println!(
                                        "Broadcast OK via lightwalletd (UnifOMR clue hint stored, 24h TTL)"
                                    );
                                } else {
                                    eprintln!("Broadcast error: {}", resp.error);
                                }
                            }
                            Err(e) => eprintln!(
                                "Broadcast failed: {}",
                                sync::redact_sync_error(&e.to_string())
                            ),
                        }
                    }
                    Err(e) => eprintln!("Invalid hex: {}", e),
                }
            }
        },
        Command::Sync {
            force_trial,
            allow_trial,
            strict_omr: _deprecated_strict,
            rebuild_merkle,
        } => {
            let w = wallet::Wallet::open(&args.wallet_name)?;
            let secret_keys = w.db.get_all_secrets()?;
            let network_byte = wallet::Wallet::network_byte(&config.network);

            let strict_omr = !allow_trial && !force_trial;
            if force_trial {
                println!("Syncing with --force-trial (OMR skipped)...");
            } else if strict_omr {
                println!("Syncing UnifOMR-strict (no trial-decrypt fallback)...");
            } else {
                println!("Syncing UnifOMR with --allow-trial fallback for non-OMR txs...");
            }
            println!("Syncing with lightwalletd at {}...", config.server_url);

            // Publish UnifOMR clue PK for every payment address (wallet-level sk_clue).
            // Fail closed: if registration fails, senders would GetClue decoys.
            let clue_pk = w
                .unifomr_clue_public_key(&config.network)
                .map_err(|e| format!("UnifOMR clue keypair required before sync: {e}"))?;
            let pay_pks = w
                .recipient_pubkeys_for_omr()
                .map_err(|e| format!("payment pubkeys required for RegisterCluePublicKey: {e}"))?;
            // Map each payment pubkey → owning SecretKey for ownership proofs.
            let addr_keys = w.db.get_all_address_keys()?;
            let mut sk_by_pk: std::collections::HashMap<[u8; 32], darkfi_sdk::crypto::SecretKey> =
                std::collections::HashMap::new();
            for (_addr, secret_bytes, _default) in addr_keys {
                if secret_bytes.len() < 32 {
                    continue;
                }
                let mut sk_arr = [0u8; 32];
                sk_arr.copy_from_slice(&secret_bytes[..32]);
                let Ok(sk) = darkfi_sdk::crypto::SecretKey::from_bytes(sk_arr) else {
                    continue;
                };
                let pk = darkfi_sdk::crypto::PublicKey::from_secret(sk).to_bytes();
                sk_by_pk.insert(pk, sk);
            }
            let mut reg = crate::client::LightwalletClient::new(
                &config.server_url,
                config.tls_pin_sha256.clone(),
            )
            .with_tor(config.use_tor);
            let mut ok = 0usize;
            let mut last_err: Option<String> = None;
            let key_version = wallet::clue_key_version_now();
            for pk_pay in pay_pks {
                if wallet::clue_already_registered(network_byte, &pk_pay, &clue_pk) {
                    ok += 1;
                    continue;
                }
                let Some(sk) = sk_by_pk.get(&pk_pay) else {
                    last_err = Some("missing payment SecretKey for ownership proof".into());
                    continue;
                };
                let ownership_proof = wallet::sign_clue_pk_ownership(
                    sk,
                    network_byte,
                    key_version,
                    &pk_pay,
                    &clue_pk,
                );
                match reg
                    .register_clue_public_key(
                        pk_pay.to_vec(),
                        clue_pk.clone(),
                        ownership_proof,
                        key_version,
                    )
                    .await
                {
                    Ok(()) => {
                        wallet::mark_clue_registered(network_byte, &pk_pay, &clue_pk);
                        ok += 1;
                    }
                    Err(e) => {
                        last_err = Some(sync::redact_sync_error(&e.to_string()));
                    }
                }
            }
            if ok == 0 {
                return Err(format!(
                    "RegisterCluePublicKey failed for all payment addresses ({}). \
                     Ensure darkfi-lightwalletd with UnifOMR is reachable at {}.",
                    last_err.unwrap_or_else(|| "unknown".into()),
                    config.server_url
                )
                .into());
            }
            println!("Registered UnifOMR clue public key for {ok} payment address(es).");

            let block_cache = {
                let cache_path =
                    format!("{}.blocks.db", wallet::Wallet::db_path(&args.wallet_name));
                match crate::block_cache::BlockCache::open(&cache_path) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        tracing::warn!("block cache open failed ({e}); continuing without cache");
                        None
                    }
                }
            };

            let engine = sync::SyncEngine::new(
                w.db,
                &config.server_url,
                secret_keys,
                config.tls_pin_sha256.clone(),
                network_byte,
                force_trial,
                strict_omr,
                block_cache,
                config.use_tor,
            );

            if rebuild_merkle {
                println!(
                    "Rebuilding Money Merkle tree from LWD GetNoteCommitments (0..=tip)..."
                );
                match engine.rebuild_money_tree_from_genesis().await {
                    Ok((appended, marked, tip)) => {
                        println!(
                            "  Merkle rebuild complete: appended={appended} marked={marked} tip={tip}"
                        );
                    }
                    Err(e) => {
                        return Err(format!(
                            "Merkle rebuild failed: {}",
                            sync::redact_sync_error(&e.to_string())
                        )
                        .into());
                    }
                }
            }

            // Multi-pass: each cycle covers ≤4096 blocks (padded OMR window);
            // loop until the wallet reaches the chain tip so a wallet far
            // behind (or freshly restored) catches up in one `sync` command.
            let mut total_scanned = 0u64;
            let mut total_found = 0u32;
            let mut total_spent = 0u32;
            loop {
                match engine.sync_once().await {
                    Ok(result) => {
                        total_scanned += u64::from(result.blocks_scanned);
                        total_found += result.notes_found;
                        total_spent += result.notes_spent;
                        let (last_synced, _) =
                            engine.db.get_sync_state().unwrap_or((result.tip_height, 0));
                        if result.blocks_scanned == 0 || last_synced >= result.tip_height {
                            println!("Sync complete:");
                            println!("  Blocks scanned: {}", total_scanned);
                            println!("  Notes found:    {}", total_found);
                            println!("  Notes spent:    {}", total_spent);
                            println!("  Chain tip:      {}", result.tip_height);
                            break;
                        }
                        println!(
                            "  ...synced to {} of {} (found {} notes so far)",
                            last_synced, result.tip_height, total_found
                        );
                    }
                    Err(e) => {
                        eprintln!("Sync failed: {}", sync::redact_sync_error(&e.to_string()));
                        break;
                    }
                }
            }
        }
        Command::Rescan => {
            let w = wallet::Wallet::open(&args.wallet_name)?;
            let (_synced, birthday) = w.db.get_sync_state()?;
            // Rescan from the wallet birthday: clear notes + Merkle tree so
            // commitments are not duplicated on re-append.
            let floor = birthday.saturating_sub(1);
            w.db.reset_for_rescan(floor)?;
            println!(
                "Wallet state cleared and sync reset to birthday height {}. Run `moonshine sync` to rescan.",
                birthday
            );
        }
        Command::Status => {
            let mut client =
                client::LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            match client.get_chain_tip().await {
                Ok(tip) => {
                    println!("Connected to lightwalletd: {}", config.server_url);
                    println!("Current tip height: {}", tip.height);
                    let hex_hash = hex::encode(&tip.hash);
                    println!("Current tip hash:   {}", hex_hash);
                }
                Err(e) => {
                    eprintln!(
                        "Failed to get server status: {}",
                        sync::redact_sync_error(&e.to_string())
                    );
                }
            }
        }
        Command::Doctor => {
            println!("Running diagnostic checks...");

            // Check wallet DB
            match wallet::Wallet::open(&args.wallet_name) {
                Ok(w) => {
                    let (h, _) = w.db.get_sync_state().unwrap_or((0, 0));
                    println!("  Wallet DB:       OK (synced to {})", h);
                }
                Err(_) => println!("  Wallet DB:       NOT FOUND"),
            }

            // Check server connectivity
            let mut client =
                client::LightwalletClient::new(&config.server_url, config.tls_pin_sha256.clone())
                    .with_tor(config.use_tor);
            match client.get_status().await {
                Ok(_) => println!("  RPC Connection:  OK"),
                Err(e) => eprintln!(
                    "  RPC Connection:  FAILED ({})",
                    sync::redact_sync_error(&e.to_string())
                ),
            }

            // Check TLS / pin policy
            let local = config.server_url.contains("localhost")
                || config.server_url.contains("127.0.0.1")
                || config.server_url.contains("[::1]");
            if config.server_url.starts_with("https://") {
                if config.tls_pin_sha256.is_some() || local {
                    println!("  TLS/Security:    OK (pin configured or localhost)");
                } else {
                    println!("  TLS/Security:    FAIL — remote HTTPS needs tls_pin_sha256");
                }
            } else if local {
                println!("  TLS/Security:    OK (localhost cleartext allowed)");
            } else {
                println!("  TLS/Security:    FAIL — remote cleartext refused (use https:// + tls_pin_sha256)");
            }

            println!("  OMR Scheme:      UnifOMR (0x05) only");
        }
        Command::Prune => {
            let w = wallet::Wallet::open(&args.wallet_name)?;
            match pruning::prune_wallet(&w.db) {
                Ok(result) => {
                    println!("Pruning complete: {} notes removed", result.notes_pruned);
                }
                Err(e) => eprintln!("Pruning error: {}", e),
            }
        }
        Command::Config {
            server_url,
            network,
        } => {
            if server_url.is_none() && network.is_none() {
                println!("Configuration:");
                println!("  Server URL:   {}", config.server_url);
                println!("  Network:      {}", config.network);
                println!(
                    "  Config Path:  {}",
                    config::Config::config_path().display()
                );
            } else {
                if let Some(s) = server_url {
                    // Fail-closed: refuse remote cleartext (match mobile / client connect).
                    let loopback =
                        s.contains("localhost") || s.contains("127.0.0.1") || s.contains("[::1]");
                    if !s.starts_with("https://") && !loopback {
                        eprintln!(
                            "Error: remote cleartext server URL refused. \
                             Use https:// for remote lightwalletd, or http://127.0.0.1 / localhost."
                        );
                        return Ok(());
                    }
                    config.server_url = s;
                }
                if let Some(n) = network {
                    config.network = n;
                }
                if let Err(e) = config.save() {
                    eprintln!("Error saving config: {}", e);
                } else {
                    println!("Configuration updated successfully.");
                }
            }
        }
        Command::Version => {
            println!("Moonshine CLI version {}", env!("CARGO_PKG_VERSION"));
            println!("  OMR Scheme:  UnifOMR (ePrint 2026/910, scheme 0x05)");
            println!("  Privacy:     Block range padding, jitter, error redaction");
        }
    }
    Ok(())
}

/// Verify GetCluePublicKey directory attestation, then build a UnifOMR clue.
fn verified_unifomr_clue(
    network_byte: u8,
    recipient_pk: &[u8; 32],
    resp: &client::proto::CluePublicKey,
    attest_pk: &[u8],
) -> Result<Vec<u8>, String> {
    if resp.clue_public_key.is_empty() {
        return Err("empty clue public key".into());
    }
    if attest_pk.len() != 32 {
        return Err("GetLightInfo missing directory_attest_pubkey; upgrade lightwalletd".into());
    }
    darkfi_lightwalletd::unifomr::verify_directory_attestation(
        attest_pk,
        network_byte,
        resp.key_version,
        recipient_pk,
        &resp.clue_public_key,
        &resp.ownership_proof,
    )?;
    let pk = darkfi_lightwalletd::unifomr::deserialize_public_key(&resp.clue_public_key)
        .map_err(|e| format!("invalid UnifOMR clue public key: {e}"))?;
    Ok(darkfi_lightwalletd::unifomr::build_omr_clue_from_pk(&pk))
}

/// Parse recipient pubkey from the moonshine Create stub wire format:
/// `DRK_TX_v1\0` + inputs_count(u32 LE) + recipient(32) + ...
fn parse_stub_recipient_pubkey(raw_tx: &[u8]) -> Option<[u8; 32]> {
    const MAGIC: &[u8] = b"DRK_TX_v1\x00";
    if raw_tx.len() < MAGIC.len() + 4 + 32 {
        return None;
    }
    if &raw_tx[..MAGIC.len()] != MAGIC {
        return None;
    }
    let recipient_off = MAGIC.len() + 4;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw_tx[recipient_off..recipient_off + 32]);
    Some(pk)
}

#[cfg(test)]
mod stub_parse_tests {
    use super::*;

    #[test]
    fn test_parse_stub_recipient() {
        let mut tx = Vec::new();
        tx.extend_from_slice(b"DRK_TX_v1\x00");
        tx.extend_from_slice(&1u32.to_le_bytes());
        let recipient = [0x42u8; 32];
        tx.extend_from_slice(&recipient);
        tx.extend_from_slice(&100u64.to_le_bytes());
        assert_eq!(parse_stub_recipient_pubkey(&tx), Some(recipient));
    }

    #[test]
    fn test_parse_stub_rejects_short() {
        assert!(parse_stub_recipient_pubkey(b"DRK_TX_v1\x00").is_none());
    }
}
