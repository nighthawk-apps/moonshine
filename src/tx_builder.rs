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

use darkfi::{
    tx::{ContractCallLeaf, Transaction, TransactionBuilder},
    zk::{proof::ProvingKey, vm::ZkCircuit, vm_heap::empty_witnesses},
    zkas::ZkBinary,
};
use darkfi_money_contract::{
    client::{
        fee_v1::{create_fee_proof, FeeCallInput, FeeCallOutput},
        transfer_v1::make_transfer_call,
        MoneyNote, OwnCoin,
    },
    model::{CoinAttributes, MoneyFeeParamsV1, TokenId},
    MoneyFunction, MONEY_CONTRACT_ZKAS_BURN_NS_V1, MONEY_CONTRACT_ZKAS_FEE_NS_V1,
    MONEY_CONTRACT_ZKAS_MINT_NS_V1,
};
use darkfi_sdk::bridgetree::Hashable;
use darkfi_sdk::crypto::pasta_prelude::{Field, PrimeField};
use darkfi_sdk::{
    crypto::{
        contract_id::MONEY_CONTRACT_ID, note::AeadEncryptedNote, FuncId, Keypair, MerkleNode,
        MerkleTree, PublicKey,
    },
    crypto::{Blind, SecretKey},
    pasta::pallas,
    tx::ContractCall,
};
use darkfi_serial::AsyncEncodable;
use std::error::Error;

/// Recompute the Money Merkle root the burn/fee circuits publish.
pub(crate) fn merkle_root_from_path(
    coin: MerkleNode,
    position: u64,
    path: &[MerkleNode],
) -> MerkleNode {
    let mut current = coin;
    for (level, sibling) in path.iter().enumerate() {
        let level = level as u8;
        current = if position & (1 << level) == 0 {
            MerkleNode::combine(level.into(), &current, sibling)
        } else {
            MerkleNode::combine(level.into(), sibling, &current)
        };
    }
    current
}

/// `witness(pos, 0)` must authenticate the coin to the current tree root.
/// A mismatch means `leaf_position` does not match the marked leaf (the
/// published root will not be in darkfid `coin_roots` → `-32110`).
pub(crate) fn assert_witness_at_tip(
    tree: &MerkleTree,
    coin: MerkleNode,
    leaf_position: darkfi_sdk::bridgetree::Position,
) -> Result<MerkleNode, Box<dyn Error>> {
    let Some(tip_root) = tree.root(0) else {
        return Err("Merkle tree has no current root".into());
    };
    let path = tree
        .witness(leaf_position, 0)
        .map_err(|_| format!("Merkle witness missing for leaf {leaf_position:?}"))?;
    let position: u64 = leaf_position.into();
    let witnessed = merkle_root_from_path(coin, position, &path);
    if witnessed != tip_root {
        return Err(format!(
            "Merkle witness for leaf {position} hashes to {} but tree tip is {}. \
             Rebuild with: moonshine sync --rebuild-merkle --allow-trial",
            hex::encode(witnessed.to_bytes()),
            hex::encode(tip_root.to_bytes()),
        )
        .into());
    }
    Ok(tip_root)
}

pub fn compute_remainder_blind(
    inputs: &[Blind<pallas::Scalar>],
    outputs: &[Blind<pallas::Scalar>],
) -> Blind<pallas::Scalar> {
    let mut remainder = pallas::Scalar::zero();
    for i in inputs {
        remainder += i.inner();
    }
    for o in outputs {
        remainder -= o.inner();
    }
    Blind(remainder)
}

/// Built Money transfer (+ optional fee) plus the coins it spends.
///
/// Callers must mark these notes spent after a successful broadcast so the
/// next send cannot republish the same nullifiers.
pub struct BuiltTransfer {
    pub tx: Transaction,
    pub spent_commitments: Vec<Vec<u8>>,
    pub spent_nullifiers: Vec<Vec<u8>>,
}

fn own_coin_commitment(coin: &OwnCoin) -> Vec<u8> {
    coin.coin.inner().to_repr().to_vec()
}

fn own_coin_nullifier(coin: &OwnCoin) -> Vec<u8> {
    coin.nullifier().inner().to_repr().to_vec()
}

#[allow(clippy::too_many_arguments)]
pub async fn build_transaction(
    amount: u64,
    fee: u64,
    token_id: TokenId,
    recipient_pubkey: PublicKey,
    wallet_secret: SecretKey,
    all_coins: Vec<OwnCoin>,
    tree: MerkleTree,
    zkas_bins: Vec<(String, Vec<u8>)>,
    payment_memo: Option<Vec<u8>>,
    half_split: bool,
) -> Result<BuiltTransfer, Box<dyn Error>> {
    let keypair = Keypair::new(wallet_secret);

    // Decode ZK binaries
    let mint_zkbin_bytes = &zkas_bins
        .iter()
        .find(|x| x.0 == MONEY_CONTRACT_ZKAS_MINT_NS_V1)
        .ok_or("Mint circuit missing")?
        .1;
    let burn_zkbin_bytes = &zkas_bins
        .iter()
        .find(|x| x.0 == MONEY_CONTRACT_ZKAS_BURN_NS_V1)
        .ok_or("Burn circuit missing")?
        .1;
    let fee_zkbin_bytes = &zkas_bins
        .iter()
        .find(|x| x.0 == MONEY_CONTRACT_ZKAS_FEE_NS_V1)
        .ok_or("Fee circuit missing")?
        .1;

    let mint_zkbin = ZkBinary::decode(mint_zkbin_bytes, false)?;
    let burn_zkbin = ZkBinary::decode(burn_zkbin_bytes, false)?;
    let fee_zkbin = ZkBinary::decode(fee_zkbin_bytes, false)?;

    let mint_circuit = ZkCircuit::new(empty_witnesses(&mint_zkbin)?, &mint_zkbin);
    let burn_circuit = ZkCircuit::new(empty_witnesses(&burn_zkbin)?, &burn_zkbin);
    let fee_circuit = ZkCircuit::new(empty_witnesses(&fee_zkbin)?, &fee_zkbin);

    let mint_pk = ProvingKey::build(mint_zkbin.k, &mint_circuit);
    let burn_pk = ProvingKey::build(burn_zkbin.k, &burn_circuit);
    let fee_pk = ProvingKey::build(fee_zkbin.k, &fee_circuit);

    // Transfer call (upstream make_transfer_call: no payment_memo arg;
    // notes currently use empty memo in money client builder).

    let mut spendable = Vec::with_capacity(all_coins.len());
    for coin in all_coins {
        match assert_witness_at_tip(&tree, MerkleNode::from(coin.coin.inner()), coin.leaf_position)
        {
            Ok(_) => spendable.push(coin),
            Err(e) => eprintln!(
                "Skipping coin not authenticated to the current Money tree: {e}"
            ),
        }
    }
    if spendable.is_empty() {
        return Err(
            "No spendable coins with a valid Merkle witness. Rebuild with: \
             moonshine sync --rebuild-merkle --allow-trial"
                .into(),
        );
    }

    let fee_candidates: Vec<OwnCoin> = spendable
        .iter()
        .filter(|c| c.note.value >= fee && c.note.token_id == token_id)
        .cloned()
        .collect();

    let (mut params, secrets, spent_coins) = make_transfer_call(
        keypair,
        recipient_pubkey,
        amount,
        token_id,
        spendable.clone(),
        tree.clone(),
        None, // spend_hook
        None, // user_data
        mint_zkbin,
        mint_pk,
        burn_zkbin,
        burn_pk,
        half_split,
    )?;
    let _ = payment_memo; // retained in local tx history by caller when present

    let mut spent_commitments: Vec<Vec<u8>> =
        spent_coins.iter().map(own_coin_commitment).collect();
    let mut spent_nullifiers: Vec<Vec<u8>> =
        spent_coins.iter().map(own_coin_nullifier).collect();

    struct FeeSrc {
        coin: OwnCoin,
        merkle_path: Vec<MerkleNode>,
        input_tx_local: bool,
        expected_root: Option<MerkleNode>,
    }

    let fee_src = if fee > 0 {
        let leftover = fee_candidates.iter().find(|c| {
            !spent_coins.iter().any(|sc| sc.coin == c.coin) && c.note.value >= fee
        });
        if let Some(c) = leftover {
            let merkle_path = tree
                .witness(c.leaf_position, 0)
                .map_err(|_| "Merkle path missing for fee coin")?;
            Some(FeeSrc {
                coin: c.clone(),
                merkle_path,
                input_tx_local: false,
                expected_root: tree.root(0),
            })
        } else {
            // DEP-0008: spend transfer change inside this tx (tx-local tree).
            // Must match host `merkle_add_local`: dummy ZERO leaf, then local coins.
            let mut local_tree = MerkleTree::new(1);
            local_tree.append(MerkleNode::from(pallas::Base::ZERO));
            let mut src = None;
            for output in params.outputs.iter_mut() {
                let Ok(note) = output.note.decrypt::<MoneyNote>(&keypair.secret) else {
                    continue;
                };
                if note.value < fee || note.token_id != token_id {
                    continue;
                }
                let derived = CoinAttributes {
                    public_key: PublicKey::from_secret(keypair.secret),
                    value: note.value,
                    token_id: note.token_id,
                    spend_hook: note.spend_hook,
                    user_data: note.user_data,
                    blind: note.coin_blind,
                }
                .to_coin();
                if derived != output.coin {
                    return Err(format!(
                        "tx-local change coin mismatch: output={} derived={}",
                        hex::encode(output.coin.inner().to_repr()),
                        hex::encode(derived.inner().to_repr())
                    )
                    .into());
                }
                output.tx_local = true;
                local_tree.append(MerkleNode::from(output.coin.inner()));
                let leaf_position = local_tree
                    .mark()
                    .ok_or("tx-local merkle mark failed")?;
                let coin = OwnCoin {
                    coin: output.coin,
                    note,
                    secret: keypair.secret,
                    leaf_position,
                };
                let merkle_path = local_tree
                    .witness(leaf_position, 0)
                    .map_err(|_| "tx-local merkle path missing")?;
                let expected_root = local_tree.root(0);
                eprintln!(
                    "tx-local tree root={} pos={:?} change={}",
                    expected_root
                        .map(|r| hex::encode(r.to_bytes()))
                        .unwrap_or_default(),
                    leaf_position,
                    hex::encode(output.coin.inner().to_repr())
                );
                src = Some(FeeSrc {
                    coin,
                    merkle_path,
                    input_tx_local: true,
                    expected_root,
                });
                break;
            }
            src
        }
    } else {
        None
    };

    if fee > 0 && fee_src.is_none() {
        return Err(
            "Not enough native tokens to pay for fee (need a leftover coin or change >= fee)"
                .into(),
        );
    }

    let mut data = vec![MoneyFunction::TransferV1 as u8];
    params.encode_async(&mut data).await?;
    let call = ContractCall {
        contract_id: *MONEY_CONTRACT_ID,
        data,
    };

    let transfer_leaf = ContractCallLeaf {
        call,
        proofs: secrets.proofs,
    };

    // Fee call — only when fee > 0 (skip_fees mode on darkfid doesn't
    // require or support Fee calls).
    if let Some(fee_src) = fee_src {
        if !fee_src.input_tx_local {
            spent_commitments.push(own_coin_commitment(&fee_src.coin));
            spent_nullifiers.push(own_coin_nullifier(&fee_src.coin));
        }
        let change_value = fee_src.coin.note.value - fee;

        let input = FeeCallInput {
            coin: fee_src.coin.clone(),
            merkle_path: fee_src.merkle_path,
            user_data_blind: Blind::random(&mut rand_core::OsRng),
        };

        let output = FeeCallOutput {
            public_key: PublicKey::from_secret(fee_src.coin.secret),
            value: change_value,
            token_id: fee_src.coin.note.token_id,
            blind: Blind::random(&mut rand_core::OsRng),
            spend_hook: FuncId::none(),
            user_data: pallas::Base::ZERO,
        };

        let input_value_blind = Blind::random(&mut rand_core::OsRng);
        let fee_value_blind = Blind::random(&mut rand_core::OsRng);
        let output_value_blind = compute_remainder_blind(&[input_value_blind], &[fee_value_blind]);

        let token_blind = Blind::random(&mut rand_core::OsRng);
        let signature_secret = SecretKey::random(&mut rand_core::OsRng);

        let (fee_proof, public_inputs) = create_fee_proof(
            &fee_zkbin,
            &fee_pk,
            &input,
            input_value_blind,
            &output,
            output_value_blind,
            output.spend_hook,
            output.user_data,
            output.blind,
            token_blind,
            signature_secret,
        )?;
        if let Some(expected) = fee_src.expected_root {
            if expected != public_inputs.merkle_root {
                return Err(format!(
                    "fee proof Merkle root {} != wallet tree root {}",
                    hex::encode(public_inputs.merkle_root.to_bytes()),
                    hex::encode(expected.to_bytes())
                )
                .into());
            }
        }

        let note = MoneyNote {
            coin_blind: output.blind,
            value: output.value,
            token_id: output.token_id,
            spend_hook: output.spend_hook,
            user_data: output.user_data,
            value_blind: output_value_blind,
            token_blind,
            memo: vec![],
        };

        let encrypted_note =
            AeadEncryptedNote::encrypt(&note, &output.public_key, &mut rand_core::OsRng)
                .map_err(|_| "Failed to encrypt note")?;

        let fee_params = MoneyFeeParamsV1 {
            input: darkfi_money_contract::model::Input {
                value_commit: public_inputs.input_value_commit,
                token_commit: public_inputs.token_commit,
                nullifier: public_inputs.nullifier,
                merkle_root: public_inputs.merkle_root,
                user_data_enc: public_inputs.input_user_data_enc,
                signature_public: public_inputs.signature_public,
                tx_local: fee_src.input_tx_local,
            },
            output: darkfi_money_contract::model::Output {
                value_commit: public_inputs.output_value_commit,
                token_commit: public_inputs.token_commit,
                coin: public_inputs.output_coin,
                note: encrypted_note,
                tx_local: false,
            },
            fee_value_blind,
            token_blind,
        };

        let mut data = vec![MoneyFunction::FeeV1 as u8];
        // Wire format matches `drk` / money contract: [FeeV1][u64 paid_fee][MoneyFeeParamsV1].
        fee.encode_async(&mut data).await?;
        fee_params.encode_async(&mut data).await?;
        let fee_call = ContractCall {
            contract_id: *MONEY_CONTRACT_ID,
            data,
        };

        // Forest siblings, Transfer first then Fee. DarkTree children are
        // emitted post-order (child before parent), which would run Fee
        // before Transfer apply and miss the tx-local Merkle root.
        let mut tx_builder = TransactionBuilder::new(transfer_leaf, vec![])?;
        tx_builder.append(
            ContractCallLeaf {
                call: fee_call,
                proofs: vec![fee_proof],
            },
            vec![],
        )?;

        let mut tx = tx_builder.build()?;
        let sigs = tx.create_sigs(&secrets.signature_secrets)?;
        tx.signatures.push(sigs);
        let fee_sigs = tx.create_sigs(&[signature_secret])?;
        tx.signatures.push(fee_sigs);
        Ok(BuiltTransfer {
            tx,
            spent_commitments,
            spent_nullifiers,
        })
    } else {
        // No fee call — build transaction with just the transfer call.
        let mut tx_builder = TransactionBuilder::new(transfer_leaf, vec![])?;
        let mut tx = tx_builder.build()?;
        let sigs = tx.create_sigs(&secrets.signature_secrets)?;
        tx.signatures.push(sigs);
        Ok(BuiltTransfer {
            tx,
            spent_commitments,
            spent_nullifiers,
        })
    }
}
