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
        transfer_v1::{TransferCallBuilder, TransferCallInput, TransferCallOutput},
        MoneyNote, OwnCoin,
    },
    model::{CoinAttributes, MoneyFeeParamsV1, MoneyTransferParamsV1, TokenId, DARK_TOKEN_ID},
    MoneyFunction, MONEY_CONTRACT_ZKAS_BURN_NS_V1, MONEY_CONTRACT_ZKAS_FEE_NS_V1,
    MONEY_CONTRACT_ZKAS_MINT_NS_V1,
};
use darkfi_sdk::bridgetree::Hashable;
use darkfi_sdk::crypto::pasta_prelude::{Field, Group, PrimeField};
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
use rand_core::RngCore;
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
             Rebuild with: moonshine sync --rebuild-merkle --force-trial",
            hex::encode(witnessed.to_bytes()),
            hex::encode(tip_root.to_bytes()),
        )
        .into());
    }
    Ok(tip_root)
}

/// Compute the final output's Pedersen value blinding factor so that:
/// `sum(input_blinds) - sum(output_blinds) == 0 (mod q)`,
/// matching DarkFi's `Money::TransferV1` entrypoint balance equation:
/// `sum(inputs.value_commit) - sum(outputs.value_commit) == identity`.
pub fn compute_remainder_blind(
    inputs: &[Blind<pallas::Scalar>],
    outputs: &[Blind<pallas::Scalar>],
) -> Blind<pallas::Scalar> {
    let mut remainder = pallas::Scalar::ZERO;
    for i in inputs {
        remainder += i.inner();
    }
    for o in outputs {
        remainder -= o.inner();
    }
    Blind(remainder)
}

/// Verify that a `MoneyTransferParamsV1` satisfies DarkFi's per-token-group
/// Pedersen commitment balance check (`sum(inputs) - sum(outputs) == identity`).
pub(crate) fn verify_transfer_value_balance(
    params: &MoneyTransferParamsV1,
) -> Result<(), Box<dyn Error>> {
    let mut groups: Vec<(pallas::Base, pallas::Point)> = Vec::new();
    for inp in &params.inputs {
        if let Some((_, acc)) = groups.iter_mut().find(|(tc, _)| *tc == inp.token_commit) {
            *acc += inp.value_commit;
        } else {
            groups.push((inp.token_commit, inp.value_commit));
        }
    }
    for out in &params.outputs {
        if let Some((_, acc)) = groups.iter_mut().find(|(tc, _)| *tc == out.token_commit) {
            *acc -= out.value_commit;
        } else {
            groups.push((out.token_commit, -out.value_commit));
        }
    }
    for (i, (_, acc)) in groups.iter().enumerate() {
        if *acc != pallas::Point::identity() {
            return Err(
                format!("TransferV1 value commitments in token group {i} do not balance").into(),
            );
        }
    }
    Ok(())
}

/// Deterministic sort key for reproducible coin selection:
/// `(leaf_position, coin_commitment_bytes)`.
fn coin_tie_key(c: &OwnCoin) -> (u64, [u8; 32]) {
    (u64::from(c.leaf_position), c.coin.to_bytes())
}

/// Wallet cap on TransferV1 inputs (one Halo2 burn proof each).
///
/// DarkFi `MAX_TX_CALLS` (20) bounds contract calls in a transaction, not burn
/// proofs inside one Money transfer. Nothing in this tree caps that proof
/// count, so a dust wallet stops here and must consolidate.
pub const MAX_TRANSFER_INPUTS: usize = 8;

/// Selection refused because the transfer would build too many burn proofs.
#[derive(Debug, thiserror::Error)]
#[error(
    "this transfer would use {attempted} inputs, above the maximum of {max}. Consolidate coins into fewer notes and retry"
)]
pub struct TooManyTransferInputs {
    pub attempted: usize,
    pub max: usize,
}

/// Deterministically select minimal unspent coins covering `target`.
///
/// Strategy:
/// 1. If any single coin covers `target`, pick the smallest single coin `>= target`
///    (tie-broken deterministically by `(leaf_position, coin_bytes)`).
/// 2. Otherwise, greedily accumulate largest-first (tie-broken by `(leaf_position, coin_bytes)`)
///    until `sum >= target`, which achieves minimum input cardinality.
pub(crate) fn select_coins_deterministic(
    coins: &[OwnCoin],
    target: u64,
) -> Result<(Vec<OwnCoin>, u64), Box<dyn Error>> {
    if target == 0 {
        return Err("Transfer target amount must be greater than 0".into());
    }
    if coins.is_empty() {
        return Err("No eligible spendable coins available".into());
    }

    // 1. Prefer a single coin when possible (smallest >= target, deterministic tie-break).
    if let Some(best_single) = coins
        .iter()
        .filter(|c| c.note.value >= target)
        .min_by_key(|c| (c.note.value, coin_tie_key(c)))
    {
        return Ok((vec![best_single.clone()], best_single.note.value - target));
    }

    // 2. Multi-input: sort descending by value, tie-broken deterministically.
    let mut sorted: Vec<OwnCoin> = coins.to_vec();
    sorted.sort_by(|a, b| {
        b.note
            .value
            .cmp(&a.note.value)
            .then_with(|| coin_tie_key(a).cmp(&coin_tie_key(b)))
    });

    let mut selected = Vec::new();
    let mut total = 0u64;
    for coin in sorted {
        if selected.len() >= MAX_TRANSFER_INPUTS {
            return Err(TooManyTransferInputs {
                attempted: selected.len() + 1,
                max: MAX_TRANSFER_INPUTS,
            }
            .into());
        }
        total = total
            .checked_add(coin.note.value)
            .ok_or("Selected coin value sum overflow")?;
        selected.push(coin);
        if total >= target {
            return Ok((selected, total - target));
        }
    }

    Err(format!("Insufficient spendable coins: have {total} atomic, need {target} atomic").into())
}

/// Select minimal unspent, unhooked coins for `TransferV1` plus an optional separate
/// leftover native DRK coin for `FeeV1`.
///
/// For native DRK transfers with `fee > 0`:
/// - First selects minimal coins covering `amount`.
/// - If an unused native DRK coin `>= fee` remains, returns it as the separate fee input.
/// - Otherwise, if transfer change already covers `fee`, uses tx-local fee change (`None`).
/// - Otherwise, expands selection to cover `amount + fee` across multiple inputs so the
///   transfer change output (`>= fee`) funds `FeeV1` tx-locally.
#[allow(clippy::type_complexity)]
pub(crate) fn select_transfer_and_fee_coins(
    spendable: &[OwnCoin],
    token_id: TokenId,
    amount: u64,
    fee: u64,
) -> Result<(Vec<OwnCoin>, u64, Option<OwnCoin>), Box<dyn Error>> {
    let transfer_pool: Vec<OwnCoin> = spendable
        .iter()
        .filter(|c| c.note.spend_hook == FuncId::none() && c.note.token_id == token_id)
        .cloned()
        .collect();

    if transfer_pool.is_empty() {
        return Err("No unhooked spendable coins matching requested token".into());
    }

    if fee == 0 {
        let (sel, change) = select_coins_deterministic(&transfer_pool, amount)?;
        return Ok((sel, change, None));
    }

    let fee_pool = filter_fee_candidates(spendable, fee);

    if token_id == *DARK_TOKEN_ID {
        let (sel, change) = select_coins_deterministic(&transfer_pool, amount)?;
        // Check if an unused DRK coin can pay the fee directly.
        // Upstream `drk` requires value > fee so the fee output is non-zero.
        let leftover = fee_pool
            .iter()
            .filter(|c| !sel.iter().any(|s| s.coin == c.coin))
            .min_by_key(|c| (c.note.value, coin_tie_key(c)))
            .cloned();
        if let Some(fee_coin) = leftover {
            return Ok((sel, change, Some(fee_coin)));
        }
        if change >= fee {
            return Ok((sel, change, None));
        }
        // Neither a leftover fee coin nor transfer change covers `fee` yet:
        // select minimal coins covering `amount + fee` so tx-local change >= fee.
        let total_needed = amount.checked_add(fee).ok_or("amount + fee overflow")?;
        let (sel_with_fee, remainder_after_fee) =
            select_coins_deterministic(&transfer_pool, total_needed)?;
        let transfer_change = remainder_after_fee
            .checked_add(fee)
            .ok_or("transfer change overflow")?;
        Ok((sel_with_fee, transfer_change, None))
    } else {
        let (sel, change) = select_coins_deterministic(&transfer_pool, amount)?;
        let fee_coin = fee_pool
            .iter()
            .min_by_key(|c| (c.note.value, coin_tie_key(c)))
            .cloned()
            .ok_or_else(|| {
                format!(
                    "No single unhooked native DRK coin covers fee of {fee} atomic units \
                     (FeeV1 takes 1 input; consolidate DRK coins or lower --fee)"
                )
            })?;
        Ok((sel, change, Some(fee_coin)))
    }
}

/// Built Money transfer (+ optional fee) plus the coins it spends.
///
/// Callers must mark these notes spent after a successful broadcast so the
/// next send cannot republish the same nullifiers.
pub struct BuiltTransfer {
    pub tx: Transaction,
    pub spent_commitments: Vec<Vec<u8>>,
    pub spent_nullifiers: Vec<Vec<u8>>,
    /// Compact-block output indexes of change that decrypts to this wallet.
    pub self_output_indices: Vec<u32>,
    /// Total number of non-tx-local outputs in the transaction (transfer + optional fee).
    pub total_outputs: u32,
}

/// Compact output indexes (skipping tx-local coins) that belong to `secret`,
/// plus total non-tx-local output count.
fn self_output_indices(
    outputs: &[darkfi_money_contract::model::Output],
    secret: &SecretKey,
    include_fee_change: bool,
) -> (Vec<u32>, u32) {
    let mut idx = 0u32;
    let mut ours = Vec::new();
    for output in outputs {
        if output.tx_local {
            continue;
        }
        if output.note.decrypt::<MoneyNote>(secret).is_ok() {
            ours.push(idx);
        }
        idx += 1;
    }
    if include_fee_change {
        ours.push(idx);
        idx += 1;
    }
    (ours, idx)
}

/// Filter unhooked native DRK coins eligible to pay `FeeV1`.
/// `FeeV1` strictly requires `*DARK_TOKEN_ID` and `FuncId::none()`.
pub(crate) fn filter_fee_candidates(spendable: &[OwnCoin], fee: u64) -> Vec<OwnCoin> {
    spendable
        .iter()
        .filter(|c| {
            c.note.value > fee
                && c.note.spend_hook == FuncId::none()
                && c.note.token_id == *DARK_TOKEN_ID
        })
        .cloned()
        .collect()
}

fn own_coin_commitment(coin: &OwnCoin) -> Vec<u8> {
    coin.coin.inner().to_repr().to_vec()
}

fn own_coin_nullifier(coin: &OwnCoin) -> Vec<u8> {
    coin.nullifier().inner().to_repr().to_vec()
}

/// Fisher-Yates shuffle using `OsRng` (cryptographic RNG, avoids output-order correlation).
fn shuffle_osrng<T>(slice: &mut [T]) {
    for i in (1..slice.len()).rev() {
        let j = (rand_core::OsRng.next_u64() as usize) % (i + 1);
        slice.swap(i, j);
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn build_transaction_extended(
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
    spend_hook: Option<FuncId>,
    user_data: Option<pallas::Base>,
) -> Result<BuiltTransfer, Box<dyn Error>> {
    if amount == 0 {
        return Err("Transfer amount must be greater than 0".into());
    }
    if half_split && amount == 1 {
        return Err("Cannot half-split an amount of 1 atomic unit".into());
    }
    if token_id.inner() == pallas::Base::ZERO {
        return Err(format!("Invalid token ID: {token_id}").into());
    }

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

    // Filter to coins with valid Merkle witnesses at the current tree tip.
    let mut spendable = Vec::with_capacity(all_coins.len());
    for coin in all_coins {
        match assert_witness_at_tip(
            &tree,
            MerkleNode::from(coin.coin.inner()),
            coin.leaf_position,
        ) {
            Ok(_) => spendable.push(coin),
            Err(e) => eprintln!("Skipping coin not authenticated to the current Money tree: {e}"),
        }
    }
    if spendable.is_empty() {
        return Err(
            "No spendable coins with a valid Merkle witness. Rebuild with: \
             moonshine sync --rebuild-merkle --force-trial"
                .into(),
        );
    }

    // Deterministic multi-input coin selection for TransferV1 + optional separate FeeV1 coin.
    let (spent_coins, change_value, leftover_fee_coin) =
        select_transfer_and_fee_coins(&spendable, token_id, amount, fee)?;

    let mut inputs = Vec::with_capacity(spent_coins.len());
    for coin in &spent_coins {
        let merkle_path = tree.witness(coin.leaf_position, 0).map_err(|_| {
            format!(
                "Merkle witness missing for coin at {:?}",
                coin.leaf_position
            )
        })?;
        inputs.push(TransferCallInput {
            coin: coin.clone(),
            merkle_path,
            user_data_blind: Blind::random(&mut rand_core::OsRng),
        });
    }

    // Build outputs (payment output(s) + optional change), tagging the exact change output
    // so output-order shuffling can never confuse change with a self-payment output.
    let recipient_memo = payment_memo.unwrap_or_default();
    let mut tagged_outputs: Vec<(TransferCallOutput, Vec<u8>, bool)> = Vec::new();
    if half_split {
        let first_half = amount / 2;
        let second_half = first_half + (amount % 2);
        for val in [first_half, second_half] {
            if val > 0 {
                tagged_outputs.push((
                    TransferCallOutput {
                        public_key: recipient_pubkey,
                        value: val,
                        token_id,
                        spend_hook: spend_hook.unwrap_or(FuncId::none()),
                        user_data: user_data.unwrap_or(pallas::Base::ZERO),
                        blind: Blind::random(&mut rand_core::OsRng),
                    },
                    recipient_memo.clone(),
                    false,
                ));
            }
        }
    } else {
        tagged_outputs.push((
            TransferCallOutput {
                public_key: recipient_pubkey,
                value: amount,
                token_id,
                spend_hook: spend_hook.unwrap_or(FuncId::none()),
                user_data: user_data.unwrap_or(pallas::Base::ZERO),
                blind: Blind::random(&mut rand_core::OsRng),
            },
            recipient_memo,
            false,
        ));
    }

    if change_value > 0 {
        tagged_outputs.push((
            TransferCallOutput {
                public_key: keypair.public,
                value: change_value,
                token_id,
                spend_hook: FuncId::none(),
                user_data: pallas::Base::ZERO,
                blind: Blind::random(&mut rand_core::OsRng),
            },
            Vec::new(),
            true,
        ));
    }

    shuffle_osrng(&mut tagged_outputs);
    let change_output_idx = tagged_outputs.iter().position(|(_, _, is_chg)| *is_chg);
    let mut outputs = Vec::with_capacity(tagged_outputs.len());
    let mut output_memos = Vec::with_capacity(tagged_outputs.len());
    for (out, memo, _) in tagged_outputs {
        outputs.push(out);
        output_memos.push(memo);
    }

    let (mut params, secrets) = TransferCallBuilder {
        clear_inputs: vec![],
        inputs,
        outputs,
        mint_zkbin,
        mint_pk,
        burn_zkbin,
        burn_pk,
        output_memos,
    }
    .build()?;

    // Verify multi-input Pedersen value commitment balance & remainder blind identity
    // matching DarkFi's TransferV1 entrypoint before signing or broadcasting.
    verify_transfer_value_balance(&params)?;
    let residual =
        compute_remainder_blind(&secrets.input_value_blinds, &secrets.output_value_blinds);
    if residual.inner() != pallas::Scalar::ZERO {
        return Err("TransferV1 multi-input value blind balance mismatch".into());
    }

    let mut spent_commitments: Vec<Vec<u8>> = spent_coins.iter().map(own_coin_commitment).collect();
    let mut spent_nullifiers: Vec<Vec<u8>> = spent_coins.iter().map(own_coin_nullifier).collect();

    struct FeeSrc {
        coin: OwnCoin,
        merkle_path: Vec<MerkleNode>,
        input_tx_local: bool,
        expected_root: Option<MerkleNode>,
    }

    let fee_src = if fee > 0 {
        if let Some(c) = leftover_fee_coin {
            let merkle_path = tree
                .witness(c.leaf_position, 0)
                .map_err(|_| "Merkle path missing for fee coin")?;
            Some(FeeSrc {
                coin: c,
                merkle_path,
                input_tx_local: false,
                expected_root: tree.root(0),
            })
        } else if let Some(idx) = change_output_idx {
            // DEP-0008: spend the tagged change output inside this tx (tx-local tree).
            // The index comes from the shuffle tag. Position is not a proxy for change.
            // Must match host `merkle_add_local`: dummy ZERO leaf, then local coins.
            let Some((chosen_idx, secret, note, _)) =
                crate::fee_attach::select_tx_local_fee_candidate(
                    &params.outputs,
                    &[keypair.secret],
                    &[],
                    fee,
                    Some(idx),
                )
            else {
                return Err("Transfer change output is not eligible to pay FeeV1".into());
            };
            let mut local_tree = MerkleTree::new(1);
            local_tree.append(MerkleNode::from(pallas::Base::ZERO));
            let output = &mut params.outputs[chosen_idx];
            let derived = CoinAttributes {
                public_key: PublicKey::from_secret(secret),
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
            let leaf_position = local_tree.mark().ok_or("tx-local merkle mark failed")?;
            let coin = OwnCoin {
                coin: output.coin,
                note,
                secret,
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
            Some(FeeSrc {
                coin,
                merkle_path,
                input_tx_local: true,
                expected_root,
            })
        } else {
            None
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

    let transfer_leaf = ContractCallLeaf::new(call, secrets.proofs, secrets.signature_secrets);

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
            ContractCallLeaf::new(fee_call, vec![fee_proof], vec![signature_secret]),
            vec![],
        )?;

        let tx = tx_builder.build_signed()?;
        let (self_output_indices, total_outputs) =
            self_output_indices(&params.outputs, &keypair.secret, true);
        Ok(BuiltTransfer {
            tx,
            spent_commitments,
            spent_nullifiers,
            self_output_indices,
            total_outputs,
        })
    } else {
        // No fee call — build transaction with just the transfer call.
        let mut tx_builder = TransactionBuilder::new(transfer_leaf, vec![])?;
        let tx = tx_builder.build_signed()?;
        let (self_output_indices, total_outputs) =
            self_output_indices(&params.outputs, &keypair.secret, false);
        Ok(BuiltTransfer {
            tx,
            spent_commitments,
            spent_nullifiers,
            self_output_indices,
            total_outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use darkfi_money_contract::model::{Output, DARK_TOKEN_ID};
    use darkfi_sdk::crypto::pedersen::pedersen_commitment_u64;

    fn make_own_coin_at(value: u64, token_id: TokenId, spend_hook: FuncId, pos: u64) -> OwnCoin {
        let kp = Keypair::random(&mut rand_core::OsRng);
        let blind = Blind::random(&mut rand_core::OsRng);
        let note = MoneyNote {
            value,
            token_id,
            spend_hook,
            user_data: pallas::Base::ZERO,
            coin_blind: blind,
            value_blind: Blind(pallas::Scalar::from(1u64)),
            token_blind: Blind::from(2u64),
            memo: Vec::new(),
        };
        let coin = CoinAttributes {
            public_key: kp.public,
            value,
            token_id,
            spend_hook,
            user_data: pallas::Base::ZERO,
            blind,
        }
        .to_coin();
        OwnCoin {
            coin,
            note,
            secret: kp.secret,
            leaf_position: pos.into(),
        }
    }

    fn make_own_coin(value: u64, token_id: TokenId, spend_hook: FuncId) -> OwnCoin {
        make_own_coin_at(value, token_id, spend_hook, 1)
    }

    fn make_encrypted_output(
        kp: &Keypair,
        value: u64,
        spend_hook: FuncId,
        memo: Vec<u8>,
    ) -> Output {
        let blind = Blind::random(&mut rand_core::OsRng);
        let note = MoneyNote {
            value,
            token_id: *DARK_TOKEN_ID,
            spend_hook,
            user_data: pallas::Base::ZERO,
            coin_blind: blind,
            value_blind: Blind(pallas::Scalar::from(1u64)),
            token_blind: Blind::from(2u64),
            memo,
        };
        let coin = CoinAttributes {
            public_key: kp.public,
            value,
            token_id: *DARK_TOKEN_ID,
            spend_hook,
            user_data: pallas::Base::ZERO,
            blind,
        }
        .to_coin();
        let enc = AeadEncryptedNote::encrypt(&note, &kp.public, &mut rand_core::OsRng).unwrap();
        Output {
            value_commit: pallas::Point::identity(),
            token_commit: pallas::Base::ZERO,
            coin,
            note: enc,
            tx_local: false,
        }
    }

    #[test]
    fn filter_fee_candidates_excludes_hooked_and_zero_token() {
        let dao_hook = crate::dao_ops::dao_spend_hook();
        let hooked = make_own_coin(10_000_000, *DARK_TOKEN_ID, dao_hook);
        let zero_tok = make_own_coin(
            10_000_000,
            TokenId::from(pallas::Base::ZERO),
            FuncId::none(),
        );
        let valid = make_own_coin(10_000_000, *DARK_TOKEN_ID, FuncId::none());
        let too_small = make_own_coin(100, *DARK_TOKEN_ID, FuncId::none());

        let exact = make_own_coin(5_000_000, *DARK_TOKEN_ID, FuncId::none());
        let kept = filter_fee_candidates(
            &[hooked, zero_tok, valid.clone(), too_small, exact],
            5_000_000,
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].coin, valid.coin);
    }

    #[test]
    fn tx_local_fee_skips_payment_output_and_memo_and_hook() {
        let kp = Keypair::random(&mut rand_core::OsRng);
        let dao_hook = crate::dao_ops::dao_spend_hook();
        let payment = make_encrypted_output(&kp, 50_000_000, FuncId::none(), b"pay-self".to_vec());
        let hooked = make_encrypted_output(&kp, 50_000_000, dao_hook, vec![]);
        let change = make_encrypted_output(&kp, 20_000_000, FuncId::none(), vec![]);

        let pick = |outputs: &[Output], idx: Option<usize>| {
            crate::fee_attach::select_tx_local_fee_candidate(
                outputs,
                &[kp.secret],
                &[],
                5_000_000,
                idx,
            )
            .map(|(i, _, note, _)| (i, note.value))
        };

        let chosen = pick(&[payment.clone(), hooked.clone(), change.clone()], Some(2))
            .expect("should pick the tagged change output");
        assert_eq!(chosen.0, 2);
        assert_eq!(chosen.1, 20_000_000);

        // Change shuffled to index 0. An unmemoized payment at index 1 is not the fee.
        let bare_payment = make_encrypted_output(&kp, 50_000_000, FuncId::none(), vec![]);
        let shuffled = pick(&[change.clone(), bare_payment.clone()], Some(0))
            .expect("change at index 0 is eligible");
        assert_eq!(shuffled.0, 0);
        assert_eq!(shuffled.1, 20_000_000);
        assert!(pick(&[change, bare_payment.clone()], None).is_none());
        assert!(pick(&[bare_payment.clone(), payment.clone()], Some(1)).is_none());

        let unmemoized_payment = make_encrypted_output(&kp, 50_000_000, FuncId::none(), vec![]);
        assert!(pick(&[unmemoized_payment], None).is_none());
        assert!(pick(&[payment.clone(), payment], None).is_none());
        assert!(pick(&[hooked, bare_payment], Some(0)).is_none());
    }

    #[test]
    fn multi_input_pedersen_blind_balance_2_and_3_inputs() {
        // 2-input -> 2-output (payment + change)
        let in2_vals = [40_000_000u64, 35_000_000u64];
        let out2_vals = [60_000_000u64, 15_000_000u64];
        let in2_blinds = [
            Blind::random(&mut rand_core::OsRng),
            Blind::random(&mut rand_core::OsRng),
        ];
        let out2_b0 = Blind::random(&mut rand_core::OsRng);
        let out2_b1 = compute_remainder_blind(&in2_blinds, &[out2_b0]);

        let mut acc2 = pallas::Point::identity();
        for (&v, &b) in in2_vals.iter().zip(in2_blinds.iter()) {
            acc2 += pedersen_commitment_u64(v, b);
        }
        acc2 -= pedersen_commitment_u64(out2_vals[0], out2_b0);
        acc2 -= pedersen_commitment_u64(out2_vals[1], out2_b1);
        assert_eq!(
            acc2,
            pallas::Point::identity(),
            "2-input TransferV1 Pedersen commitments must sum to identity"
        );
        assert_eq!(
            compute_remainder_blind(&in2_blinds, &[out2_b0, out2_b1]).inner(),
            pallas::Scalar::ZERO
        );

        // 3-input -> 3-output (--half-split payment + change)
        let in3_vals = [25_000_000u64, 30_000_000u64, 20_000_000u64];
        let out3_vals = [32_500_000u64, 32_500_000u64, 10_000_000u64];
        let in3_blinds = [
            Blind::random(&mut rand_core::OsRng),
            Blind::random(&mut rand_core::OsRng),
            Blind::random(&mut rand_core::OsRng),
        ];
        let out3_b0 = Blind::random(&mut rand_core::OsRng);
        let out3_b1 = Blind::random(&mut rand_core::OsRng);
        let out3_b2 = compute_remainder_blind(&in3_blinds, &[out3_b0, out3_b1]);

        let mut acc3 = pallas::Point::identity();
        for (&v, &b) in in3_vals.iter().zip(in3_blinds.iter()) {
            acc3 += pedersen_commitment_u64(v, b);
        }
        for (&v, &b) in out3_vals.iter().zip([out3_b0, out3_b1, out3_b2].iter()) {
            acc3 -= pedersen_commitment_u64(v, b);
        }
        assert_eq!(
            acc3,
            pallas::Point::identity(),
            "3-input TransferV1 Pedersen commitments must sum to identity"
        );

        // 3-input -> 1-output (exact sweep, 0 change)
        let out1_b0 = compute_remainder_blind(&in3_blinds, &[]);
        let mut acc_exact = pallas::Point::identity();
        for (&v, &b) in in3_vals.iter().zip(in3_blinds.iter()) {
            acc_exact += pedersen_commitment_u64(v, b);
        }
        acc_exact -= pedersen_commitment_u64(75_000_000, out1_b0);
        assert_eq!(
            acc_exact,
            pallas::Point::identity(),
            "3-input exact-sweep TransferV1 Pedersen commitments must sum to identity"
        );
    }

    #[test]
    fn coin_selection_2_input_and_3_input_and_fee_edge_cases() {
        let c1 = make_own_coin_at(50_000_000, *DARK_TOKEN_ID, FuncId::none(), 1);
        let c2 = make_own_coin_at(40_000_000, *DARK_TOKEN_ID, FuncId::none(), 2);
        let c3 = make_own_coin_at(20_000_000, *DARK_TOKEN_ID, FuncId::none(), 3);
        let hooked = make_own_coin_at(
            999_000_000,
            *DARK_TOKEN_ID,
            crate::dao_ops::dao_spend_hook(),
            4,
        );

        // 2-input transfer (60M + 5M fee = 65M): selects c1 (50M) + c2 (40M) = 90M,
        // and leftover c3 (20M) pays fee separately (or change 30M pays tx-locally).
        let (sel2, chg2, fee2) = select_transfer_and_fee_coins(
            &[c3.clone(), hooked.clone(), c1.clone(), c2.clone()],
            *DARK_TOKEN_ID,
            60_000_000,
            5_000_000,
        )
        .unwrap();
        assert_eq!(sel2.len(), 2);
        assert_eq!(sel2[0].coin, c1.coin);
        assert_eq!(sel2[1].coin, c2.coin);
        assert_eq!(chg2, 30_000_000);
        assert_eq!(fee2.as_ref().map(|c| c.coin), Some(c3.coin));

        // 3-input transfer (100M + 5M fee = 105M): selects all 3 unhooked coins (110M),
        // change = 10M >= 5M fee (paid tx-locally), excludes hooked 999M coin!
        let (sel3, chg3, fee3) = select_transfer_and_fee_coins(
            &[c3.clone(), hooked.clone(), c2.clone(), c1.clone()],
            *DARK_TOKEN_ID,
            100_000_000,
            5_000_000,
        )
        .unwrap();
        assert_eq!(sel3.len(), 3);
        assert_eq!(chg3, 10_000_000);
        assert!(fee3.is_none(), "fee must come from tx-local change >= fee");

        // Edge case: [60M, 3M, 3M] sending 60M + 5M fee. Neither 3M coin covers 5M fee alone,
        // so selector MUST pull all 3 coins into TransferV1 (total 66M -> change 6M >= 5M fee).
        let big = make_own_coin_at(60_000_000, *DARK_TOKEN_ID, FuncId::none(), 10);
        let dust_a = make_own_coin_at(3_000_000, *DARK_TOKEN_ID, FuncId::none(), 11);
        let dust_b = make_own_coin_at(3_000_000, *DARK_TOKEN_ID, FuncId::none(), 12);
        let (sel_edge, chg_edge, fee_edge) = select_transfer_and_fee_coins(
            &[dust_b.clone(), big.clone(), dust_a.clone()],
            *DARK_TOKEN_ID,
            60_000_000,
            5_000_000,
        )
        .unwrap();
        assert_eq!(sel_edge.len(), 3);
        assert_eq!(chg_edge, 6_000_000);
        assert!(fee_edge.is_none());

        // Determinism check: reversed input order produces identical selection.
        let (sel_rev, chg_rev, fee_rev) = select_transfer_and_fee_coins(
            &[dust_a, big, dust_b],
            *DARK_TOKEN_ID,
            60_000_000,
            5_000_000,
        )
        .unwrap();
        assert_eq!(
            sel_edge.iter().map(|c| c.coin).collect::<Vec<_>>(),
            sel_rev.iter().map(|c| c.coin).collect::<Vec<_>>()
        );
        assert_eq!(chg_edge, chg_rev);
        assert_eq!(fee_edge.map(|c| c.coin), fee_rev.map(|c| c.coin));
    }

    #[test]
    fn custom_token_multi_input_with_separate_drk_fee() {
        let custom_tok = TokenId::from(pallas::Base::from(777u64));
        let t1 = make_own_coin_at(300, custom_tok, FuncId::none(), 1);
        let t2 = make_own_coin_at(400, custom_tok, FuncId::none(), 2);
        let t3 = make_own_coin_at(200, custom_tok, FuncId::none(), 3);
        let drk_fee = make_own_coin_at(10_000_000, *DARK_TOKEN_ID, FuncId::none(), 4);

        let (sel, chg, fee_coin) = select_transfer_and_fee_coins(
            &[t3, drk_fee.clone(), t1.clone(), t2.clone()],
            custom_tok,
            650,
            5_000_000,
        )
        .unwrap();
        assert_eq!(sel.len(), 2);
        assert_eq!(sel[0].coin, t2.coin);
        assert_eq!(sel[1].coin, t1.coin);
        assert_eq!(chg, 50);
        assert_eq!(fee_coin.as_ref().map(|c| c.coin), Some(drk_fee.coin));
    }

    #[test]
    fn transfer_input_cap_asks_to_consolidate() {
        let dust: Vec<OwnCoin> = (0..12)
            .map(|i| make_own_coin_at(1_000_000, *DARK_TOKEN_ID, FuncId::none(), i))
            .collect();
        let (exact, change) =
            select_coins_deterministic(&dust, (MAX_TRANSFER_INPUTS as u64) * 1_000_000).unwrap();
        assert_eq!(exact.len(), MAX_TRANSFER_INPUTS);
        assert_eq!(change, 0);

        let err = select_coins_deterministic(&dust, (MAX_TRANSFER_INPUTS as u64 + 1) * 1_000_000)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Consolidate"),
            "cap error should tell the user to consolidate: {msg}"
        );
        assert!(
            msg.contains(&MAX_TRANSFER_INPUTS.to_string()),
            "cap error should name the limit: {msg}"
        );
        let too_many = err
            .downcast_ref::<TooManyTransferInputs>()
            .expect("structured cap error");
        assert_eq!(too_many.max, MAX_TRANSFER_INPUTS);
        assert!(too_many.attempted > MAX_TRANSFER_INPUTS);

        // A single covering coin is still one input, even in a dust wallet.
        let mut mixed = dust.clone();
        mixed.push(make_own_coin_at(
            50_000_000,
            *DARK_TOKEN_ID,
            FuncId::none(),
            100,
        ));
        let (one, _) = select_coins_deterministic(&mixed, 40_000_000).unwrap();
        assert_eq!(one.len(), 1);

        let via_fee = select_transfer_and_fee_coins(
            &dust,
            *DARK_TOKEN_ID,
            (MAX_TRANSFER_INPUTS as u64 + 1) * 1_000_000,
            0,
        )
        .unwrap_err();
        assert!(via_fee.to_string().contains("Consolidate"));
    }
}
