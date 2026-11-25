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
             Rebuild with: moonshine sync --rebuild-merkle --force-trial",
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
    /// Compact-block output indexes of change that decrypts to this wallet.
    /// Index 0 is the payment output and is covered by the recipient clue.
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
            c.note.value >= fee
                && c.note.spend_hook == FuncId::none()
                && c.note.token_id == *darkfi_money_contract::model::DARK_TOKEN_ID
        })
        .cloned()
        .collect()
}

/// Select a tx-local change output for `FeeV1` without cannibalizing payment outputs.
///
/// Iterates from the tail (where `make_transfer_call` appends change) and skips:
/// - payment outputs (`idx < min_change_index`)
/// - non-DRK coins or coins smaller than `fee`
/// - contract-hooked notes (`spend_hook != FuncId::none()`)
/// - outputs carrying a non-empty payment memo
pub(crate) fn select_tx_local_fee_output(
    outputs: &[darkfi_money_contract::model::Output],
    secret: &SecretKey,
    fee: u64,
    min_change_index: usize,
) -> Option<(usize, MoneyNote)> {
    for (idx, output) in outputs.iter().enumerate().rev() {
        if idx < min_change_index {
            continue;
        }
        let Ok(note) = output.note.decrypt::<MoneyNote>(secret) else {
            continue;
        };
        if note.value < fee
            || note.token_id != *darkfi_money_contract::model::DARK_TOKEN_ID
            || note.spend_hook != FuncId::none()
            || !note.memo.is_empty()
        {
            continue;
        }
        return Some((idx, note));
    }
    None
}

fn own_coin_commitment(coin: &OwnCoin) -> Vec<u8> {
    coin.coin.inner().to_repr().to_vec()
}

fn own_coin_nullifier(coin: &OwnCoin) -> Vec<u8> {
    coin.nullifier().inner().to_repr().to_vec()
}

#[allow(dead_code)]
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
    build_transaction_extended(
        amount,
        fee,
        token_id,
        recipient_pubkey,
        wallet_secret,
        all_coins,
        tree,
        zkas_bins,
        payment_memo,
        half_split,
        None,
        None,
    )
    .await
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

    // Transfer call. The pinned DarkFi builder takes the recipient memo.

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

    let fee_candidates = filter_fee_candidates(&spendable, fee);

    let transfer_spendable: Vec<OwnCoin> = spendable
        .iter()
        .filter(|c| c.note.spend_hook == FuncId::none() && c.note.token_id == token_id)
        .cloned()
        .collect();

    let (mut params, secrets, spent_coins) = make_transfer_call(
        keypair,
        recipient_pubkey,
        amount,
        token_id,
        transfer_spendable,
        tree.clone(),
        spend_hook,
        user_data,
        mint_zkbin,
        mint_pk,
        burn_zkbin,
        burn_pk,
        half_split,
        payment_memo.unwrap_or_default(),
    )?;

    let mut spent_commitments: Vec<Vec<u8>> = spent_coins.iter().map(own_coin_commitment).collect();
    let mut spent_nullifiers: Vec<Vec<u8>> = spent_coins.iter().map(own_coin_nullifier).collect();

    struct FeeSrc {
        coin: OwnCoin,
        merkle_path: Vec<MerkleNode>,
        input_tx_local: bool,
        expected_root: Option<MerkleNode>,
    }

    let fee_src = if fee > 0 {
        let leftover = fee_candidates
            .iter()
            .find(|c| !spent_coins.iter().any(|sc| sc.coin == c.coin) && c.note.value >= fee);
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
            // Payment outputs occupy 0..(1 or 2 with half_split); never cannibalize them.
            let min_change_index = if half_split { 2 } else { 1 };
            let mut local_tree = MerkleTree::new(1);
            local_tree.append(MerkleNode::from(pallas::Base::ZERO));
            let mut src = None;
            if let Some((idx, note)) =
                select_tx_local_fee_output(&params.outputs, &keypair.secret, fee, min_change_index)
            {
                let output = &mut params.outputs[idx];
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
                let leaf_position = local_tree.mark().ok_or("tx-local merkle mark failed")?;
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
    use darkfi_sdk::pasta::group::Group;

    fn make_own_coin(value: u64, token_id: TokenId, spend_hook: FuncId) -> OwnCoin {
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
            leaf_position: 1u64.into(),
        }
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

        let kept = filter_fee_candidates(&[hooked, zero_tok, valid.clone(), too_small], 5_000_000);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].coin, valid.coin);
    }

    #[test]
    fn tx_local_fee_skips_payment_output_and_memo_and_hook() {
        let kp = Keypair::random(&mut rand_core::OsRng);
        let dao_hook = crate::dao_ops::dao_spend_hook();
        // Self-transfer: output 0 is payment (with memo), output 1 is hooked, output 2 is plain change.
        let payment = make_encrypted_output(&kp, 50_000_000, FuncId::none(), b"pay-self".to_vec());
        let hooked = make_encrypted_output(&kp, 50_000_000, dao_hook, vec![]);
        let change = make_encrypted_output(&kp, 20_000_000, FuncId::none(), vec![]);

        let chosen = select_tx_local_fee_output(
            &[payment.clone(), hooked, change],
            &kp.secret,
            5_000_000,
            1,
        )
        .expect("should pick change output");
        assert_eq!(chosen.0, 2);
        assert_eq!(chosen.1.value, 20_000_000);

        // Even without a memo, output 0 (payment) must not be cannibalized when min_change_index == 1.
        let unmemoized_payment = make_encrypted_output(&kp, 50_000_000, FuncId::none(), vec![]);
        assert!(
            select_tx_local_fee_output(&[unmemoized_payment], &kp.secret, 5_000_000, 1).is_none()
        );
        // If output 1 has a memo, skip it too.
        assert!(
            select_tx_local_fee_output(&[payment.clone(), payment], &kp.secret, 5_000_000, 1)
                .is_none()
        );
    }
}
