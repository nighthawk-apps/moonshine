//! Attach a Money::FeeV1 call to an existing [`TransactionBuilder`].
//!
//! Mirrors `drk::append_fee_call`: prefer a decryptable tx-local TransferV1
//! change (native token, value ≥ fee), else fall back to a wallet coin.

use crate::tx_builder::{assert_witness_at_tip, compute_remainder_blind};
use darkfi::zk::halo2::Field;
use darkfi::{
    tx::{ContractCallIter, ContractCallLeaf, Transaction, TransactionBuilder},
    zk::{proof::ProvingKey, vm::ZkCircuit, vm_heap::empty_witnesses},
    zkas::ZkBinary,
};
use darkfi_money_contract::{
    client::{
        fee_v1::{create_fee_proof, FeeCallInput, FeeCallOutput},
        money_call_nullifiers, MoneyNote, OwnCoin,
    },
    model::{MoneyFeeParamsV1, MoneyTransferParamsV1, Nullifier, DARK_TOKEN_ID},
    MoneyFunction, MONEY_CONTRACT_ZKAS_FEE_NS_V1,
};
use darkfi_sdk::{
    crypto::{
        contract_id::MONEY_CONTRACT_ID, note::AeadEncryptedNote, poseidon_hash, Blind, FuncId,
        MerkleNode, MerkleTree, PublicKey, SecretKey,
    },
    crypto::pasta_prelude::PrimeField,
    pasta::pallas,
    tx::ContractCall,
};
use darkfi_serial::{deserialize, AsyncEncodable, Encodable};
use std::error::Error;

/// Append a fee call and sign. Returns the tx plus spent fee nullifier/commitment.
///
/// When a prior TransferV1 call in `tx_builder` has native change covering `fee`,
/// that output is marked `tx_local` and spent from the local Merkle tree (same as
/// upstream `0f985c7cf`). Otherwise `fee_coin` + `tree` are required.
pub async fn finish_with_native_fee(
    mut tx_builder: TransactionBuilder,
    fee: u64,
    fee_coin: Option<OwnCoin>,
    tree: Option<&MerkleTree>,
    zkas_bins: &[(String, Vec<u8>)],
    wallet_secrets: &[SecretKey],
) -> Result<(Transaction, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    if fee == 0 {
        return Ok((tx_builder.build_signed()?, Vec::new(), Vec::new()));
    }

    let fee_zkbin_bytes = &zkas_bins
        .iter()
        .find(|x| x.0 == MONEY_CONTRACT_ZKAS_FEE_NS_V1)
        .ok_or("Fee circuit missing from lightwalletd")?
        .1;
    let fee_zkbin = ZkBinary::decode(fee_zkbin_bytes, false)?;
    let fee_pk = ProvingKey::build(
        fee_zkbin.k,
        &ZkCircuit::new(empty_witnesses(&fee_zkbin)?, &fee_zkbin),
    );

    let spent_nullifiers = collect_spent_nullifiers(&mut tx_builder).await?;

    let (coin, fee_tree, is_tx_local) =
        if let Some((coin, local_tree)) =
            mark_tx_local_output_for_fee(&mut tx_builder, wallet_secrets, &spent_nullifiers, fee)?
        {
            (coin, local_tree, true)
        } else {
            let coin = fee_coin.ok_or(
                "Not enough native tokens to pay for fee (need leftover DRK or change ≥ fee)",
            )?;
            let tree = tree.ok_or("Money Merkle tree missing for fee coin")?;
            if coin.note.value < fee {
                return Err("fee coin too small".into());
            }
            if spent_nullifiers.contains(&coin.nullifier()) {
                return Err("fee coin already spent in this transaction".into());
            }
            (coin, tree.clone(), false)
        };

    let expected_root = if is_tx_local {
        fee_tree.root(0)
    } else {
        Some(assert_witness_at_tip(
            &fee_tree,
            MerkleNode::from(coin.coin.inner()),
            coin.leaf_position,
        )?)
    };
    let merkle_path = fee_tree
        .witness(coin.leaf_position, 0)
        .map_err(|_| "fee coin Merkle witness missing")?;

    let change_value = coin.note.value - fee;
    let input = FeeCallInput {
        coin: coin.clone(),
        merkle_path,
        user_data_blind: Blind::random(&mut rand_core::OsRng),
    };
    let output = FeeCallOutput {
        public_key: PublicKey::from_secret(coin.secret),
        value: change_value,
        token_id: coin.note.token_id,
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
    if let Some(expected) = expected_root {
        if expected != public_inputs.merkle_root {
            return Err(format!(
                "fee proof Merkle root mismatch: {} vs {}",
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
            .map_err(|_| "Failed to encrypt fee change note")?;

    let fee_params = MoneyFeeParamsV1 {
        input: darkfi_money_contract::model::Input {
            value_commit: public_inputs.input_value_commit,
            token_commit: public_inputs.token_commit,
            nullifier: public_inputs.nullifier,
            merkle_root: public_inputs.merkle_root,
            user_data_enc: public_inputs.input_user_data_enc,
            signature_public: public_inputs.signature_public,
            tx_local: is_tx_local,
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
    fee.encode_async(&mut data).await?;
    fee_params.encode_async(&mut data).await?;
    let fee_call = ContractCall {
        contract_id: *MONEY_CONTRACT_ID,
        data,
    };
    tx_builder.append(
        ContractCallLeaf::new(fee_call, vec![fee_proof], vec![signature_secret]),
        vec![],
    )?;

    let (spent_cm, spent_nf) = if is_tx_local {
        (Vec::new(), Vec::new())
    } else {
        (
            coin.coin.inner().to_repr().to_vec(),
            coin.nullifier().inner().to_repr().to_vec(),
        )
    };
    Ok((tx_builder.build_signed()?, spent_cm, spent_nf))
}

async fn collect_spent_nullifiers(
    tx_builder: &mut TransactionBuilder,
) -> Result<Vec<Nullifier>, Box<dyn Error>> {
    let tx = tx_builder.build()?;
    let mut spent = Vec::new();
    for call in &tx.calls {
        if call.data.is_money_fee() {
            return Err("Fee call already exists".into());
        }
        if call.data.contract_id == *MONEY_CONTRACT_ID {
            if let Ok(nullifiers) = money_call_nullifiers(&call.data).await {
                spent.extend(nullifiers);
            }
        }
    }
    Ok(spent)
}

/// Find and mark a native-token TransferV1 change output as tx-local for the fee.
fn mark_tx_local_output_for_fee(
    tx_builder: &mut TransactionBuilder,
    wallet_secrets: &[SecretKey],
    spent_nullifiers: &[Nullifier],
    required_fee: u64,
) -> Result<Option<(OwnCoin, MerkleTree)>, Box<dyn Error>> {
    let mut tree = MerkleTree::new(1);
    tree.append(MerkleNode::from(pallas::Base::ZERO));

    for call in tx_builder.call_iter_mut() {
        if !call.is_money_transfer() {
            continue;
        }

        let Ok(mut params) = deserialize::<MoneyTransferParamsV1>(&call.data[1..]) else {
            continue;
        };

        let found = params.outputs.iter().enumerate().find_map(|(idx, output)| {
            for secret in wallet_secrets {
                let Ok(note) = output.note.decrypt::<MoneyNote>(secret) else {
                    continue;
                };
                let nullifier =
                    Nullifier::from(poseidon_hash([secret.inner(), output.coin.inner()]));
                let suitable = note.token_id == *DARK_TOKEN_ID
                    && note.value >= required_fee
                    && !spent_nullifiers.contains(&nullifier);
                if suitable {
                    return Some((idx, *secret, note, output.coin));
                }
            }
            None
        });

        if let Some((idx, ..)) = &found {
            params.outputs[*idx].tx_local = true;
        }
        let fee_idx = found.as_ref().map(|(idx, ..)| *idx);

        let mut position = None;
        for (i, output) in params.outputs.iter().enumerate() {
            if !output.tx_local {
                continue;
            }
            tree.append(MerkleNode::from(output.coin.inner()));
            if Some(i) == fee_idx {
                position = Some(tree.mark().ok_or("tx-local merkle mark failed")?);
            }
        }

        let Some((_, secret, note, coin)) = found else {
            continue;
        };
        let position = position.ok_or("tx-local fee leaf position missing")?;

        let mut data = vec![MoneyFunction::TransferV1 as u8];
        params
            .encode(&mut data)
            .map_err(|e| format!("encode transfer params: {e}"))?;
        call.data = data;

        return Ok(Some((
            OwnCoin {
                coin,
                note,
                secret,
                leaf_position: position,
            },
            tree,
        )));
    }

    Ok(None)
}
