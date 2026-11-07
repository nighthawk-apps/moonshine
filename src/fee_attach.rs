//! Attach a Money::FeeV1 call to an existing [`TransactionBuilder`].

use darkfi::zk::halo2::Field;
use crate::tx_builder::{assert_witness_at_tip, compute_remainder_blind};
use darkfi::{
    tx::{ContractCallLeaf, Transaction, TransactionBuilder},
    zk::{proof::ProvingKey, vm::ZkCircuit, vm_heap::empty_witnesses},
    zkas::ZkBinary,
};
use darkfi_money_contract::{
    client::{
        fee_v1::{create_fee_proof, FeeCallInput, FeeCallOutput},
        MoneyNote, OwnCoin,
    },
    model::MoneyFeeParamsV1,
    MoneyFunction, MONEY_CONTRACT_ZKAS_FEE_NS_V1,
};
use darkfi_sdk::{
    crypto::{
        contract_id::MONEY_CONTRACT_ID, note::AeadEncryptedNote, Blind, FuncId, MerkleNode,
        MerkleTree, PublicKey, SecretKey,
    },
    crypto::pasta_prelude::PrimeField,
    pasta::pallas,
    tx::ContractCall,
};
use darkfi_serial::AsyncEncodable;
use std::error::Error;

/// Append a fee call and sign. Returns the tx plus spent fee nullifier/commitment.
pub async fn finish_with_native_fee(
    mut tx_builder: TransactionBuilder,
    fee: u64,
    fee_coin: OwnCoin,
    tree: &MerkleTree,
    zkas_bins: &[(String, Vec<u8>)],
) -> Result<(Transaction, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    if fee == 0 {
        return Ok((tx_builder.build_signed()?, Vec::new(), Vec::new()));
    }
    if fee_coin.note.value < fee {
        return Err("fee coin too small".into());
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

    let expected_root = assert_witness_at_tip(
        tree,
        MerkleNode::from(fee_coin.coin.inner()),
        fee_coin.leaf_position,
    )?;
    let merkle_path = tree
        .witness(fee_coin.leaf_position, 0)
        .map_err(|_| "fee coin Merkle witness missing")?;

    let change_value = fee_coin.note.value - fee;
    let input = FeeCallInput {
        coin: fee_coin.clone(),
        merkle_path,
        user_data_blind: Blind::random(&mut rand_core::OsRng),
    };
    let output = FeeCallOutput {
        public_key: PublicKey::from_secret(fee_coin.secret),
        value: change_value,
        token_id: fee_coin.note.token_id,
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
    if expected_root != public_inputs.merkle_root {
        return Err(format!(
            "fee proof Merkle root mismatch: {} vs {}",
            hex::encode(public_inputs.merkle_root.to_bytes()),
            hex::encode(expected_root.to_bytes())
        )
        .into());
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
            tx_local: false,
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

    let spent_nf = fee_coin.nullifier().inner().to_repr().to_vec();
    let spent_cm = fee_coin.coin.inner().to_repr().to_vec();
    Ok((tx_builder.build_signed()?, spent_cm, spent_nf))
}
