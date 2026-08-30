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
    model::{MoneyFeeParamsV1, TokenId},
    MoneyFunction, MONEY_CONTRACT_ZKAS_BURN_NS_V1, MONEY_CONTRACT_ZKAS_FEE_NS_V1,
    MONEY_CONTRACT_ZKAS_MINT_NS_V1,
};
use darkfi_sdk::crypto::pasta_prelude::Field;
use darkfi_sdk::{
    crypto::{
        contract_id::MONEY_CONTRACT_ID, note::AeadEncryptedNote, FuncId, Keypair, MerkleTree,
        PublicKey,
    },
    crypto::{Blind, SecretKey},
    pasta::pallas,
    tx::ContractCall,
};
use darkfi_serial::AsyncEncodable;
use std::error::Error;

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
) -> Result<Transaction, Box<dyn Error>> {
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

    // L5: Pre-collect fee candidate coins before make_transfer_call consumes
    // all_coins, avoiding a full Vec<OwnCoin> clone.
    let fee_candidates: Vec<OwnCoin> = all_coins
        .iter()
        .filter(|c| c.note.value >= fee && c.note.token_id == token_id)
        .cloned()
        .collect();

    let (params, secrets, spent_coins) = make_transfer_call(
        keypair,
        recipient_pubkey,
        amount,
        token_id,
        all_coins, // consumed, no clone needed
        tree.clone(),
        None, // spend_hook
        None, // user_data
        mint_zkbin,
        mint_pk,
        burn_zkbin,
        burn_pk,
        false, // half_split
    )?;
    let _ = payment_memo; // retained in local tx history by caller when present

    let mut data = vec![MoneyFunction::TransferV1 as u8];
    params.encode_async(&mut data).await?;
    let call = ContractCall {
        contract_id: *MONEY_CONTRACT_ID,
        data,
    };

    let mut tx_builder = TransactionBuilder::new(
        ContractCallLeaf {
            call,
            proofs: secrets.proofs,
        },
        vec![],
    )?;

    // Fee call — only when fee > 0 (skip_fees mode on darkfid doesn't
    // require or support Fee calls).
    if fee > 0 {
        let available_fee_coins: Vec<&OwnCoin> = fee_candidates
            .iter()
            .filter(|c| !spent_coins.iter().any(|sc| sc.coin == c.coin))
            .collect();

        let fee_coin = available_fee_coins
            .first()
            .ok_or("Not enough native tokens to pay for fee")?;
        let change_value = fee_coin.note.value - fee;

        let input = FeeCallInput {
            coin: (*fee_coin).clone(),
            merkle_path: tree
                .witness(fee_coin.leaf_position, 0)
                .map_err(|_| "Merkle path missing")?,
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
        // Wire format matches `drk` / money contract: [FeeV1][u64 paid_fee][MoneyFeeParamsV1].
        fee.encode_async(&mut data).await?;
        fee_params.encode_async(&mut data).await?;
        let fee_call = ContractCall {
            contract_id: *MONEY_CONTRACT_ID,
            data,
        };

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
        Ok(tx)
    } else {
        // No fee call — build transaction with just the transfer call.
        let mut tx = tx_builder.build()?;
        let sigs = tx.create_sigs(&secrets.signature_secrets)?;
        tx.signatures.push(sigs);
        Ok(tx)
    }
}
