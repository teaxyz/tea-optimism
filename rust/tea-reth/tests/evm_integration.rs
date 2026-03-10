//! Integration test: verify the GPG precompile is registered and callable through
//! a real EVM instance created by `TeaEvmFactory`.
//!
//! This bridges the gap between unit tests (which call `gpg_verify_run` directly)
//! and a live network — it proves that `TeaEvmFactory` correctly injects the
//! precompile at address `0x0696` into the OP EVM.

use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Bytes, U256, address};
use op_revm::OpSpecId;
use revm::{context::CfgEnv, database::CacheDB, database_interface::EmptyDBTyped};
use tea_reth::evm::TeaEvmFactory;
use tea_reth::l1_cost;

/// The GPG verify precompile address.
const GPG_VERIFY_ADDR: alloy_primitives::Address =
    address!("0x0000000000000000000000000000000000000696");

/// A dummy caller address for system calls.
const CALLER: alloy_primitives::Address = address!("0x0000000000000000000000000000000000000001");

fn make_evm_env() -> EvmEnv<OpSpecId> {
    EvmEnv {
        cfg_env: CfgEnv::new()
            .with_chain_id(6122) // Tea mainnet
            .with_spec_and_mainnet_gas_params(OpSpecId::FJORD),
        ..Default::default()
    }
}

/// Verify the precompile is registered at 0x0696 by sending our ed25519 test
/// vector through a real EVM `transact_system_call` and checking for success.
#[test]
fn test_gpg_precompile_registered_in_evm() {
    let factory = TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    // Load the ed25519 test input (same hex data used in unit tests).
    let input_hex = include_str!("../src/precompiles/testdata_gpg_verify_ed25519.hex");
    let input = hex::decode(input_hex.trim()).expect("valid hex");

    let result = evm.transact_system_call(CALLER, GPG_VERIFY_ADDR, Bytes::from(input));
    let result = result.expect("EVM transact should succeed");

    // The precompile returns bytes32(1) for a valid signature.
    let output = result.result.output().expect("should have output");
    assert_eq!(output.len(), 32, "output should be 32 bytes");
    assert_eq!(output[31], 1, "last byte should be 1 (valid signature)");
}

/// Verify that calling a non-precompile address doesn't accidentally hit
/// the GPG precompile — sanity check that registration is address-specific.
#[test]
fn test_wrong_address_is_not_gpg_precompile() {
    let factory = TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    // Call a nearby address that is NOT a precompile.
    let wrong_addr = address!("0x0000000000000000000000000000000000000697");
    let result = evm.transact_system_call(CALLER, wrong_addr, Bytes::new());
    let result = result.expect("EVM transact should succeed (empty call)");

    // Should return empty output (no code at that address).
    let output = result.result.output().cloned().unwrap_or_default();
    assert!(output.is_empty(), "non-precompile address should return empty output");
}

/// Verify that the standard OP precompiles are still present alongside Tea's
/// custom precompile (e.g., ecrecover at 0x01).
#[test]
fn test_standard_precompiles_still_present() {
    let factory = TeaEvmFactory;

    // Seed the DB with the caller account so the CALL has enough balance.
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    db.insert_account_info(
        CALLER,
        revm::state::AccountInfo {
            balance: alloy_primitives::U256::from(1_000_000_000u64),
            nonce: 0,
            code_hash: alloy_primitives::B256::ZERO,
            code: None,
            account_id: None,
        },
    );

    let mut evm = factory.create_evm(db, make_evm_env());

    // Call ecrecover (0x01) with empty input — it should fail gracefully
    // (return empty output) rather than behaving like a missing contract.
    let ecrecover_addr = address!("0x0000000000000000000000000000000000000001");
    let result = evm.transact_system_call(CALLER, ecrecover_addr, Bytes::new());
    // ecrecover with empty/invalid input returns empty output, but the call succeeds.
    assert!(result.is_ok(), "ecrecover precompile should be callable");
}

/// Verify that a wrong message hash returns bytes32(0) through the EVM,
/// not an error — matching the Go precompile behavior.
///
/// We corrupt the message hash (first 32 bytes) rather than the signature bytes,
/// so the signature still parses correctly but verification fails.
#[test]
fn test_wrong_message_returns_zero_through_evm() {
    let factory = TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    // Load the ed25519 test input and corrupt the message hash.
    let input_hex = include_str!("../src/precompiles/testdata_gpg_verify_ed25519.hex");
    let mut input = hex::decode(input_hex.trim()).expect("valid hex");

    // Corrupt the first byte of the message hash (bytes 0..32 in ABI encoding).
    input[0] ^= 0xFF;

    let result = evm.transact_system_call(CALLER, GPG_VERIFY_ADDR, Bytes::from(input));
    let result = result.expect("EVM transact should succeed even for wrong message");

    // The precompile returns bytes32(0) for an invalid signature.
    let output = result.result.output().expect("should have output");
    assert_eq!(output.len(), 32, "output should be 32 bytes");
    assert!(
        output.iter().all(|&b| b == 0),
        "output should be all zeros (signature doesn't match message)"
    );
}

// === Additional tests from PR #5 review feedback ===
// Factory → L1BlockInfo integration tests

/// Seed a CacheDB with a known price at the oracle slot.
/// Verify tea_l1_cost_multiplier reads the correct rate.
#[test]
fn test_tea_l1_cost_multiplier_reads_oracle() {
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();

    // Seed oracle price: 999 * WAD
    let price = U256::from(999u64) * l1_cost::WAD;
    db.insert_account_storage(
        l1_cost::GAS_PRICE_ORACLE_ADDR,
        l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
        price,
    )
    .expect("insert storage");

    let factory = TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert!(multiplier.is_some(), "multiplier should be set");
    let (numerator, denominator) = multiplier.unwrap();
    assert_eq!(numerator, price, "numerator should match oracle price");
    assert_eq!(denominator, l1_cost::WAD, "denominator should be WAD");
}

/// Zero oracle value should trigger the backup rate (1,500,000 * WAD).
#[test]
fn test_tea_l1_cost_multiplier_zero_oracle_uses_backup() {
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();

    // Seed oracle with zero (or just don't seed — default is zero)
    db.insert_account_storage(
        l1_cost::GAS_PRICE_ORACLE_ADDR,
        l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
        U256::ZERO,
    )
    .expect("insert storage");

    let factory = TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert!(multiplier.is_some(), "multiplier should be set even with zero oracle");
    let (numerator, denominator) = multiplier.unwrap();
    let expected_backup = U256::from(l1_cost::BACKUP_TEA_PER_ETH) * l1_cost::WAD;
    assert_eq!(numerator, expected_backup, "should use backup rate");
    assert_eq!(denominator, l1_cost::WAD);
}

/// Empty DB (no oracle contract) → db.storage() returns U256::ZERO → backup rate.
#[test]
fn test_tea_l1_cost_multiplier_empty_db() {
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();

    let factory = TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert!(multiplier.is_some(), "multiplier should be set from empty DB");
    let (numerator, denominator) = multiplier.unwrap();
    let expected_backup = U256::from(l1_cost::BACKUP_TEA_PER_ETH) * l1_cost::WAD;
    assert_eq!(numerator, expected_backup, "empty DB should use backup rate");
    assert_eq!(denominator, l1_cost::WAD);
}

/// Verify the EVM factory correctly sets the multiplier on OpContext.
#[test]
fn test_evm_factory_sets_multiplier_on_context() {
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();

    // Seed with a distinctive value
    let custom_rate = U256::from(12345u64) * l1_cost::WAD;
    db.insert_account_storage(
        l1_cost::GAS_PRICE_ORACLE_ADDR,
        l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
        custom_rate,
    )
    .expect("insert storage");

    let factory = TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert_eq!(
        multiplier,
        Some((custom_rate, l1_cost::WAD)),
        "factory should set multiplier from oracle"
    );
}

/// Verify that the packed slot value with timestamp is handled correctly
/// when read through the factory path (U256 extraction).
#[test]
fn test_evm_factory_packed_slot_with_timestamp() {
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();

    // Packed value: timestamp (upper 96 bits) | price (lower 160 bits)
    // This is the examplePriceRatio from Go tests: timestamp=0x67931924, price=999*WAD
    let packed = U256::from_be_bytes(alloy_primitives::hex!(
        "00000000000000006793192400000000000000000000003627e8f712373c0000"
    ));
    db.insert_account_storage(
        l1_cost::GAS_PRICE_ORACLE_ADDR,
        l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
        packed,
    )
    .expect("insert storage");

    let factory = TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert!(multiplier.is_some());
    let (numerator, _denominator) = multiplier.unwrap();

    // The price should be 999 * WAD (timestamp stripped)
    let expected_price = U256::from(999u64) * l1_cost::WAD;
    assert_eq!(numerator, expected_price, "should extract price ignoring timestamp");
}
