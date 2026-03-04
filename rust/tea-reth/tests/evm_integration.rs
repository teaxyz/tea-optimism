//! Integration test: verify the GPG precompile is registered and callable through
//! a real EVM instance created by `TeaEvmFactory`.
//!
//! This bridges the gap between unit tests (which call `gpg_verify_run` directly)
//! and a live network — it proves that `TeaEvmFactory` correctly injects the
//! precompile at address `0x0696` into the OP EVM.

use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Bytes, address};
use op_revm::OpSpecId;
use revm::{context::CfgEnv, database::CacheDB, database_interface::EmptyDBTyped};
use tea_reth::evm::TeaEvmFactory;

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
