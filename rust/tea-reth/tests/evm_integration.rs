//! Integration test: verify the GPG and SSH precompiles are registered and callable
//! through a real EVM instance created by `TeaEvmFactory`.
//!
//! This bridges the gap between unit tests (which call precompile functions directly)
//! and a live network — it proves that `TeaEvmFactory` correctly injects both
//! precompiles into the OP EVM.

use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_primitives::{Bytes, U256, address};
use op_revm::OpSpecId;
use revm::{context::CfgEnv, database::CacheDB, database_interface::EmptyDBTyped};

/// The GPG verify precompile address.
const GPG_VERIFY_ADDR: alloy_primitives::Address =
    address!("0x0000000000000000000000000000000000000696");

/// The SSH verify precompile address.
const SSH_VERIFY_ADDR: alloy_primitives::Address =
    address!("0x0000000000000000000000000000000000000697");

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

// ========== GPG precompile tests (unchanged from original) ==========

/// Verify the precompile is registered at 0x0696 by sending our ed25519 test
/// vector through a real EVM `transact_system_call` and checking for success.
#[test]
fn test_gpg_precompile_registered_in_evm() {
    let factory = tea_reth::evm::TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    let input_hex = include_str!("../src/precompiles/testdata_gpg_verify_ed25519.hex");
    let input = hex::decode(input_hex.trim()).expect("valid hex");

    let result = evm.transact_system_call(CALLER, GPG_VERIFY_ADDR, Bytes::from(input));
    let result = result.expect("EVM transact should succeed");

    let output = result.result.output().expect("should have output");
    assert_eq!(output.len(), 32, "output should be 32 bytes");
    assert_eq!(output[31], 1, "last byte should be 1 (valid signature)");
}

/// Verify that calling a non-precompile address doesn't accidentally hit
/// the GPG precompile — sanity check that registration is address-specific.
#[test]
fn test_wrong_address_is_not_precompile() {
    let factory = tea_reth::evm::TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    // Call an address that is NOT a precompile (between GPG and SSH)
    let wrong_addr = address!("0x0000000000000000000000000000000000000698");
    let result = evm.transact_system_call(CALLER, wrong_addr, Bytes::new());
    let result = result.expect("EVM transact should succeed (empty call)");

    let output = result.result.output().cloned().unwrap_or_default();
    assert!(output.is_empty(), "non-precompile address should return empty output");
}

/// Verify that the standard OP precompiles are still present alongside Tea's
/// custom precompiles (e.g., ecrecover at 0x01).
#[test]
fn test_standard_precompiles_still_present() {
    let factory = tea_reth::evm::TeaEvmFactory;

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

    let ecrecover_addr = address!("0x0000000000000000000000000000000000000001");
    let result = evm.transact_system_call(CALLER, ecrecover_addr, Bytes::new());
    assert!(result.is_ok(), "ecrecover precompile should be callable");
}

/// Verify that a wrong message hash returns bytes32(0) through the EVM.
#[test]
fn test_gpg_wrong_message_returns_zero_through_evm() {
    let factory = tea_reth::evm::TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    let input_hex = include_str!("../src/precompiles/testdata_gpg_verify_ed25519.hex");
    let mut input = hex::decode(input_hex.trim()).expect("valid hex");
    input[0] ^= 0xFF;

    let result = evm.transact_system_call(CALLER, GPG_VERIFY_ADDR, Bytes::from(input));
    let result = result.expect("EVM transact should succeed even for wrong message");

    let output = result.result.output().expect("should have output");
    assert_eq!(output.len(), 32, "output should be 32 bytes");
    assert!(
        output.iter().all(|&b| b == 0),
        "output should be all zeros (signature doesn't match message)"
    );
}

// ========== SSH precompile tests ==========

/// Verify the SSH precompile is registered at 0x0697 with an ed25519 test vector.
#[test]
fn test_ssh_precompile_registered_in_evm() {
    let factory = tea_reth::evm::TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    let input_hex = include_str!("../src/precompiles/testdata_ssh_verify_ed25519.hex");
    let input = hex::decode(input_hex.trim()).expect("valid hex");

    let result = evm.transact_system_call(CALLER, SSH_VERIFY_ADDR, Bytes::from(input));
    let result = result.expect("EVM transact should succeed");

    let output = result.result.output().expect("should have output");
    assert_eq!(output.len(), 32, "output should be 32 bytes");
    assert_eq!(output[31], 1, "last byte should be 1 (valid signature)");
}

/// Verify SSH RSA verification works through the EVM.
#[test]
fn test_ssh_rsa_precompile_through_evm() {
    let factory = tea_reth::evm::TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    let input_hex = include_str!("../src/precompiles/testdata_ssh_verify_rsa.hex");
    let input = hex::decode(input_hex.trim()).expect("valid hex");

    let result = evm.transact_system_call(CALLER, SSH_VERIFY_ADDR, Bytes::from(input));
    let result = result.expect("EVM transact should succeed");

    let output = result.result.output().expect("should have output");
    assert_eq!(output.len(), 32, "output should be 32 bytes");
    assert_eq!(output[31], 1, "last byte should be 1 (valid RSA signature)");
}

/// Verify SSH wrong message returns bytes32(0) through the EVM.
#[test]
fn test_ssh_wrong_message_returns_zero_through_evm() {
    let factory = tea_reth::evm::TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    let input_hex = include_str!("../src/precompiles/testdata_ssh_verify_ed25519.hex");
    let mut input = hex::decode(input_hex.trim()).expect("valid hex");
    input[0] ^= 0xFF;

    let result = evm.transact_system_call(CALLER, SSH_VERIFY_ADDR, Bytes::from(input));
    let result = result.expect("EVM transact should succeed even for wrong message");

    let output = result.result.output().expect("should have output");
    assert_eq!(output.len(), 32);
    assert!(
        output.iter().all(|&b| b == 0),
        "output should be all zeros (signature doesn't match message)"
    );
}

/// Verify both precompiles coexist — calling each produces correct results.
#[test]
fn test_both_precompiles_coexist() {
    let factory = tea_reth::evm::TeaEvmFactory;
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let mut evm = factory.create_evm(db, make_evm_env());

    // Call GPG precompile
    let gpg_input_hex = include_str!("../src/precompiles/testdata_gpg_verify_ed25519.hex");
    let gpg_input = hex::decode(gpg_input_hex.trim()).expect("valid hex");
    let gpg_result = evm.transact_system_call(CALLER, GPG_VERIFY_ADDR, Bytes::from(gpg_input));
    let gpg_result = gpg_result.expect("GPG transact should succeed");
    assert_eq!(
        gpg_result.result.output().expect("gpg output")[31],
        1,
        "GPG precompile should return valid"
    );

    // Call SSH precompile on the same EVM instance
    let ssh_input_hex = include_str!("../src/precompiles/testdata_ssh_verify_ed25519.hex");
    let ssh_input = hex::decode(ssh_input_hex.trim()).expect("valid hex");
    let ssh_result = evm.transact_system_call(CALLER, SSH_VERIFY_ADDR, Bytes::from(ssh_input));
    let ssh_result = ssh_result.expect("SSH transact should succeed");
    assert_eq!(
        ssh_result.result.output().expect("ssh output")[31],
        1,
        "SSH precompile should return valid"
    );
}

// ========== Factory / L1 cost tests (unchanged from original) ==========

#[test]
fn test_tea_l1_cost_multiplier_reads_oracle() {
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let price = U256::from(999u64) * tea_reth::l1_cost::WAD;
    db.insert_account_storage(
        tea_reth::l1_cost::GAS_PRICE_ORACLE_ADDR,
        tea_reth::l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
        price,
    )
    .expect("insert storage");

    let factory = tea_reth::evm::TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert!(multiplier.is_some());
    let (numerator, denominator) = multiplier.unwrap();
    assert_eq!(numerator, price);
    assert_eq!(denominator, tea_reth::l1_cost::WAD);
}

#[test]
fn test_tea_l1_cost_multiplier_zero_oracle_uses_backup() {
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    db.insert_account_storage(
        tea_reth::l1_cost::GAS_PRICE_ORACLE_ADDR,
        tea_reth::l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
        U256::ZERO,
    )
    .expect("insert storage");

    let factory = tea_reth::evm::TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert!(multiplier.is_some());
    let (numerator, denominator) = multiplier.unwrap();
    let expected_backup = U256::from(tea_reth::l1_cost::BACKUP_TEA_PER_ETH) * tea_reth::l1_cost::WAD;
    assert_eq!(numerator, expected_backup);
    assert_eq!(denominator, tea_reth::l1_cost::WAD);
}

#[test]
fn test_tea_l1_cost_multiplier_empty_db() {
    let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let factory = tea_reth::evm::TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert!(multiplier.is_some());
    let (numerator, denominator) = multiplier.unwrap();
    let expected_backup = U256::from(tea_reth::l1_cost::BACKUP_TEA_PER_ETH) * tea_reth::l1_cost::WAD;
    assert_eq!(numerator, expected_backup);
    assert_eq!(denominator, tea_reth::l1_cost::WAD);
}

#[test]
fn test_evm_factory_sets_multiplier_on_context() {
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let custom_rate = U256::from(12345u64) * tea_reth::l1_cost::WAD;
    db.insert_account_storage(
        tea_reth::l1_cost::GAS_PRICE_ORACLE_ADDR,
        tea_reth::l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
        custom_rate,
    )
    .expect("insert storage");

    let factory = tea_reth::evm::TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert_eq!(
        multiplier,
        Some((custom_rate, tea_reth::l1_cost::WAD)),
    );
}

#[test]
fn test_evm_factory_packed_slot_with_timestamp() {
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    let packed = U256::from_be_bytes(alloy_primitives::hex!(
        "00000000000000006793192400000000000000000000003627e8f712373c0000"
    ));
    db.insert_account_storage(
        tea_reth::l1_cost::GAS_PRICE_ORACLE_ADDR,
        tea_reth::l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
        packed,
    )
    .expect("insert storage");

    let factory = tea_reth::evm::TeaEvmFactory;
    let evm = factory.create_evm(db, make_evm_env());

    let multiplier = evm.ctx().chain.l1_cost_multiplier;
    assert!(multiplier.is_some());
    let (numerator, _denominator) = multiplier.unwrap();
    let expected_price = U256::from(999u64) * tea_reth::l1_cost::WAD;
    assert_eq!(numerator, expected_price);
}
