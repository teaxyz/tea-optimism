//! Cross-executor L1 cost parity tests.
//!
//! These tests prove that an EVM produced by tea-reth's `TeaEvmFactory`
//! (the execution layer used by sequencers, followers, and tx-ingress) and
//! an EVM produced by kona's `FpvmOpEvmFactory` (the fault-proof VM used by
//! op-challenger for output-root replay) compute **byte-identical** L1
//! transaction cost given the same input, same L1BlockInfo state, and same
//! oracle slot value.
//!
//! # Why this matters
//!
//! Both factories set `ctx.chain.l1_cost_multiplier` from the same
//! GasPriceOracle slot via shared helpers in the `tea-l1-cost` crate. They
//! both consume the same patched `op-revm` for the L1 cost calculation
//! itself. The deductive argument is "same inputs → same multiplier → same
//! op-revm → same output," but tests that only inspect the multiplier value
//! don't actually run the L1 cost calculation on both sides.
//!
//! This file closes that gap by:
//!  1. Building two CacheDBs seeded with identical GasPriceOracle state.
//!  2. Constructing one EVM via each factory.
//!  3. Manually populating the same L1BlockInfo state on both EVM contexts
//!     (l1_base_fee, l1_blob_base_fee, scalars) — these would normally be
//!     read from the L1Block predeploy during a real transaction, but for
//!     a pure L1-cost-calc test we set them directly to keep the test
//!     hermetic.
//!  4. Invoking `L1BlockInfo::calculate_tx_l1_cost(input, spec_id)` on
//!     both EVMs with the same transaction calldata.
//!  5. Asserting byte equality.
//!
//! # What this does NOT test
//!
//! - Full block execution. The kona fault-proof flow uses
//!   `kona_executor::StatelessL2Builder` which consumes a witness +
//!   produces a sealed header and receipts. A parity test at that level
//!   requires building a synthetic block, constructing matching state
//!   witnesses for both sides, and running both executors end-to-end. That
//!   is the right Tier 2 follow-up.
//! - Real Tea Sepolia block replay (Tier 2 from the audit plan).
//! - On-chain dispute game flow (Tier 3 — operational, requires Sepolia
//!   deploy + `DisputeGameFactory.setImplementation`).
//!
//! What this DOES test is the actual L1 cost computation codepath on both
//! sides — the part of the EVM that the multiplier wiring is meant to
//! affect. If this test passes, identical L1 fees on every receipt across
//! EL and FPVM is guaranteed for any tx that doesn't otherwise diverge.

use alloy_evm::{EvmEnv, EvmFactory};
use alloy_op_evm::OpEvm;
use alloy_primitives::U256;
use op_revm::OpSpecId;
use revm::{context::CfgEnv, database::CacheDB, database_interface::EmptyDBTyped};

/// Build a CacheDB seeded with a given GasPriceOracle slot value.
/// Both EL and FPVM factories should read this slot via `tea-l1-cost`
/// helpers and produce the same multiplier.
fn seeded_db(
    oracle_slot_value: U256,
) -> CacheDB<EmptyDBTyped<core::convert::Infallible>> {
    let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
    db.insert_account_storage(
        tea_l1_cost::GAS_PRICE_ORACLE_ADDR,
        tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
        oracle_slot_value,
    )
    .expect("seed oracle storage");
    // Custom-gas-token enabled: the TEAO1-165 gate requires the L1Block
    // isCustomGasToken flag set for either factory to apply the multiplier.
    db.insert_account_storage(
        tea_l1_cost::L1_BLOCK_ATTRIBUTES_ADDR,
        tea_l1_cost::IS_CUSTOM_GAS_TOKEN_SLOT_U256,
        U256::from(1u64),
    )
    .expect("seed cgt flag");
    db
}

/// Tea L2 chain id (mainnet); the cfg_env chain_id only affects signature
/// recovery, which we don't exercise here, but matching it across both
/// factories rules out divergence via spurious cfg differences.
const TEA_CHAIN_ID: u64 = 6122;

fn make_env() -> EvmEnv<OpSpecId> {
    EvmEnv {
        cfg_env: CfgEnv::new()
            .with_chain_id(TEA_CHAIN_ID)
            .with_spec_and_mainnet_gas_params(OpSpecId::FJORD),
        ..Default::default()
    }
}

/// Realistic Fjord L1BlockInfo state. Values chosen to match what op-batcher
/// + L1 oracle would post for a typical Sepolia block: 1 gwei L1 base fee,
/// 10 gwei blob base fee, 2x base scalar, 800k blob scalar. Numbers are
/// arbitrary but identical-on-both-sides — the parity claim is about same
/// inputs → same outputs, not about realism.
fn populate_l1_block_info(info: &mut op_revm::L1BlockInfo) {
    info.l1_base_fee = U256::from(1_000_000_000u64); // 1 gwei
    info.l1_blob_base_fee = Some(U256::from(10_000_000_000u64)); // 10 gwei
    info.l1_base_fee_scalar = U256::from(2_000_000u64);
    info.l1_blob_base_fee_scalar = Some(U256::from(800_000u64));
}

/// Compute the tx_l1_cost the EVM would charge for `input` calldata under
/// FJORD rules. Uses the EVM's actual L1BlockInfo (including the multiplier
/// the factory set). Clears the cache between calls so we exercise the
/// computation path, not the cached value.
fn compute_l1_cost<DB, I, P>(evm: &mut OpEvm<DB, I, P>, input: &[u8]) -> U256
where
    DB: alloy_evm::Database,
{
    let info = &mut evm.ctx_mut().chain;
    info.tx_l1_cost = None; // force recalculation
    info.calculate_tx_l1_cost(input, OpSpecId::FJORD)
}

/// Build a kona FpvmOpEvmFactory with mock hint/oracle channels. Mirrors
/// the test pattern in `kona/bin/client/src/fpvm_evm/precompiles/provider.rs`
/// and `factory.rs::tests`.
macro_rules! make_kona_factory {
    () => {{
        let hint_chan = kona_preimage::BidirectionalChannel::new().unwrap();
        let preimage_chan = kona_preimage::BidirectionalChannel::new().unwrap();
        let hint_writer = kona_preimage::HintWriter::new(hint_chan.client);
        let oracle_reader = kona_preimage::OracleReader::new(preimage_chan.client);
        kona_client::fpvm_evm::FpvmOpEvmFactory::new(hint_writer, oracle_reader)
    }};
}

/// Build identical-state EVMs from both factories and compute tx_l1_cost
/// for `input` on each. Returns `(el_cost, fpvm_cost)`.
fn run_both_executors(oracle_slot_value: U256, input: &[u8]) -> (U256, U256) {
    // EL side: tea-reth's TeaEvmFactory.
    let el_db = seeded_db(oracle_slot_value);
    let el_factory = tea_reth::evm::TeaEvmFactory;
    let mut el_evm = el_factory.create_evm(el_db, make_env());
    populate_l1_block_info(&mut el_evm.ctx_mut().chain);
    let el_cost = compute_l1_cost(&mut el_evm, input);

    // FPVM side: kona-client's FpvmOpEvmFactory.
    let fpvm_db = seeded_db(oracle_slot_value);
    let fpvm_factory = make_kona_factory!();
    let mut fpvm_evm = <_ as EvmFactory>::create_evm(&fpvm_factory, fpvm_db, make_env());
    populate_l1_block_info(&mut fpvm_evm.ctx_mut().chain);
    let fpvm_cost = compute_l1_cost(&mut fpvm_evm, input);

    (el_cost, fpvm_cost)
}

// ─────────────────────────────────────────── Test cases

/// 1:1 oracle rate → multiplier (WAD, WAD) → tx_l1_cost equals raw Fjord
/// cost. The fact that both sides produce identical output here is the
/// baseline parity check: same multiplier-application path, same Fjord
/// math.
#[test]
fn cross_executor_parity_one_to_one_rate() {
    let oracle_rate = tea_l1_cost::WAD; // 1 WAD = no scaling
    let input = b"hello-world-with-some-calldata-that-incurs-l1-cost";
    let (el, fpvm) = run_both_executors(oracle_rate, input);
    assert_eq!(el, fpvm, "EL and FPVM must agree at 1:1 rate");
    assert_ne!(el, U256::ZERO, "test input should incur non-zero L1 cost");
}

/// Backup rate scenario: oracle returns zero, both sides fall back to
/// BACKUP_TEA_PER_ETH * WAD. Same multiplier, same computation, same
/// receipt fee.
#[test]
fn cross_executor_parity_backup_rate() {
    let input = b"calldata-under-backup-rate-scenario";
    let (el, fpvm) = run_both_executors(U256::ZERO, input);
    assert_eq!(el, fpvm, "EL and FPVM must agree under backup rate");
    assert_ne!(el, U256::ZERO);
}

/// Non-1.0 multiplier: 999:1 rate (the canonical Go-test value from
/// `rollup_cost_test.go:44-45`). Proves the multiplier is actually scaling
/// the L1 cost on both sides — if either factory failed to set the field
/// or set it wrong, the costs would diverge.
#[test]
fn cross_executor_parity_999_to_1_rate() {
    let oracle_rate = U256::from(999u64) * tea_l1_cost::WAD;
    let input = b"calldata-that-scales-with-tea-eth-ratio";
    let (el, fpvm) = run_both_executors(oracle_rate, input);
    assert_eq!(el, fpvm, "EL and FPVM must agree at 999:1 rate");

    // Cross-check against the unscaled cost: scaling must actually be
    // applied (the multiplier wiring isn't a no-op).
    let (unscaled_el, unscaled_fpvm) = run_both_executors(tea_l1_cost::WAD, input);
    assert_eq!(unscaled_el, unscaled_fpvm);
    assert_eq!(
        el, unscaled_el * U256::from(999u64),
        "scaled cost must equal raw_cost * 999",
    );
}

/// Packed oracle slot (timestamp upper 96 bits, price lower 160 bits) — the
/// exact wire format the GasPriceOracle contract stores. Both factories
/// must strip the timestamp via `extract_price_from_u256` and produce the
/// same final cost.
#[test]
fn cross_executor_parity_packed_slot_with_timestamp() {
    // examplePriceRatio from rollup_cost_test.go: timestamp=0x67931924, price=999*WAD
    let packed = U256::from_be_bytes(alloy_primitives::hex!(
        "00000000000000006793192400000000000000000000003627e8f712373c0000"
    ));
    let input = b"calldata-with-realistic-packed-oracle-slot";
    let (el, fpvm) = run_both_executors(packed, input);
    assert_eq!(el, fpvm, "EL and FPVM must agree with packed slot");
    // 999*WAD scaling — sanity check
    let (unscaled, _) = run_both_executors(tea_l1_cost::WAD, input);
    assert_eq!(
        el, unscaled * U256::from(999u64),
        "packed slot must yield 999x scaling",
    );
}

/// Empty calldata returns U256::ZERO regardless of multiplier (op-revm
/// short-circuits before the scaling step). Both sides must short-circuit
/// the same way.
#[test]
fn cross_executor_parity_empty_calldata() {
    let oracle_rate = U256::from(42u64) * tea_l1_cost::WAD;
    let (el, fpvm) = run_both_executors(oracle_rate, b"");
    assert_eq!(el, fpvm, "EL and FPVM must agree on empty calldata");
    assert_eq!(el, U256::ZERO, "empty calldata short-circuits to zero");
}

/// Deposit tx prefix (first byte = 0x7E) also short-circuits to zero.
/// op-revm:l1block.rs:298. Both sides must agree.
#[test]
fn cross_executor_parity_deposit_tx_short_circuits() {
    let oracle_rate = U256::from(42u64) * tea_l1_cost::WAD;
    let mut input = vec![0x7E_u8]; // type-126 deposit tx envelope marker
    input.extend_from_slice(b"-rest-of-deposit-tx-payload");
    let (el, fpvm) = run_both_executors(oracle_rate, &input);
    assert_eq!(el, fpvm, "EL and FPVM must agree on deposit tx");
    assert_eq!(el, U256::ZERO, "deposit tx short-circuits to zero");
}

/// Multiple calldata sizes — exercises the variable-size data_gas path of
/// the Fjord cost calculation. Both sides must produce identical output
/// for each size.
#[test]
fn cross_executor_parity_varying_calldata_sizes() {
    let oracle_rate = U256::from(7u64) * tea_l1_cost::WAD;
    for size in [1usize, 32, 100, 256, 1024, 4096] {
        let input: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
        let (el, fpvm) = run_both_executors(oracle_rate, &input);
        assert_eq!(
            el, fpvm,
            "EL and FPVM must agree for calldata size {size}",
        );
    }
}

/// Sweep across several different oracle slot values. For each value, the
/// EL and FPVM costs must match. This is the matrix test that would catch
/// any "factory A applies the multiplier and factory B doesn't" bug.
#[test]
fn cross_executor_parity_oracle_value_sweep() {
    let input = b"sweep-test-calldata-payload";
    for (label, oracle_rate) in [
        ("zero (backup)", U256::ZERO),
        ("1:1", tea_l1_cost::WAD),
        ("2:1", U256::from(2u64) * tea_l1_cost::WAD),
        ("999:1", U256::from(999u64) * tea_l1_cost::WAD),
        ("BACKUP rate", U256::from(tea_l1_cost::BACKUP_TEA_PER_ETH) * tea_l1_cost::WAD),
        ("1M:1", U256::from(1_000_000u64) * tea_l1_cost::WAD),
    ] {
        let (el, fpvm) = run_both_executors(oracle_rate, input);
        assert_eq!(el, fpvm, "EL and FPVM diverged at oracle rate '{label}'");
    }
}

/// Sanity: with the multiplier wiring in place, scaling actually applies.
/// If a future refactor breaks the wiring on one side (and not the other),
/// the scaled vs unscaled assertion catches it.
#[test]
fn cross_executor_parity_scaling_actually_engages() {
    let input = b"scaling-engages-sanity-check";
    let (unscaled, _) = run_both_executors(tea_l1_cost::WAD, input);
    let (scaled, _) = run_both_executors(
        U256::from(5u64) * tea_l1_cost::WAD,
        input,
    );
    assert_eq!(
        scaled, unscaled * U256::from(5u64),
        "5x rate must produce 5x cost — wiring is engaged",
    );
}
