//! POC (TEAO1-143): Interop host replays fee-paying optimistic blocks with raw OP fees.
//!
//! Proof statement: the exact host-side EVM factory that interop optimistic-block re-execution
//! USED TO construct (`OpEvmFactory::default()`) and the client-side factory used by interop
//! replay (`FpvmOpEvmFactory`) charge different L1 fees and leave different sender balances for
//! the same non-deposit transaction when the Tea oracle multiplier is not 1x. Because the interop
//! host persists an execution-derived header for the optimistic block, this factory split is
//! sufficient to produce a different post-state/header than the client replay.
//!
//! This test documents WHY the host must not hand-roll its own factory: it pins the divergence
//! the fix closes by routing the host re-execution through the same `FpvmOpEvmFactory` as the
//! client. The two factories themselves are unchanged, so this comparison keeps passing and stands
//! as the regression rationale for `kona-host`'s interop `L2BlockData` handler.

use alloy_consensus::{SignableTransaction, TxLegacy, transaction::Recovered};
use alloy_evm::{
    Evm,
    EvmFactory,
    block::{BlockExecutor, BlockExecutorFactory},
    revm::context::BlockEnv,
};
use alloy_eips::{Encodable2718, eip2718::WithEncoded};
use alloy_op_evm::{
    OpEvmFactory,
    block::{OpAlloyReceiptBuilder, OpBlockExecutionCtx, OpBlockExecutorFactory},
};
use alloy_primitives::{Address, Bytes, TxKind, U256, address};
use alloy_op_hardforks::OpChainHardforks;
use kona_client::fpvm_evm::FpvmOpEvmFactory;
use kona_preimage::{BidirectionalChannel, HintWriter, OracleReader};
use op_alloy_consensus::OpTxEnvelope;
use op_revm::{
    OpSpecId,
    constants::{
        BASE_FEE_SCALAR_OFFSET, ECOTONE_L1_BLOB_BASE_FEE_SLOT, ECOTONE_L1_FEE_SCALARS_SLOT,
        L1_BASE_FEE_SLOT, L1_BLOCK_CONTRACT, OPERATOR_FEE_SCALARS_SLOT,
    },
};
use revm::{
    Database,
    context::CfgEnv,
    database::{InMemoryDB, State},
    primitives::HashMap,
    state::AccountInfo,
};

const TEA_CHAIN_ID: u64 = 6122;
const BLOCK_GAS_LIMIT: u64 = 1_000_000;
const BLOCK_TIMESTAMP: u64 = u64::MAX;
const SENDER: Address = address!("1000000000000000000000000000000000000001");
const RECIPIENT: Address = address!("2000000000000000000000000000000000000002");
const BENEFICIARY: Address = address!("3000000000000000000000000000000000000003");
const INITIAL_BALANCE: u128 = 1_000_000_000_000_000_000;

fn seeded_state(oracle_slot_value: U256) -> State<InMemoryDB> {
    const L1_BASE_FEE: U256 = U256::from_limbs([1_000_000_000, 0, 0, 0]);
    const L1_BLOB_BASE_FEE: U256 = U256::from_limbs([10_000_000_000, 0, 0, 0]);
    const L1_BASE_FEE_SCALAR: u64 = 2_000_000;
    const L1_BLOB_BASE_FEE_SCALAR: u64 = 800_000;
    const OPERATOR_FEE_SCALAR: u8 = 5;
    const OPERATOR_FEE_CONST: u8 = 6;

    let l1_fee_scalars = U256::from_limbs([
        0,
        (L1_BASE_FEE_SCALAR << (64 - BASE_FEE_SCALAR_OFFSET * 2)) | L1_BLOB_BASE_FEE_SCALAR,
        0,
        0,
    ]);

    let mut operator_fee_and_da_footprint = [0u8; 32];
    operator_fee_and_da_footprint[31] = OPERATOR_FEE_CONST;
    operator_fee_and_da_footprint[23] = OPERATOR_FEE_SCALAR;
    let operator_fee_and_da_footprint_u256 = U256::from_be_bytes(operator_fee_and_da_footprint);

    let mut db = State::builder().with_database(InMemoryDB::default()).build();

    db.insert_account_with_storage(
        L1_BLOCK_CONTRACT,
        Default::default(),
        HashMap::from_iter([
            (L1_BASE_FEE_SLOT, L1_BASE_FEE),
            (ECOTONE_L1_FEE_SCALARS_SLOT, l1_fee_scalars),
            (ECOTONE_L1_BLOB_BASE_FEE_SLOT, L1_BLOB_BASE_FEE),
            (OPERATOR_FEE_SCALARS_SLOT, operator_fee_and_da_footprint_u256),
        ]),
    );

    db.insert_account_with_storage(
        tea_l1_cost::GAS_PRICE_ORACLE_ADDR,
        Default::default(),
        HashMap::from_iter([(tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256, oracle_slot_value)]),
    );

    db.insert_account(
        SENDER,
        AccountInfo { balance: U256::from(INITIAL_BALANCE), ..Default::default() },
    );

    db
}

fn make_env() -> alloy_evm::EvmEnv<OpSpecId> {
    alloy_evm::EvmEnv {
        cfg_env: CfgEnv::new()
            .with_chain_id(TEA_CHAIN_ID)
            .with_spec_and_mainnet_gas_params(OpSpecId::JOVIAN),
        block_env: BlockEnv {
            number: U256::from(1u64),
            timestamp: U256::from(BLOCK_TIMESTAMP),
            gas_limit: BLOCK_GAS_LIMIT,
            basefee: 0,
            beneficiary: BENEFICIARY,
            ..Default::default()
        },
    }
}

fn make_fee_paying_tx() -> Recovered<OpTxEnvelope> {
    let tx = TxLegacy {
        gas_limit: 200_000,
        to: TxKind::Call(RECIPIENT),
        input: Bytes::from_static(b"tea-l1-cost-divergence"),
        ..Default::default()
    };

    Recovered::new_unchecked(
        OpTxEnvelope::Legacy(tx.into_signed(alloy_primitives::Signature::test_signature())),
        SENDER,
    )
}

fn run_with_stock_factory(oracle_slot_value: U256) -> (Option<(U256, U256)>, U256, U256) {
    let mut state = seeded_state(oracle_slot_value);
    let executor_factory = OpBlockExecutorFactory::new(
        OpAlloyReceiptBuilder::default(),
        OpChainHardforks::op_mainnet(),
        OpEvmFactory::default(),
    );
    let evm = executor_factory.evm_factory().create_evm(&mut state, make_env());
    let mut executor = executor_factory.create_executor(evm, OpBlockExecutionCtx::default());

    let tx = make_fee_paying_tx();
    let tx_bytes: Bytes = tx.encoded_2718().into();
    let tx_with_encoded = WithEncoded::new(tx_bytes.clone(), tx.clone());

    executor
        .execute_transaction(&tx_with_encoded)
        .expect("host-side execution should succeed");

    let multiplier = executor.evm().ctx().chain.l1_cost_multiplier;
    let tx_l1_cost = {
        let chain = &mut executor.evm_mut().ctx_mut().chain;
        chain.clear_tx_l1_cost();
        chain.calculate_tx_l1_cost(tx_bytes.as_ref(), OpSpecId::JOVIAN)
    };
    let sender_balance_after = executor
        .evm_mut()
        .db_mut()
        .basic(SENDER)
        .expect("sender lookup should succeed")
        .expect("sender account should exist")
        .balance;

    (multiplier, tx_l1_cost, sender_balance_after)
}

fn run_with_fpvm_factory(oracle_slot_value: U256) -> (Option<(U256, U256)>, U256, U256) {
    let hint_chan = BidirectionalChannel::new().expect("hint channel");
    let preimage_chan = BidirectionalChannel::new().expect("preimage channel");
    let fpvm_factory = FpvmOpEvmFactory::new(
        HintWriter::new(hint_chan.client),
        OracleReader::new(preimage_chan.client),
    );

    let mut state = seeded_state(oracle_slot_value);
    let executor_factory = OpBlockExecutorFactory::new(
        OpAlloyReceiptBuilder::default(),
        OpChainHardforks::op_mainnet(),
        fpvm_factory,
    );
    let evm = executor_factory.evm_factory().create_evm(&mut state, make_env());
    let mut executor = executor_factory.create_executor(evm, OpBlockExecutionCtx::default());

    let tx = make_fee_paying_tx();
    let tx_bytes: Bytes = tx.encoded_2718().into();
    let tx_with_encoded = WithEncoded::new(tx_bytes.clone(), tx.clone());

    executor
        .execute_transaction(&tx_with_encoded)
        .expect("client-side execution should succeed");

    let multiplier = executor.evm().ctx().chain.l1_cost_multiplier;
    let tx_l1_cost = {
        let chain = &mut executor.evm_mut().ctx_mut().chain;
        chain.clear_tx_l1_cost();
        chain.calculate_tx_l1_cost(tx_bytes.as_ref(), OpSpecId::JOVIAN)
    };
    let sender_balance_after = executor
        .evm_mut()
        .db_mut()
        .basic(SENDER)
        .expect("sender lookup should succeed")
        .expect("sender account should exist")
        .balance;

    (multiplier, tx_l1_cost, sender_balance_after)
}

#[test]
fn interop_host_factory_diverges_from_client_fee_replay() {
    let tea_multiplier_rate = U256::from(42u64) * tea_l1_cost::WAD;

    let (host_multiplier, host_l1_cost, host_sender_after) =
        run_with_stock_factory(tea_multiplier_rate);
    let (client_multiplier, client_l1_cost, client_sender_after) =
        run_with_fpvm_factory(tea_multiplier_rate);

    assert_eq!(
        host_multiplier, None,
        "the stock host-side OpEvmFactory leaves the Tea multiplier unset",
    );
    assert_eq!(
        client_multiplier,
        Some((tea_multiplier_rate, tea_l1_cost::WAD)),
        "the FPVM client-side factory installs the Tea multiplier from the oracle",
    );

    assert_ne!(
        host_l1_cost, client_l1_cost,
        "the same fee-paying tx must charge different L1 fees across the two factories",
    );
    assert_eq!(
        client_l1_cost,
        host_l1_cost * U256::from(42u64),
        "the FPVM replay applies the 42x Tea oracle multiplier while the host-side factory does not",
    );

    assert!(
        host_sender_after > client_sender_after,
        "the host-side replay leaves the sender with a higher balance because it undercharges L1 fees",
    );
    assert_eq!(
        host_sender_after - client_sender_after,
        client_l1_cost - host_l1_cost,
        "the sender balance delta is exactly the missing Tea-scaled L1 fee",
    );
}
