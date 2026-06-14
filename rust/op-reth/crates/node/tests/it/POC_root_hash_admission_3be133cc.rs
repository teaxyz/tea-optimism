//! Admission-boundary regression for the RootHash `knownAccounts` rejection
//! (Cantina: "RootHash conditionals still bypass inclusion-time revalidation in
//! the payload builder").
//!
//! The payload builder runs against a bare revm `Database` with no storage trie,
//! so it can never honor an `AccountStorage::RootHash` predicate at inclusion
//! time. `eth_sendRawTransactionConditional` therefore rejects such conditionals
//! at admission. This test exercises the real RPC boundary for both sides of the
//! compatibility contract:
//! - rejected input: a `RootHash` conditional is refused with an invalid-params
//!   error and never enters the pool;
//! - allowed legitimate input: a `Slots`-based conditional that matches state is
//!   still accepted into the pool unchanged.

use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_eth::erc4337::{AccountStorage, TransactionConditional};
use reth_db::test_utils::create_test_rw_db_with_path;
use reth_e2e_test_utils::{transaction::TransactionTestContext, wallet::Wallet};
use reth_node_builder::{EngineNodeLauncher, Node, NodeBuilder, NodeConfig};
use reth_node_core::args::DatadirArgs;
use reth_optimism_chainspec::OpChainSpecBuilder;
use reth_optimism_node::{OpNode, args::RollupArgs};
use reth_optimism_rpc::eth::ext::OpEthExtApi;
use reth_provider::providers::BlockchainProvider;
use reth_rpc_api::L2EthApiExtServer;
use reth_transaction_pool::TransactionPool;
use std::sync::Arc;

#[tokio::test]
async fn test_root_hash_conditional_rejected_and_slots_conditional_accepted_at_admission() {
    reth_tracing::init_test_tracing();
    let genesis: alloy_genesis::Genesis =
        serde_json::from_str(include_str!("../assets/genesis.json")).unwrap();
    let chain_spec = Arc::new(
        OpChainSpecBuilder::base_mainnet().genesis(genesis).ecotone_activated().build(),
    );
    let chain_id = chain_spec.chain().id();
    let rollup_args = RollupArgs { enable_tx_conditional: true, ..Default::default() };
    let mut config = NodeConfig::new(chain_spec.clone()).with_unused_ports().with_datadir_args(
        DatadirArgs { datadir: reth_db::test_utils::tempdir_path().into(), ..Default::default() },
    );
    config.network.discovery.discv5_port = 0;
    config.network.discovery.discv5_port_ipv6 = 0;
    let db = create_test_rw_db_with_path(
        config
            .datadir
            .datadir
            .unwrap_or_chain_default(config.chain.chain(), config.datadir.clone())
            .db(),
    );
    let runtime = reth_tasks::Runtime::test();
    let node_handle = NodeBuilder::new(config.clone())
        .with_database(db)
        .with_types_and_provider::<OpNode, BlockchainProvider<_>>()
        .with_components(OpNode::new(rollup_args.clone()).components())
        .with_add_ons(OpNode::new(rollup_args).add_ons())
        .launch_with_fn(|builder| {
            let launcher = EngineNodeLauncher::new(
                runtime.clone(),
                builder.config.datadir(),
                Default::default(),
            );
            builder.launch_with(launcher)
        })
        .await
        .expect("failed to launch node");
    let full_node = node_handle.node;
    let api = OpEthExtApi::new(None, full_node.pool.clone(), full_node.provider.clone());

    let wallets = Wallet::new(2).with_chain_id(chain_id).wallet_gen();
    let rejected_tx =
        TransactionTestContext::transfer_tx_bytes_with_nonce(chain_id, wallets[0].clone(), 0).await;
    let accepted_tx =
        TransactionTestContext::transfer_tx_bytes_with_nonce(chain_id, wallets[1].clone(), 0).await;

    let watched = Address::with_last_byte(0x42);

    // Rejected malicious/unsupported input: a RootHash predicate must be refused
    // at admission with the dedicated invalid-params error, before any state
    // validation, and the tx must never enter the pool.
    let mut root_condition = TransactionConditional::default();
    root_condition
        .known_accounts
        .insert(watched, AccountStorage::RootHash(B256::with_last_byte(0x11)));
    let err = api
        .send_raw_transaction_conditional(rejected_tx, root_condition)
        .await
        .expect_err("RootHash conditionals must be rejected at admission");
    assert!(
        err.to_string().contains("RootHash"),
        "rejection must surface the RootHash-specific error, got: {err}"
    );
    assert_eq!(
        full_node.pool.pooled_transactions().len(),
        0,
        "a rejected RootHash conditional must never enter the pool"
    );

    // Allowed legitimate input: a Slots predicate that matches current state
    // (an absent slot reads as zero) is admitted exactly as before the fix.
    let mut slots = alloy_primitives::map::HashMap::default();
    slots.insert(U256::ZERO, B256::ZERO);
    let mut slots_condition = TransactionConditional::default();
    slots_condition.known_accounts.insert(watched, AccountStorage::Slots(slots));
    let accepted_hash = api
        .send_raw_transaction_conditional(accepted_tx, slots_condition)
        .await
        .expect("a matching Slots conditional must still be accepted at admission");
    assert!(
        full_node.pool.get(&accepted_hash).is_some(),
        "the accepted Slots conditional must be present in the pool"
    );
}
