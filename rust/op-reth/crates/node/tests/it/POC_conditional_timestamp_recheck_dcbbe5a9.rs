//! Proof Statement: A transaction submitted through
//! `eth_sendRawTransactionConditional` with `timestampMax = head.timestamp + 1`
//! is accepted into the pool at head `T`. After the fix it must NOT be included
//! in the next block built at `T + 2`, proving `timestampMax` IS re-checked
//! during payload building. A companion test pins the same enforcement for the
//! `blockNumberMax` ceiling (`blockNumberMax = head.number`, next block exceeds
//! it), so both block-attribute ceilings the finding flags are covered.
//!
//! Cantina: "Conditional transactions are never re-checked during block
//! building". The maintenance task only evicts expired conditionals on a
//! post-commit `Commit` notification, leaving a window where the next block is
//! built before any eviction fires. The builder now enforces the conditional's
//! `blockNumberMax`/`timestampMax` ceilings at inclusion (companion to the
//! existing TEAO1-167 `knownAccounts` re-check).

use alloy_consensus::BlockHeader;
use alloy_genesis::Genesis;
use alloy_rpc_types_eth::erc4337::TransactionConditional;
use reth_db::test_utils::create_test_rw_db_with_path;
use reth_e2e_test_utils::{
    node::NodeTestContext, transaction::TransactionTestContext, wallet::Wallet,
};
use reth_node_builder::{EngineNodeLauncher, Node, NodeBuilder, NodeConfig};
use reth_node_core::args::DatadirArgs;
use reth_optimism_chainspec::OpChainSpecBuilder;
use reth_optimism_node::{OpNode, args::RollupArgs, utils::optimism_payload_attributes};
use reth_optimism_rpc::eth::ext::OpEthExtApi;
use reth_provider::{BlockReaderIdExt, providers::BlockchainProvider};
use reth_rpc_api::L2EthApiExtServer;
use std::sync::Arc;

#[tokio::test]
async fn test_conditional_timestamp_max_rechecked_during_payload_building() {
    reth_tracing::init_test_tracing();
    let genesis: Genesis = serde_json::from_str(include_str!("../assets/genesis.json")).unwrap();
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
    let head = full_node
        .provider
        .latest_header()
        .expect("latest header query failed")
        .expect("genesis header missing");
    let head_timestamp = head.header().timestamp();
    let next_block_timestamp = head_timestamp + 2;
    let wallets = Wallet::new(2).with_chain_id(chain_id).wallet_gen();
    let anchor_wallet = wallets[0].clone();
    let conditional_wallet = wallets[1].clone();
    let anchor_tx =
        TransactionTestContext::optimism_l1_block_info_tx(chain_id, anchor_wallet, 0).await;
    let conditional_tx =
        TransactionTestContext::transfer_tx_bytes_with_nonce(chain_id, conditional_wallet, 0).await;
    let condition =
        TransactionConditional { timestamp_max: Some(head_timestamp + 1), ..Default::default() };
    assert!(condition.matches_timestamp(head_timestamp));
    assert!(!condition.matches_timestamp(next_block_timestamp));
    let conditional_hash = api
        .send_raw_transaction_conditional(conditional_tx.clone(), condition)
        .await
        .expect("conditional submission should succeed at the current head");
    let mut node =
        NodeTestContext::new(full_node, move |_| optimism_payload_attributes(next_block_timestamp))
            .await
            .unwrap();
    let anchor_hash = node.rpc.inject_tx(anchor_tx).await.expect("anchor tx should be accepted");
    let payload = node.advance_block().await.expect("payload build should succeed");
    let block = payload.block();
    node.wait_block(block.number(), block.hash(), false)
        .await
        .expect("block should become canonical");
    let hashes: Vec<_> =
        block.body().transactions().map(|tx| tx.tx_hash().to_owned()).collect();
    assert!(
        hashes.iter().any(|hash| hash.as_slice() == anchor_hash.as_slice()),
        "expected the anchor transaction to keep the block non-empty"
    );
    assert_eq!(
        block.header().timestamp(),
        next_block_timestamp,
        "test must build the next block at T + 2"
    );
    // INVERTED vs the finding's PoC to prove the FIX: the conditional tx whose
    // `timestampMax` (head + 1) has expired by the candidate block timestamp
    // (head + 2) must now be EXCLUDED during payload building, not included.
    assert!(
        !hashes.iter().any(|hash| hash.as_slice() == conditional_hash.as_slice()),
        "conditional tx with expired timestampMax must be excluded during payload building"
    );
}

/// Same window as above, for the other ceiling the finding flags: a conditional
/// with `blockNumberMax = head.number + 1` is valid at admission (the head does
/// not reach it) but the next block (`head.number + 1`) does. No `Commit` fires
/// between admission and the build, so only the builder's re-check can exclude
/// it.
#[tokio::test]
async fn test_conditional_block_number_max_rechecked_during_payload_building() {
    reth_tracing::init_test_tracing();
    let genesis: Genesis = serde_json::from_str(include_str!("../assets/genesis.json")).unwrap();
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
    let head = full_node
        .provider
        .latest_header()
        .expect("latest header query failed")
        .expect("genesis header missing");
    let head_number = head.header().number();
    let next_block_timestamp = head.header().timestamp() + 2;
    let wallets = Wallet::new(2).with_chain_id(chain_id).wallet_gen();
    let anchor_wallet = wallets[0].clone();
    let conditional_wallet = wallets[1].clone();
    let anchor_tx =
        TransactionTestContext::optimism_l1_block_info_tx(chain_id, anchor_wallet, 0).await;
    let conditional_tx =
        TransactionTestContext::transfer_tx_bytes_with_nonce(chain_id, conditional_wallet, 0).await;
    // `has_exceeded_block_number` is `n >= block_number_max`, so a ceiling of
    // `head + 1` still admits at the current head but is reached by the next block.
    let condition = TransactionConditional {
        block_number_max: Some(head_number + 1),
        ..Default::default()
    };
    assert!(!condition.has_exceeded_block_number(head_number));
    assert!(condition.has_exceeded_block_number(head_number + 1));
    let conditional_hash = api
        .send_raw_transaction_conditional(conditional_tx.clone(), condition)
        .await
        .expect("conditional submission should succeed at the current head");
    let mut node =
        NodeTestContext::new(full_node, move |_| optimism_payload_attributes(next_block_timestamp))
            .await
            .unwrap();
    let anchor_hash = node.rpc.inject_tx(anchor_tx).await.expect("anchor tx should be accepted");
    let payload = node.advance_block().await.expect("payload build should succeed");
    let block = payload.block();
    node.wait_block(block.number(), block.hash(), false)
        .await
        .expect("block should become canonical");
    let hashes: Vec<_> =
        block.body().transactions().map(|tx| tx.tx_hash().to_owned()).collect();
    assert!(
        hashes.iter().any(|hash| hash.as_slice() == anchor_hash.as_slice()),
        "expected the anchor transaction to keep the block non-empty"
    );
    assert_eq!(
        block.header().number(),
        head_number + 1,
        "test must build the block that reaches blockNumberMax"
    );
    assert!(
        !hashes.iter().any(|hash| hash.as_slice() == conditional_hash.as_slice()),
        "conditional tx with expired blockNumberMax must be excluded during payload building"
    );
}
