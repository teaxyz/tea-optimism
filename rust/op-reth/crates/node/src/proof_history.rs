//! Shared launcher that installs the proof-history stack (TEAO1-152).
//!
//! The proof-history stack is an [`OpProofsExEx`] plus proof-storage-backed
//! `eth_getProof` / `debug_*` RPC overrides, persisted in an on-disk MDBX store.
//!
//! Contract: the caller supplies an **already fully-configured** node builder
//! (types + components + add-ons), so that any caller-specific executor is
//! preserved. In particular tea-reth hands a builder whose executor is its
//! `TeaExecutorBuilder` (GPG precompile 0x0696 + TEA L1 cost function); this
//! launcher must NOT replace it. We only *add* an ExEx, an `on_node_started`
//! metrics hook, and RPC module overrides, then launch.
//!
//! Gate / path / preflight all live here so both the op-reth default binary and
//! tea-reth go through identical install semantics.

use crate::args::RollupArgs;
use futures_util::FutureExt;
use reth_db_api::database_metrics::DatabaseMetrics;
use jsonrpsee_types::ErrorObject;
use reth_node_api::{
    BuildNextEnv, ConfigureEvm, FullNodeComponents, HeaderTy, NodeTypes, PayloadTypes,
};
use reth_node_builder::{
    DebugNode, DebugNodeLauncher, FullNodeTypes, LaunchNode, NodeAdapter, NodeBuilderWithComponents,
    NodeComponents, NodeComponentsBuilder, NodeHandle, WithLaunchContext, rpc::RethRpcAddOns,
};
use reth_optimism_payload_builder::OpAttributes;
use reth_rpc_eth_api::{EthApiTypes, helpers::FullEthApi};

/// The payload-builder attributes for the node's payload type.
type PayloadAttrs<T> =
    <<<T as FullNodeTypes>::Types as NodeTypes>::Payload as PayloadTypes>::PayloadBuilderAttributes;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_exex::OpProofsExEx;
use reth_optimism_primitives::OpPrimitives;
use reth_optimism_rpc::{
    debug::{DebugApiExt, DebugApiOverrideServer},
    eth::proofs::{EthApiExt, EthApiOverrideServer},
};
use reth_optimism_trie::{OpProofsStorage, OpProofsStore, db::MdbxProofsStorage};
use std::{path::PathBuf, sync::Arc};
use tracing::info;

/// Whether the proof-history stack should be installed for this CLI invocation
/// (TEAO1-152).
///
/// Fires on either `--proofs-history` or a supplied `--proofs-history.storage-path`.
/// The sub-flag is included because upstream's `default_value_ifs` meant to imply
/// the bare flag from the storage path never fires (it references the long-flag
/// string `"proofs-history.storage-path"` rather than the field-derived arg id
/// `proofs_history_storage_path`), so the path alone leaves `proofs_history ==
/// false`. Without this, passing only the storage path would silently install
/// nothing — the exact accept-but-ignore mismatch TEAO1-152 is about.
pub fn should_install_proofs_history(args: &RollupArgs) -> bool {
    args.proofs_history || args.proofs_history_storage_path.is_some()
}

/// Resolve the on-disk storage path for the proof-history stack.
///
/// Only meaningful when [`should_install_proofs_history`] is true. The proof
/// storage is MDBX-backed and therefore needs an explicit path: requesting
/// proof-history (e.g. a bare `--proofs-history`) without
/// `--proofs-history.storage-path` is rejected with a clear error rather than
/// panicking or silently doing nothing.
pub fn proofs_history_storage_path(args: &RollupArgs) -> eyre::Result<PathBuf> {
    args.proofs_history_storage_path
        .clone()
        .ok_or_else(|| eyre::eyre!("--proofs-history requires --proofs-history.storage-path"))
}

/// Launch a node, installing the proof-history stack when requested.
///
/// `node_builder` must already be fully configured by the caller (types,
/// components — including any custom executor — and add-ons). This launcher
/// preserves that configuration and only adds the proof-history ExEx + RPC
/// overrides + a storage-metrics hook before launching with debug capabilities.
///
/// When proof-history is not requested, the node launches unchanged.
pub async fn launch_node_with_proof_history<T, CB, AO>(
    mut node_builder: WithLaunchContext<NodeBuilderWithComponents<T, CB, AO>>,
    args: &RollupArgs,
) -> eyre::Result<()>
where
    T: FullNodeTypes<Types: NodeTypes<ChainSpec = OpChainSpec, Primitives = OpPrimitives>>,
    CB: NodeComponentsBuilder<T>,
    AO: RethRpcAddOns<NodeAdapter<T, CB::Components>>,
    AO::EthApi: FullEthApi,
    ErrorObject<'static>: From<<AO::EthApi as EthApiTypes>::Error>,
    // DebugApiExt::into_rpc (debug_executePayload) re-builds the next block env,
    // so the node's EVM config must know how to build it for the payload attrs,
    // and the payload attrs must be OP attributes.
    PayloadAttrs<T>: OpAttributes<Transaction = op_alloy_consensus::OpTxEnvelope>,
    <CB::Components as NodeComponents<T>>::Evm: ConfigureEvm<
            NextBlockEnvCtx: BuildNextEnv<PayloadAttrs<T>, HeaderTy<T::Types>, OpChainSpec>,
        >,
    T::Types: DebugNode<NodeAdapter<T, CB::Components>>,
    // launch_with_debug_capabilities goes through the DebugNodeLauncher; pin its
    // produced node to the concrete NodeHandle so `node_exit_future` is reachable.
    DebugNodeLauncher: LaunchNode<
            NodeBuilderWithComponents<T, CB, AO>,
            Node = NodeHandle<NodeAdapter<T, CB::Components>, AO>,
        >,
{
    if should_install_proofs_history(args) {
        let path = proofs_history_storage_path(args)?;
        info!(target: "reth::cli", "Using on-disk storage for proofs history");
        let mdbx = Arc::new(
            MdbxProofsStorage::new(&path)
                .map_err(|e| eyre::eyre!("Failed to create MdbxProofsStorage: {e}"))?,
        );
        let storage: OpProofsStorage<Arc<MdbxProofsStorage>> = mdbx.clone().into();

        // Preflight: the proofs-history ExEx requires the MDBX store to be
        // pre-initialized (backfilled from current chain state by
        // `tea-reth proofs init`). Without it the ExEx panics mid-launch with
        // an op-reth-centric message ("run 'op-reth initialize-op-proofs …'").
        // Surface a clean, tea-reth-correct error here instead.
        if storage
            .get_earliest_block_number()
            .map_err(|e| eyre::eyre!("failed to read proofs-history storage: {e}"))?
            .is_none()
        {
            eyre::bail!(
                "proofs-history storage at {path} is not initialized; run \
                 `tea-reth proofs init --proofs-history.storage-path {path}` \
                 (with the same --chain/--datadir) before starting the node \
                 with --proofs-history",
                path = path.display(),
            );
        }

        let storage_exec = storage.clone();
        let window = args.proofs_history_window;
        let prune_interval = args.proofs_history_prune_interval;
        let verification_interval = args.proofs_history_verification_interval;
        node_builder = node_builder
            .on_node_started(move |node| {
                let executor = node.task_executor.clone();
                let metrics_interval = node.config.metrics.push_gateway_interval;
                let storage = mdbx.clone();
                executor.spawn_critical_task("op-proofs-storage-metrics", async move {
                    loop {
                        tokio::time::sleep(metrics_interval).await;
                        storage.report_metrics();
                    }
                });
                Ok(())
            })
            .install_exex("proofs-history", async move |exex_context| {
                Ok(OpProofsExEx::builder(exex_context, storage_exec)
                    .with_proofs_history_window(window)
                    .with_proofs_history_prune_interval(prune_interval)
                    .with_verification_interval(verification_interval)
                    .build()
                    .run()
                    .boxed())
            })
            .extend_rpc_modules(move |ctx| {
                let api_ext = EthApiExt::new(ctx.registry.eth_api().clone(), storage.clone());
                let debug_ext = DebugApiExt::new(
                    ctx.node().provider().clone(),
                    ctx.registry.eth_api().clone(),
                    storage,
                    Box::new(ctx.node().task_executor().clone()),
                    ctx.node().evm_config().clone(),
                );
                ctx.modules.replace_configured(api_ext.into_rpc())?;
                ctx.modules.replace_configured(debug_ext.into_rpc())?;
                Ok(())
            });
    }

    let handle = node_builder.launch_with_debug_capabilities().await?;
    handle.node_exit_future.await
}
