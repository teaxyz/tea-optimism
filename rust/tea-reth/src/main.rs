//! Tea-reth: Custom OP Stack execution client for the Tea L2 chain.
//!
//! This binary is a thin wrapper around op-reth that adds:
//! - GPG signature verification precompile at address 0x0696
//! - TEA-denominated L1 cost function (wraps Fjord cost with TEA/ETH exchange rate)
//!
//! It uses the standard OpNode with a custom executor builder that injects
//! Tea-specific precompiles via TeaEvmFactory.

use std::marker::PhantomData;

use clap::Parser;
use futures_util::FutureExt;
// `report_metrics` on MdbxProofsStorage comes from this trait.
use reth_db::database_metrics::DatabaseMetrics;
use reth_node_builder::rpc::BasicEngineValidatorBuilder;
// `provider`/`task_executor`/`evm_config` accessors on the started node come
// from FullNodeComponents.
use reth_node_builder::{
    BuilderContext, FullNodeComponents, NodeTypes, components::ExecutorBuilder,
};
use reth_op::{
    OpPrimitives,
    chainspec::OpChainSpec,
    evm::{OpBlockExecutorFactory, OpRethReceiptBuilder},
    node::{
        OpEngineApiBuilder, OpEngineValidatorBuilder, OpEvmConfig, OpExecutorBuilder, OpNode,
        args::RollupArgs,
    },
};
use reth_optimism_cli::{Cli, chainspec::OpChainSpecParser};
// TEAO1-152: proofs-history stack — installed inline below so it runs on
// tea-reth's TeaExecutorBuilder-configured node builder (op-reth's
// launch_node_with_proof_history hardcodes a plain OpNode and cannot reference
// TeaExecutorBuilder, which lives here).
use reth_optimism_exex::OpProofsExEx;
use reth_optimism_rpc::{
    debug::{DebugApiExt, DebugApiOverrideServer},
    eth::proofs::{EthApiExt, EthApiOverrideServer},
};
use reth_optimism_trie::{OpProofsStorage, db::MdbxProofsStorage};
use tea_reth::evm::TeaEvmFactory;
use tracing::info;

/// Tea executor builder: wraps OpExecutorBuilder but swaps in TeaEvmFactory.
#[derive(Debug, Clone, Default)]
struct TeaExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for TeaExecutorBuilder
where
    Node: reth_node_builder::FullNodeTypes<
            Types: NodeTypes<ChainSpec = OpChainSpec, Primitives = OpPrimitives>,
        >,
{
    type EVM = OpEvmConfig<
        OpChainSpec,
        <Node::Types as NodeTypes>::Primitives,
        OpRethReceiptBuilder,
        TeaEvmFactory,
    >;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        let OpEvmConfig { executor_factory, block_assembler, _pd: _ } =
            OpExecutorBuilder::default().build_evm(ctx).await?;
        let tea_executor_factory = OpBlockExecutorFactory::new(
            *executor_factory.receipt_builder(),
            ctx.chain_spec(),
            TeaEvmFactory,
        );
        Ok(OpEvmConfig {
            executor_factory: tea_executor_factory,
            block_assembler,
            _pd: PhantomData,
        })
    }
}

fn main() {
    reth_cli_util::sigsegv_handler::install();

    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "1");
        }
    }

    if let Err(err) =
        Cli::<OpChainSpecParser, RollupArgs>::parse().run(async move |builder, rollup_args| {
            // `rollup_args.clone()` so the proofs-history flags stay readable below
            // (RollupArgs is Clone).
            let node = OpNode::new(rollup_args.clone());

            info!(target: "tea_reth", "Launching Tea node with custom precompiles");

            let mut node_builder = builder
                .with_types::<OpNode>()
                .with_components(
                    node.components()
                        // Swap the default OpExecutorBuilder for Tea's custom one.
                        // INVARIANT (TEAO1-152): TeaExecutorBuilder injects
                        // TeaEvmFactory (GPG precompile 0x0696 + TEA L1 cost fn).
                        // The proofs-history install below MUST NOT change this.
                        .executor(TeaExecutorBuilder),
                )
                .with_add_ons(
                    node.add_ons_builder::<op_alloy_network::Optimism>()
                        .build::<
                            _,
                            OpEngineValidatorBuilder,
                            OpEngineApiBuilder<OpEngineValidatorBuilder>,
                            BasicEngineValidatorBuilder<OpEngineValidatorBuilder>,
                        >(),
                );

            // TEAO1-152: when proofs-history is requested, ACTUALLY install the
            // proof-history stack (OpProofsExEx + proof-storage-backed
            // eth_getProof / debug_* RPC overrides), mirroring op-reth's dead
            // `launch_node_with_proof_history`. This only ADDS an ExEx + RPC
            // overrides + an on_node_started hook; the executor is untouched.
            //
            // Gate on `proofs_history OR a storage-path was supplied`: upstream
            // RollupArgs intends `--proofs-history.storage-path` to imply
            // `--proofs-history` via a clap `default_value_ifs`, but that
            // predicate references the long-flag string `"proofs-history.storage-path"`
            // instead of the field-derived arg id `proofs_history_storage_path`,
            // so it never fires — passing only the sub-flag leaves
            // `proofs_history == false`. Without this OR, an operator who sets
            // only the storage path would get a SILENT no-install (no proofs
            // served, no error) — exactly the kind of mismatch TEAO1-152 is
            // about. A bare `--proofs-history` with no path still errors below.
            if should_install_proofs_history(&rollup_args) {
                let path = proofs_history_storage_path(&rollup_args)?;
                info!(target: "tea_reth", "Using on-disk storage for proofs history");
                let mdbx = std::sync::Arc::new(
                    MdbxProofsStorage::new(&path)
                        .map_err(|e| eyre::eyre!("Failed to create MdbxProofsStorage: {e}"))?,
                );
                let storage: OpProofsStorage<std::sync::Arc<MdbxProofsStorage>> =
                    mdbx.clone().into();
                let storage_exec = storage.clone();
                let window = rollup_args.proofs_history_window;
                let prune_interval = rollup_args.proofs_history_prune_interval;
                let verification_interval = rollup_args.proofs_history_verification_interval;
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
                        let api_ext =
                            EthApiExt::new(ctx.registry.eth_api().clone(), storage.clone());
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
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

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
fn should_install_proofs_history(args: &RollupArgs) -> bool {
    args.proofs_history || args.proofs_history_storage_path.is_some()
}

/// Resolve the on-disk storage path for the proof-history stack.
///
/// Only meaningful when [`should_install_proofs_history`] is true. The proof
/// storage is MDBX-backed and therefore needs an explicit path: requesting
/// proof-history (e.g. a bare `--proofs-history`) without
/// `--proofs-history.storage-path` is rejected with a clear error rather than
/// panicking (op-reth's reference path `expect()`s here) or silently doing
/// nothing.
fn proofs_history_storage_path(args: &RollupArgs) -> eyre::Result<std::path::PathBuf> {
    args.proofs_history_storage_path
        .clone()
        .ok_or_else(|| eyre::eyre!("--proofs-history requires --proofs-history.storage-path"))
}

#[cfg(test)]
mod tests {
    use super::{proofs_history_storage_path, should_install_proofs_history};
    use clap::Parser;
    use reth_op::node::args::RollupArgs;

    /// Tiny harness to parse just the flattened `RollupArgs` from a CLI line.
    #[derive(Parser)]
    struct T {
        #[command(flatten)]
        r: RollupArgs,
    }

    /// TEAO1-152: the install gate must fire for the storage-path sub-flag —
    /// the exact bypass the finding flags. Upstream's `default_value_ifs` is
    /// dead (it keys on the long-flag string, not the field-derived arg id), so
    /// `--proofs-history.storage-path` alone leaves `proofs_history == false`;
    /// without the storage-path OR in the gate this would silently NOT install
    /// the proof-history stack. Assert the path parses and the gate fires.
    #[test]
    fn proofs_history_subflag_enables_install_gate() {
        let parsed = T::parse_from(["x", "--proofs-history.storage-path", "/tmp/ph"]);
        // Documents the upstream clap quirk this fix works around: the bare
        // boolean stays false even though a path was supplied.
        assert!(!parsed.r.proofs_history);
        assert_eq!(
            parsed.r.proofs_history_storage_path.as_deref(),
            Some(std::path::Path::new("/tmp/ph")),
        );
        // The gate must still fire so the stack is installed.
        assert!(should_install_proofs_history(&parsed.r), "storage-path sub-flag must trigger the install gate");
    }

    /// The bare `--proofs-history` flag also fires the gate.
    #[test]
    fn proofs_history_bare_flag_enables_install_gate() {
        let parsed = T::parse_from(["x", "--proofs-history"]);
        assert!(parsed.r.proofs_history);
        assert!(should_install_proofs_history(&parsed.r));
    }

    /// TEAO1-152 error case: a bare `--proofs-history` with NO storage path is
    /// rejected with a clear error (the MDBX proof store needs an explicit path),
    /// rather than panicking or silently installing nothing.
    #[test]
    fn proofs_history_without_storage_path_errors() {
        let parsed = T::parse_from(["x", "--proofs-history"]);
        // Gate fires (so `main` enters the install branch)...
        assert!(should_install_proofs_history(&parsed.r));
        // ...but path resolution fails closed with a descriptive error.
        let err = proofs_history_storage_path(&parsed.r)
            .expect_err("bare --proofs-history without a storage path must error");
        assert!(
            err.to_string().contains("--proofs-history.storage-path"),
            "error must name the missing flag, got: {err}"
        );
    }

    /// Success case: when a storage path is supplied, resolution returns it.
    #[test]
    fn proofs_history_with_storage_path_resolves() {
        let parsed = T::parse_from(["x", "--proofs-history", "--proofs-history.storage-path", "/tmp/ph"]);
        assert_eq!(
            proofs_history_storage_path(&parsed.r).expect("path should resolve"),
            std::path::PathBuf::from("/tmp/ph"),
        );
    }

    /// With no proofs-history flags the gate stays closed: no ExEx / RPC
    /// override install, node launches as a plain tea-reth node.
    #[test]
    fn no_proofs_history_flag_keeps_gate_closed() {
        let parsed = T::parse_from(["x"]);
        assert!(!parsed.r.proofs_history);
        assert!(parsed.r.proofs_history_storage_path.is_none());
        assert!(!should_install_proofs_history(&parsed.r), "no flags must leave the install gate closed");
    }
}
