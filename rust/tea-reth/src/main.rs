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
use reth_node_builder::rpc::BasicEngineValidatorBuilder;
use reth_node_builder::{BuilderContext, NodeTypes, components::ExecutorBuilder};
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
// TEAO1-152: the proofs-history stack (gate + path resolution + preflight
// init-check + ExEx/RPC install) lives in op-reth's `proof_history` module so
// op-reth's default binary and tea-reth share one implementation. We pass it
// our fully-configured node builder (TeaExecutorBuilder) and it preserves the
// executor — see the function's contract.
use reth_optimism_node::proof_history::launch_node_with_proof_history;
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
            let node = OpNode::new(rollup_args.clone());

            info!(target: "tea_reth", "Launching Tea node with custom precompiles");

            let node_builder = builder
                .with_types::<OpNode>()
                .with_components(
                    node.components()
                        // Swap the default OpExecutorBuilder for Tea's custom one.
                        // INVARIANT (TEAO1-152): TeaExecutorBuilder injects
                        // TeaEvmFactory (GPG precompile 0x0696 + TEA L1 cost fn).
                        // The shared proofs-history launcher preserves the
                        // caller's executor, so this MUST remain TeaExecutorBuilder.
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

            // TEAO1-152: hand the fully-configured (TeaExecutorBuilder) node
            // builder to op-reth's shared proofs-history launcher. It applies the
            // install gate (proofs_history OR storage-path supplied), resolves the
            // path, runs the preflight init-check, and installs the OpProofsExEx +
            // eth_getProof/debug_* RPC overrides when requested — preserving our
            // executor — then launches. When not requested it launches unchanged.
            launch_node_with_proof_history(node_builder, &rollup_args).await
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    // TEAO1-152: the install gate + path resolution now live in op-reth's shared
    // `proof_history` module (so op-reth and tea-reth share one implementation);
    // tea-reth still owns these tests to lock the behavior its node depends on.
    use reth_optimism_node::proof_history::{
        proofs_history_storage_path, should_install_proofs_history,
    };
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
