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
            let node = OpNode::new(rollup_args);

            info!(target: "tea_reth", "Launching Tea node with custom precompiles");

            let handle = builder
                .with_types::<OpNode>()
                .with_components(
                    node.components()
                        // Swap the default OpExecutorBuilder for Tea's custom one
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
                )
                .launch_with_debug_capabilities()
                .await?;

            handle.node_exit_future.await
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
