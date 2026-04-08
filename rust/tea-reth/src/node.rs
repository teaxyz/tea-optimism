//! Tea node builder components.
//!
//! Provides [`TeaExecutorBuilder`] for injecting [`TeaEvmFactory`] into an OP Stack
//! node, and [`TeaOpEvmConfig`] as the resulting EVM configuration type.

use std::marker::PhantomData;
use std::sync::Arc;

use reth_node_builder::{BuilderContext, NodeTypes, components::ExecutorBuilder};
use reth_op::{
    OpPrimitives,
    chainspec::OpChainSpec,
    evm::{OpBlockAssembler, OpBlockExecutorFactory, OpRethReceiptBuilder},
    node::{OpEvmConfig, OpExecutorBuilder},
};

use crate::evm::TeaEvmFactory;

/// Convenience type alias for the Tea-customized OP EVM configuration.
///
/// This replaces the default `OpEvmFactory` with [`TeaEvmFactory`] to inject
/// Tea's GPG precompile and L1 cost multiplier.
pub type TeaOpEvmConfig =
    OpEvmConfig<OpChainSpec, OpPrimitives, OpRethReceiptBuilder, TeaEvmFactory>;

/// Create a [`TeaOpEvmConfig`] for the given chain spec.
///
/// This is the Tea equivalent of `OpEvmConfig::optimism(chain_spec)` — it wires
/// in [`TeaEvmFactory`] instead of the default `OpEvmFactory`.
pub fn tea_optimism(chain_spec: Arc<OpChainSpec>) -> TeaOpEvmConfig {
    OpEvmConfig {
        executor_factory: OpBlockExecutorFactory::new(
            OpRethReceiptBuilder::default(),
            chain_spec.clone(),
            TeaEvmFactory,
        ),
        block_assembler: OpBlockAssembler::new(chain_spec),
        _pd: PhantomData,
    }
}

/// Tea executor builder: wraps [`OpExecutorBuilder`] but swaps in [`TeaEvmFactory`].
///
/// Use this with `.executor(TeaExecutorBuilder)` on a node builder to make the
/// node's block execution use Tea's custom EVM (precompiles + L1 cost multiplier).
#[derive(Debug, Clone, Default)]
pub struct TeaExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for TeaExecutorBuilder
where
    Node: reth_node_builder::FullNodeTypes<
            Types: NodeTypes<ChainSpec = OpChainSpec, Primitives = OpPrimitives>,
        >,
{
    type EVM = TeaOpEvmConfig;

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
