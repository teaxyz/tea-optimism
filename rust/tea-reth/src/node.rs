//! Tea node types for op-rbuilder integration.
//!
//! Exports `TeaOpEvmConfig`, `TeaExecutorBuilder`, `TeaEvmFactory`, and
//! `tea_optimism()` so op-rbuilder can import them from `tea_reth::node`.

use std::marker::PhantomData;

use alloy_evm::{Database, Evm as _, EvmEnv, EvmFactory, precompiles::PrecompilesMap};
use alloy_op_evm::{OpEvm, OpEvmFactory};
use op_revm::{
    OpContext, OpHaltReason, OpSpecId, OpTransaction, OpTransactionError,
};
use revm::{
    Inspector,
    context::{BlockEnv, ContextTr, TxEnv},
    context_interface::result::EVMError,
    inspector::NoOpInspector,
};

use reth_node_builder::{BuilderContext, NodeTypes, components::ExecutorBuilder};
use reth_op::{
    OpPrimitives,
    chainspec::OpChainSpec,
    evm::{OpBlockAssembler, OpBlockExecutorFactory, OpEvmConfig, OpRethReceiptBuilder},
};

// --- TeaEvmFactory ---

/// Tea EVM factory that wraps [`OpEvmFactory`] and adds Tea-specific precompiles
/// and the TEA/ETH L1 cost multiplier.
#[derive(Default, Debug, Clone, Copy)]
pub struct TeaEvmFactory;

impl EvmFactory for TeaEvmFactory {
    type Evm<DB: Database, I: Inspector<OpContext<DB>>> = OpEvm<DB, I, Self::Precompiles>;
    type Context<DB: Database> = OpContext<DB>;
    type Tx = OpTransaction<TxEnv>;
    type Error<DBError: core::error::Error + Send + Sync + 'static> =
        EVMError<DBError, OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        mut db: DB,
        input: EvmEnv<OpSpecId>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let multiplier = tea_precompiles::tea_l1_cost_multiplier(&mut db);
        let mut op_evm = OpEvmFactory::default().create_evm(db, input);
        *op_evm.components_mut().2 = tea_precompiles::tea_precompiles(*op_evm.ctx().cfg().spec());
        op_evm.ctx_mut().chain.l1_cost_multiplier = multiplier;
        op_evm
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        mut db: DB,
        input: EvmEnv<OpSpecId>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let multiplier = tea_precompiles::tea_l1_cost_multiplier(&mut db);
        let mut op_evm = OpEvmFactory::default().create_evm_with_inspector(db, input, inspector);
        *op_evm.components_mut().2 = tea_precompiles::tea_precompiles(*op_evm.ctx().cfg().spec());
        op_evm.ctx_mut().chain.l1_cost_multiplier = multiplier;
        op_evm
    }
}

// --- TeaOpEvmConfig ---

/// Tea's EvmConfig: `OpEvmConfig` parameterized with `TeaEvmFactory`.
pub type TeaOpEvmConfig = OpEvmConfig<
    OpChainSpec,
    OpPrimitives,
    OpRethReceiptBuilder,
    TeaEvmFactory,
>;

/// Construct a `TeaOpEvmConfig` for the given chain spec.
pub fn tea_optimism(chain_spec: std::sync::Arc<OpChainSpec>) -> TeaOpEvmConfig {
    let tea_executor_factory = OpBlockExecutorFactory::new(
        OpRethReceiptBuilder::default(),
        chain_spec.clone(),
        TeaEvmFactory,
    );
    OpEvmConfig {
        executor_factory: tea_executor_factory,
        block_assembler: OpBlockAssembler::new(chain_spec),
        _pd: PhantomData,
    }
}

// --- TeaExecutorBuilder ---

/// Tea executor builder: swaps `OpEvmFactory` for `TeaEvmFactory`.
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
        Ok(tea_optimism(ctx.chain_spec()))
    }
}
