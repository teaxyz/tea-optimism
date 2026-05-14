//! Tea EVM factory with custom precompile registration.
//!
//! Sets up Tea-specific precompiles (GPG verify at `0x0696`, SSH verify at
//! `0x0697`, SSHSIG verify at `0x0698`) and the TEA/ETH exchange rate
//! multiplier for L1 cost calculation.

use alloy_evm::{Database, Evm, EvmEnv, EvmFactory, precompiles::PrecompilesMap};
use alloy_op_evm::{OpEvm, OpEvmFactory};
use alloy_primitives::U256;
use op_revm::{
    OpContext, OpHaltReason, OpSpecId, OpTransaction, OpTransactionError,
    precompiles::OpPrecompiles,
};
use revm::{
    Inspector,
    context::{BlockEnv, ContextTr, TxEnv},
    context_interface::result::EVMError,
    inspector::NoOpInspector,
    precompile::Precompiles,
};
use std::sync::OnceLock;

use crate::l1_cost;
use crate::precompiles::gpg_verify;
use crate::precompiles::ssh_sig_verify;
use crate::precompiles::ssh_verify;

/// Tea precompiles: standard OP precompiles plus Tea-specific ones.
struct TeaPrecompiles;

impl TeaPrecompiles {
    /// Returns the complete precompile map for Tea, including the GPG, SSH,
    /// and SSHSIG verify precompiles.
    fn precompiles(spec_id: OpSpecId) -> PrecompilesMap {
        static INSTANCE: OnceLock<Precompiles> = OnceLock::new();

        PrecompilesMap::from_static(INSTANCE.get_or_init(|| {
            let mut precompiles = OpPrecompiles::new_with_spec(spec_id).precompiles().clone();
            precompiles.extend([
                gpg_verify::precompile(),
                ssh_verify::precompile(),
                ssh_sig_verify::precompile(),
            ]);
            precompiles
        }))
    }
}

/// Tea EVM factory that wraps [`OpEvmFactory`] and adds Tea-specific precompiles
/// and the TEA/ETH L1 cost multiplier.
#[derive(Default, Debug, Clone, Copy)]
pub struct TeaEvmFactory;

/// Read the TEA/ETH exchange rate from the GasPriceOracle and return the
/// L1 cost multiplier as `(numerator, denominator)`.
fn tea_l1_cost_multiplier<DB: Database>(db: &mut DB) -> Option<(U256, U256)> {
    let raw =
        db.storage(l1_cost::GAS_PRICE_ORACLE_ADDR, l1_cost::LATEST_PRICE_RATIO_SLOT_U256).ok()?;
    let price = l1_cost::extract_price_from_u256(raw);
    let rate = l1_cost::tea_per_wad_eth_or_backup(price);
    Some((rate, l1_cost::WAD))
}

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
        // Read TEA/ETH exchange rate before the DB is moved into the EVM.
        let multiplier = tea_l1_cost_multiplier(&mut db);

        let mut op_evm = OpEvmFactory::default().create_evm(db, input);
        *op_evm.components_mut().2 = TeaPrecompiles::precompiles(*op_evm.ctx().cfg().spec());
        op_evm.ctx_mut().chain.l1_cost_multiplier = multiplier;
        op_evm
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        mut db: DB,
        input: EvmEnv<OpSpecId>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let multiplier = tea_l1_cost_multiplier(&mut db);

        let mut op_evm = OpEvmFactory::default().create_evm_with_inspector(db, input, inspector);
        *op_evm.components_mut().2 = TeaPrecompiles::precompiles(*op_evm.ctx().cfg().spec());
        op_evm.ctx_mut().chain.l1_cost_multiplier = multiplier;
        op_evm
    }
}
