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
};
use std::borrow::Cow;

use crate::l1_cost;
use crate::precompiles::gpg_verify;
use crate::precompiles::ssh_sig_verify;
use crate::precompiles::ssh_verify;

/// Tea precompiles: standard OP precompiles plus Tea-specific ones.
struct TeaPrecompiles;

impl TeaPrecompiles {
    /// Returns the complete precompile map for `spec_id`, including the GPG,
    /// SSH, and SSHSIG verify precompiles.
    ///
    /// Built fresh for the requested spec on every call. A process-global
    /// `OnceLock` (the prior implementation) latched the first hardfork's OP
    /// precompile set forever, so an EVM created for a later hardfork in the
    /// same process silently ran with the wrong precompiles (TEAO1-145). This
    /// mirrors the FPVM, which rebuilds per spec via
    /// `OpFpvmPrecompiles::new_with_spec`, keeping EL and FPVM precompile sets
    /// in lockstep. The per-call clone is negligible next to EVM execution and
    /// is paid identically on the FPVM side.
    fn precompiles(spec_id: OpSpecId) -> PrecompilesMap {
        let mut precompiles = OpPrecompiles::new_with_spec(spec_id).precompiles().clone();
        precompiles.extend([
            gpg_verify::precompile(),
            ssh_verify::precompile(),
            ssh_sig_verify::precompile(),
        ]);
        PrecompilesMap::new(Cow::Owned(precompiles))
    }
}

/// Tea EVM factory that wraps [`OpEvmFactory`] and adds Tea-specific precompiles
/// and the TEA/ETH L1 cost multiplier.
#[derive(Default, Debug, Clone, Copy)]
pub struct TeaEvmFactory;

/// Read the TEA/ETH exchange rate from the GasPriceOracle and return the
/// L1 cost multiplier as `(numerator, denominator)`. The pure-math part —
/// extracting the 160-bit price from a packed slot and applying the
/// backup-rate fallback — lives in `tea_l1_cost::multiplier_from_oracle_value`
/// so the FPVM side in `kona::fpvm_evm::factory` consumes the same logic
/// and cannot drift on a one-sided refactor.
fn tea_l1_cost_multiplier<DB: Database>(db: &mut DB, chain_id: u64) -> Option<(U256, U256)> {
    // Off-Tea chains must never receive the TEA/ETH multiplier or the
    // 1,500,000× backup-rate fallback — applying it would diverge generic OP
    // replay from canonical Optimism (TEAO1-132). `None` means "no scaling"
    // downstream in the patched op-revm L1-cost path.
    if !crate::chainspec::is_tea(chain_id) {
        return None;
    }
    let raw =
        db.storage(l1_cost::GAS_PRICE_ORACLE_ADDR, l1_cost::LATEST_PRICE_RATIO_SLOT_U256).ok()?;
    Some(l1_cost::multiplier_from_oracle_value(raw))
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
        let multiplier = tea_l1_cost_multiplier(&mut db, input.cfg_env.chain_id);

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
        let multiplier = tea_l1_cost_multiplier(&mut db, input.cfg_env.chain_id);

        let mut op_evm = OpEvmFactory::default().create_evm_with_inspector(db, input, inspector);
        *op_evm.components_mut().2 = TeaPrecompiles::precompiles(*op_evm.ctx().cfg().spec());
        op_evm.ctx_mut().chain.l1_cost_multiplier = multiplier;
        op_evm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, address};
    use std::collections::BTreeSet;

    const GPG: Address = address!("0x0000000000000000000000000000000000000696");
    const SSH: Address = address!("0x0000000000000000000000000000000000000697");
    const SSHSIG: Address = address!("0x0000000000000000000000000000000000000698");

    fn addr_set(spec: OpSpecId) -> BTreeSet<Address> {
        TeaPrecompiles::precompiles(spec).addresses().copied().collect()
    }

    /// TEAO1-145: the precompile set must be built for the requested spec on
    /// every call, not latched from the first spec seen in the process. FJORD
    /// (pre-Prague) and ISTHMUS (Prague BLS precompiles) have different OP base
    /// sets; under the old process-global `OnceLock`, the second build returned
    /// the first's cached set, so they would compare equal. Both specs must
    /// also carry the three Tea precompiles, and order must not matter.
    #[test]
    fn precompiles_are_per_spec_not_latched() {
        let fjord = addr_set(OpSpecId::FJORD);
        let isthmus = addr_set(OpSpecId::ISTHMUS);

        for a in [GPG, SSH, SSHSIG] {
            assert!(fjord.contains(&a), "FJORD missing Tea precompile {a}");
            assert!(isthmus.contains(&a), "ISTHMUS missing Tea precompile {a}");
        }
        assert_ne!(
            fjord, isthmus,
            "per-spec precompile sets must differ — a latched cache would make them equal (TEAO1-145)"
        );

        // Reverse build order yields the same per-spec answer (no latching).
        let isthmus_first = addr_set(OpSpecId::ISTHMUS);
        let fjord_second = addr_set(OpSpecId::FJORD);
        assert_eq!(isthmus_first, isthmus);
        assert_eq!(fjord_second, fjord);
    }
}
