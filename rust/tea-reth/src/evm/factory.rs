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

    // ── Multiplier installation on EVM construction (TEAO1-132/164/167/178) ──
    //
    // Every EVM the node builds is created through this factory: block
    // execution, eth_call, eth_estimateGas, eth_simulateV1 (via base-reth's
    // `evm_with_env` -> `create_evm`), and trace replay (via
    // `evm_with_env_and_inspector` -> `create_evm_with_inspector`). Proving the
    // factory installs the TEA L1-cost multiplier on a Tea chain (and leaves it
    // `None` off-Tea) therefore proves the multiplier reaches every EVM-based
    // RPC path with no per-RPC override:
    //   - 164 (eth_simulateV1): covered by `create_evm`.
    //   - 178 (trace replay):   covered by `create_evm_with_inspector`; a trace
    //                           thus reproduces exactly what the EL charged.
    //   - 167 (state-conditional re-validation): the txpool leg is
    //     `apply_op_checks` (tested in the txpool crate); the payload/execution
    //     leg is this factory.

    /// A `Database` stub returning a fixed value for the GasPriceOracle's
    /// `LATEST_PRICE_RATIO_SLOT` and defaults elsewhere — mirrors the kona
    /// FPVM-side `OracleDb` so both sides exercise the same construction path.
    #[derive(Debug, Default)]
    struct OracleDb {
        slot_value: U256,
    }

    // Implement the underlying `revm::Database`; `alloy_evm::Database` (the
    // bound `create_evm` requires) is then satisfied by its blanket impl.
    impl revm::Database for OracleDb {
        type Error = core::convert::Infallible;

        fn basic(
            &mut self,
            _address: alloy_primitives::Address,
        ) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
            Ok(None)
        }

        fn code_by_hash(
            &mut self,
            _code_hash: alloy_primitives::B256,
        ) -> Result<revm::state::Bytecode, Self::Error> {
            Ok(revm::state::Bytecode::default())
        }

        fn storage(
            &mut self,
            address: alloy_primitives::Address,
            index: U256,
        ) -> Result<U256, Self::Error> {
            if address == l1_cost::GAS_PRICE_ORACLE_ADDR
                && index == l1_cost::LATEST_PRICE_RATIO_SLOT_U256
            {
                Ok(self.slot_value)
            } else {
                Ok(U256::ZERO)
            }
        }

        fn block_hash(&mut self, _number: u64) -> Result<alloy_primitives::B256, Self::Error> {
            Ok(alloy_primitives::B256::ZERO)
        }
    }

    fn tea_env() -> EvmEnv<OpSpecId> {
        let cfg = revm::context::CfgEnv::new()
            .with_chain_id(crate::chainspec::TEA_CHAIN_ID)
            .with_spec_and_mainnet_gas_params(OpSpecId::default());
        EvmEnv { cfg_env: cfg, ..Default::default() }
    }

    /// TEAO1-164: eth_simulateV1 builds its EVM via `evm_with_env` ->
    /// `create_evm`. On a Tea chain the constructed EVM must carry the
    /// oracle-derived multiplier so the simulation charges the real L1 cost.
    #[test]
    fn create_evm_installs_multiplier_on_tea_chain() {
        let oracle_rate = U256::from(42u64) * l1_cost::WAD;
        let expected = l1_cost::multiplier_from_oracle_value(oracle_rate);
        let evm = TeaEvmFactory.create_evm(OracleDb { slot_value: oracle_rate }, tea_env());
        assert_eq!(evm.ctx().chain.l1_cost_multiplier, Some(expected));
    }

    /// TEAO1-178: trace replay builds its EVM via `evm_with_env_and_inspector`
    /// -> `create_evm_with_inspector`. That path must install the same
    /// multiplier so a trace faithfully reproduces what the EL charged.
    #[test]
    fn create_evm_with_inspector_installs_multiplier_on_tea_chain() {
        let oracle_rate = U256::from(7u64) * l1_cost::WAD;
        let expected = l1_cost::multiplier_from_oracle_value(oracle_rate);
        let evm = TeaEvmFactory.create_evm_with_inspector(
            OracleDb { slot_value: oracle_rate },
            tea_env(),
            NoOpInspector,
        );
        assert_eq!(evm.ctx().chain.l1_cost_multiplier, Some(expected));
    }

    /// Off-Tea chains must never receive the multiplier (TEAO1-132); the same
    /// RPC paths then compute L1 cost as canonical Optimism.
    #[test]
    fn create_evm_leaves_multiplier_none_off_tea() {
        let cfg = revm::context::CfgEnv::new()
            .with_chain_id(1)
            .with_spec_and_mainnet_gas_params(OpSpecId::default());
        let env = EvmEnv { cfg_env: cfg, ..Default::default() };
        let evm = TeaEvmFactory
            .create_evm(OracleDb { slot_value: U256::from(42u64) * l1_cost::WAD }, env);
        assert_eq!(evm.ctx().chain.l1_cost_multiplier, None);
    }
}
