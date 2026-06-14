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
use tea_precompiles::gpg_verify;
use tea_precompiles::ssh_sig_verify;
use tea_precompiles::ssh_verify;

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
fn tea_l1_cost_multiplier<DB: Database>(
    db: &mut DB,
    chain_id: u64,
    block_number: u64,
) -> Option<(U256, U256)> {
    // Off-Tea chains must never receive the TEA/ETH multiplier or the
    // 1,500,000× backup-rate fallback — applying it would diverge generic OP
    // replay from canonical Optimism (TEAO1-132). `None` means "no scaling"
    // downstream in the patched op-revm L1-cost path.
    if !crate::chainspec::is_tea(chain_id) {
        return None;
    }
    // TEAO1-165: gate on L1Block.isCustomGasToken — the SAME flag the
    // GasPriceOracle reads — so the multiplier applies only on custom-gas-token
    // chains, matching the contract. On a non-CGT chain the price slot is never
    // written; it must NOT become the 1,500,000× backup. Return `None` (identity)
    // so execution charges the standard ETH-denominated L1 fee, consistent with
    // the standalone GasPriceOracleStandard installed on non-CGT chains.
    let cgt =
        db.storage(l1_cost::L1_BLOCK_ATTRIBUTES_ADDR, l1_cost::IS_CUSTOM_GAS_TOKEN_SLOT_U256).ok()?;
    if !l1_cost::cgt_enabled(cgt) {
        return None;
    }
    // TEAO1-178: on transaction-level trace/replay paths the RPC layer replays
    // the block's earlier txs into `db` (mutating the GasPriceOracle slot on
    // blocks where tx0 updates it) and then builds this *fresh* target EVM. To
    // charge the same multiplier the chain did, it records the block-start
    // (parent-state) oracle ratio for this block via `tea_trace_ctx`; consume it
    // here so the target trace matches canonical execution. The DB itself is
    // left untouched, so a contract `SLOAD`ing the oracle slot during the traced
    // tx still observes the post-update value, exactly as on-chain. Normal block
    // execution and `eth_call` record nothing → fall back to the live slot.
    let raw = match tea_trace_ctx::take_parent_oracle(block_number) {
        Some(raw) => raw,
        None => {
            db.storage(l1_cost::GAS_PRICE_ORACLE_ADDR, l1_cost::LATEST_PRICE_RATIO_SLOT_U256).ok()?
        }
    };
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
        let multiplier = tea_l1_cost_multiplier(
            &mut db,
            input.cfg_env.chain_id,
            input.block_env.number.saturating_to(),
        );

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
        let multiplier = tea_l1_cost_multiplier(
            &mut db,
            input.cfg_env.chain_id,
            input.block_env.number.saturating_to(),
        );

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

    // ── Multiplier installation on EVM construction (TEAO1-132/164/167) ──
    //
    // Every EVM the node builds is created through this factory: block
    // execution, eth_call, eth_estimateGas, eth_simulateV1 (via base-reth's
    // `evm_with_env` -> `create_evm`), and trace replay (via
    // `evm_with_env_and_inspector` -> `create_evm_with_inspector`). Proving the
    // factory installs the TEA L1-cost multiplier on a Tea chain (and leaves it
    // `None` off-Tea) proves the multiplier reaches every EVM-based RPC path
    // with no per-RPC override:
    //   - 164 (eth_simulateV1): covered by `create_evm`.
    //   - 167 (state-conditional re-validation): the txpool leg is
    //     `apply_op_checks` (tested in the txpool crate); the payload/execution
    //     leg is this factory.
    //
    // NOTE on TEAO1-178 (trace/replay): installing *a* multiplier on the
    // `create_evm_with_inspector` path is necessary but NOT sufficient — on the
    // replay path the DB handed to the factory is already mutated by replaying
    // tx0's oracle update, so reading the slot here would charge the wrong
    // (post-tx0) multiplier. The real 178 fix records the block-start
    // (parent-state) ratio in `tea_trace_ctx` from the RPC replay override and
    // has the factory consume it; see the `*_uses_recorded_parent_oracle_*` and
    // `*_falls_back_to_db_*` regression tests below.

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
            } else if address == l1_cost::L1_BLOCK_ATTRIBUTES_ADDR
                && index == l1_cost::IS_CUSTOM_GAS_TOKEN_SLOT_U256
            {
                // These tests model a Tea custom-gas-token chain (TEAO1-165 gate).
                Ok(U256::from(1u64))
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

    /// Trace replay builds its EVM via `evm_with_env_and_inspector` ->
    /// `create_evm_with_inspector`. That path must install the oracle-derived
    /// multiplier (necessary for TEAO1-178; the parent-state correctness is
    /// covered by the `*_uses_recorded_parent_oracle_*` regression tests).
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

    /// TEAO1-165: on a Tea chain whose L1Block reports `isCustomGasToken == false`
    /// (the slot is unset → an empty DB reads 0), the EL must NOT apply the
    /// multiplier or the 1,500,000× backup. It returns `None` (identity), so
    /// execution charges the standard ETH-denominated L1 fee — matching the
    /// standalone `GasPriceOracleStandard` the contract side installs on non-CGT
    /// chains, instead of contradicting it.
    #[test]
    fn create_evm_leaves_multiplier_none_when_not_cgt() {
        use revm::database::CacheDB;
        use revm::database_interface::EmptyDBTyped;
        let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
        let evm = TeaEvmFactory.create_evm(db, tea_env());
        assert_eq!(
            evm.ctx().chain.l1_cost_multiplier,
            None,
            "non-CGT chain must not receive the TEA multiplier/backup (TEAO1-165)"
        );
    }

    // ── TEAO1-178 regression: trace/replay must charge the block-start ──────
    // (parent-state) multiplier, not the post-replay (mutated) oracle slot.
    //
    // These tests encode the fix checklist:
    //  - "Carry the original block-scoped `l1_cost_multiplier` into any fresh
    //     target EVM creation": the factory consumes the parent ratio recorded
    //     by the RPC replay override (`tea_trace_ctx`) in preference to the DB.
    //  - "Regression test that replays a non-deposit tx from a block where tx0
    //     updates `GasPriceOracle.latestPrice`": the `OracleDb` here returns the
    //     *mutated* (post-tx0) slot value, standing in for the post-replay DB;
    //     the recorded parent ratio differs, and the EVM must use the parent.

    fn tea_env_at(block_number: u64) -> EvmEnv<OpSpecId> {
        let cfg = revm::context::CfgEnv::new()
            .with_chain_id(crate::chainspec::TEA_CHAIN_ID)
            .with_spec_and_mainnet_gas_params(OpSpecId::default());
        let block_env = revm::context::BlockEnv { number: U256::from(block_number), ..Default::default() };
        EvmEnv { cfg_env: cfg, block_env }
    }

    /// `create_evm` (block-exec / eth_simulateV1 path) must use the recorded
    /// parent ratio over the mutated DB slot when one is published for the block.
    #[test]
    fn create_evm_uses_recorded_parent_oracle_over_mutated_db() {
        let block = 178_001u64;
        let parent_rate = U256::from(3u64) * l1_cost::WAD; // block-start (settled) ratio
        let mutated_rate = U256::from(900u64) * l1_cost::WAD; // post-tx0 slot value in the DB
        let expected = l1_cost::multiplier_from_oracle_value(parent_rate);

        tea_trace_ctx::set_parent_oracle(block, parent_rate);
        let evm =
            TeaEvmFactory.create_evm(OracleDb { slot_value: mutated_rate }, tea_env_at(block));

        assert_eq!(
            evm.ctx().chain.l1_cost_multiplier,
            Some(expected),
            "target EVM must charge the block-start ratio, not the post-replay slot",
        );
        assert_ne!(
            evm.ctx().chain.l1_cost_multiplier,
            Some(l1_cost::multiplier_from_oracle_value(mutated_rate)),
            "must NOT charge the mutated post-tx0 slot value (the TEAO1-178 bug)",
        );
    }

    /// Same for the trace/replay EVM construction path itself
    /// (`create_evm_with_inspector`), which is where TEAO1-178 manifests.
    #[test]
    fn create_evm_with_inspector_uses_recorded_parent_oracle_over_mutated_db() {
        let block = 178_002u64;
        let parent_rate = U256::from(5u64) * l1_cost::WAD;
        let mutated_rate = U256::from(1_234u64) * l1_cost::WAD;
        let expected = l1_cost::multiplier_from_oracle_value(parent_rate);

        tea_trace_ctx::set_parent_oracle(block, parent_rate);
        let evm = TeaEvmFactory.create_evm_with_inspector(
            OracleDb { slot_value: mutated_rate },
            tea_env_at(block),
            NoOpInspector,
        );

        assert_eq!(evm.ctx().chain.l1_cost_multiplier, Some(expected));
    }

    /// No record (normal block execution / `eth_call`, or a record for a
    /// different block) → the factory falls back to the live DB slot, exactly as
    /// before, so the fix is inert outside the trace/replay paths.
    #[test]
    fn create_evm_falls_back_to_db_without_matching_record() {
        let block = 178_003u64;
        let db_rate = U256::from(11u64) * l1_cost::WAD;
        let expected_from_db = l1_cost::multiplier_from_oracle_value(db_rate);

        // A record for a *different* block must be ignored (and cleared) — the
        // block-keyed handoff prevents a stale entry from leaking into this EVM.
        tea_trace_ctx::set_parent_oracle(block + 1, U256::from(777u64) * l1_cost::WAD);
        let evm = TeaEvmFactory.create_evm(OracleDb { slot_value: db_rate }, tea_env_at(block));
        assert_eq!(
            evm.ctx().chain.l1_cost_multiplier,
            Some(expected_from_db),
            "without a matching record the live DB slot is used",
        );

        // The mismatched record was consumed/cleared, so it cannot leak to a
        // later construction either.
        let evm2 =
            TeaEvmFactory.create_evm(OracleDb { slot_value: db_rate }, tea_env_at(block + 1));
        assert_eq!(evm2.ctx().chain.l1_cost_multiplier, Some(expected_from_db));
    }
}
