//! [`EvmFactory`] implementation for the EVM in the FPVM environment.

use super::precompiles::OpFpvmPrecompiles;
use alloy_evm::{Database, EvmEnv, EvmFactory};
use alloy_op_evm::OpEvm;
use alloy_primitives::U256;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use op_revm::{
    DefaultOp, OpContext, OpEvm as RevmOpEvm, OpHaltReason, OpSpecId, OpTransaction,
    OpTransactionError,
};
use revm::{
    Context, Inspector,
    context::{BlockEnv, Evm as RevmEvm, FrameStack, TxEnv, result::EVMError},
    handler::instructions::EthInstructions,
    inspector::NoOpInspector,
};

/// Reads the TEA/ETH exchange rate from the on-chain GasPriceOracle and
/// returns the L1 cost multiplier as `(numerator, denominator)`. Mirror
/// of `tea_reth::evm::factory::tea_l1_cost_multiplier`; both call sites
/// share the constants via the `tea-l1-cost` crate so the EL and FPVM
/// cannot drift.
///
/// Returns `None` if the storage read fails (e.g. account does not exist).
/// op-revm's patched L1-cost path treats `None` as multiplier=1, matching
/// the EL behavior on chains without the Tea oracle.
fn tea_l1_cost_multiplier<DB: Database>(db: &mut DB) -> Option<(U256, U256)> {
    let raw = db
        .storage(tea_l1_cost::GAS_PRICE_ORACLE_ADDR, tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256)
        .ok()?;
    let price = tea_l1_cost::extract_price_from_u256(raw);
    let rate = tea_l1_cost::tea_per_wad_eth_or_backup(price);
    Some((rate, tea_l1_cost::WAD))
}

/// Factory producing [`OpEvm`]s with FPVM-accelerated precompile overrides enabled.
#[derive(Debug, Clone)]
pub struct FpvmOpEvmFactory<H, O> {
    /// The hint writer.
    hint_writer: H,
    /// The oracle reader.
    oracle_reader: O,
}

impl<H, O> FpvmOpEvmFactory<H, O>
where
    H: HintWriterClient + Clone + Send + Sync,
    O: PreimageOracleClient + Clone + Send + Sync,
{
    /// Creates a new [`FpvmOpEvmFactory`].
    pub fn new(hint_writer: H, oracle_reader: O) -> Self {
        Self { hint_writer, oracle_reader }
    }

    /// Returns a reference to the inner [`HintWriterClient`].
    pub fn hint_writer(&self) -> &H {
        &self.hint_writer
    }

    /// Returns a reference to the inner [`PreimageOracleClient`].
    pub fn oracle_reader(&self) -> &O {
        &self.oracle_reader
    }
}

impl<H, O> EvmFactory for FpvmOpEvmFactory<H, O>
where
    H: HintWriterClient + Clone + Send + Sync + 'static,
    O: PreimageOracleClient + Clone + Send + Sync + 'static,
{
    type Evm<DB: Database, I: Inspector<OpContext<DB>>> = OpEvm<DB, I, OpFpvmPrecompiles<H, O>>;
    type Context<DB: Database> = OpContext<DB>;
    type Tx = OpTransaction<TxEnv>;
    type Error<DBError: core::error::Error + Send + Sync + 'static> =
        EVMError<DBError, OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;
    type Precompiles = OpFpvmPrecompiles<H, O>;
    type BlockEnv = BlockEnv;

    fn create_evm<DB: Database>(
        &self,
        mut db: DB,
        input: EvmEnv<OpSpecId>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let spec_id = *input.spec_id();
        // Read multiplier before db is moved into the Context.
        let multiplier = tea_l1_cost_multiplier(&mut db);
        let mut ctx =
            Context::op().with_db(db).with_block(input.block_env).with_cfg(input.cfg_env);
        ctx.chain.l1_cost_multiplier = multiplier;
        let revm_evm = RevmOpEvm(RevmEvm {
            ctx,
            inspector: NoOpInspector {},
            instruction: EthInstructions::new_mainnet(),
            precompiles: OpFpvmPrecompiles::new_with_spec(
                spec_id,
                self.hint_writer.clone(),
                self.oracle_reader.clone(),
            ),
            frame_stack: FrameStack::new(),
        });

        OpEvm::new(revm_evm, false)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        mut db: DB,
        input: EvmEnv<OpSpecId>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let spec_id = *input.spec_id();
        let multiplier = tea_l1_cost_multiplier(&mut db);
        let mut ctx =
            Context::op().with_db(db).with_block(input.block_env).with_cfg(input.cfg_env);
        ctx.chain.l1_cost_multiplier = multiplier;
        let revm_evm = RevmOpEvm(RevmEvm {
            ctx,
            inspector,
            instruction: EthInstructions::new_mainnet(),
            precompiles: OpFpvmPrecompiles::new_with_spec(
                spec_id,
                self.hint_writer.clone(),
                self.oracle_reader.clone(),
            ),
            frame_stack: FrameStack::new(),
        });

        OpEvm::new(revm_evm, true)
    }
}

#[cfg(test)]
mod tests {
    //! Parity tests for `tea_l1_cost_multiplier`.
    //!
    //! The same `(rate, denominator)` semantics are exercised by the EL via
    //! `tea_reth::evm::factory::tea_l1_cost_multiplier`. These tests pin the
    //! FPVM side against the underlying `tea-l1-cost` helpers so a refactor
    //! that breaks EL/FPVM parity is caught at unit-test time.
    //!
    //! Constants are not duplicated; they come from `tea_l1_cost`, the same
    //! crate the EL consumes. A drifting constant would fail to compile both
    //! sides simultaneously, not just one.
    use super::*;
    use alloy_primitives::{Address, B256, U256};
    use revm::{database::EmptyDB, database_interface::Database};

    /// A `Database` stub that returns a single fixed value for the
    /// GasPriceOracle's `LATEST_PRICE_RATIO_SLOT` and `Default::default()`
    /// for everything else. Lets us exercise `tea_l1_cost_multiplier` end
    /// to end without spinning up a real `revm` state DB.
    #[derive(Debug, Default)]
    struct OracleDb {
        slot_value: U256,
    }

    impl Database for OracleDb {
        type Error = <EmptyDB as Database>::Error;

        fn basic(
            &mut self,
            _address: Address,
        ) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
            EmptyDB::default().basic(_address)
        }

        fn code_by_hash(
            &mut self,
            _code_hash: B256,
        ) -> Result<revm::state::Bytecode, Self::Error> {
            EmptyDB::default().code_by_hash(_code_hash)
        }

        fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
            if address == tea_l1_cost::GAS_PRICE_ORACLE_ADDR
                && index == tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256
            {
                Ok(self.slot_value)
            } else {
                Ok(U256::ZERO)
            }
        }

        fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
            EmptyDB::default().block_hash(_number)
        }
    }

    /// Oracle returns zero → multiplier falls back to BACKUP_TEA_PER_ETH * WAD.
    /// Mirrors `tea_l1_cost::tests::test_backup_rate`.
    #[test]
    fn multiplier_backup_when_oracle_zero() {
        let mut db = OracleDb { slot_value: U256::ZERO };
        let (rate, denom) = tea_l1_cost_multiplier(&mut db).expect("storage read succeeds");
        assert_eq!(rate, U256::from(tea_l1_cost::BACKUP_TEA_PER_ETH) * tea_l1_cost::WAD);
        assert_eq!(denom, tea_l1_cost::WAD);
    }

    /// Oracle slot at the canonical Go-test "examplePriceRatio" (999 * WAD)
    /// produces `(999 * WAD, WAD)`, matching the EL.
    #[test]
    fn multiplier_matches_oracle_example_price_ratio() {
        let slot_bytes = alloy_primitives::hex!(
            "00000000000000006793192400000000000000000000003627e8f712373c0000"
        );
        let mut db = OracleDb { slot_value: U256::from_be_bytes(slot_bytes) };
        let (rate, denom) = tea_l1_cost_multiplier(&mut db).expect("storage read succeeds");
        assert_eq!(rate, U256::from(999u64) * tea_l1_cost::WAD);
        assert_eq!(denom, tea_l1_cost::WAD);
    }

    /// 1:1 exchange-rate scenario: oracle returns WAD, so `(WAD, WAD)` gives
    /// `l1_cost * 1 = l1_cost` — the no-op fallback for chains without a
    /// rate oracle.
    #[test]
    fn multiplier_one_to_one() {
        let mut db = OracleDb { slot_value: tea_l1_cost::WAD };
        let (rate, denom) = tea_l1_cost_multiplier(&mut db).expect("storage read succeeds");
        assert_eq!(rate, tea_l1_cost::WAD);
        assert_eq!(denom, tea_l1_cost::WAD);
    }

    /// A non-1.0 multiplier produces the same scaled cost the EL would
    /// compute. End-to-end check: read storage → extract price → apply.
    #[test]
    fn multiplier_scales_cost_identically_to_el() {
        let oracle_rate = U256::from(42u64) * tea_l1_cost::WAD;
        let mut db = OracleDb { slot_value: oracle_rate };
        let (rate, denom) = tea_l1_cost_multiplier(&mut db).expect("storage read succeeds");
        let fjord_cost = U256::from(3_203_000u64);
        // EL-side equivalent: tea_l1_cost::apply_tea_exchange_rate(fjord_cost, rate)
        let kona_scaled = fjord_cost * rate / denom;
        let el_scaled = tea_l1_cost::apply_tea_exchange_rate(fjord_cost, rate);
        assert_eq!(kona_scaled, el_scaled);
        assert_eq!(kona_scaled, fjord_cost * U256::from(42u64));
    }
}
