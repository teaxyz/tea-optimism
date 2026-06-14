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
/// of `tea_reth::evm::factory::tea_l1_cost_multiplier`. The pure-math part
/// — masking the 160-bit price out of the packed oracle slot and applying
/// the backup-rate fallback — lives in `tea_l1_cost::multiplier_from_oracle_value`
/// so EL and FPVM consume the same code path and cannot drift on a
/// one-sided refactor.
///
/// Returns `None` if the storage read fails (e.g. account does not exist).
/// op-revm's patched L1-cost path treats `None` as multiplier=1, matching
/// the EL behavior on chains without the Tea oracle.
///
/// Off-Tea chains return `None` unconditionally (TEAO1-132): the multiplier and
/// its 1,500,000× backup fallback must apply only on Tea chains, or generic OP
/// replay in this FPVM would diverge from canonical Optimism. The `is_tea` gate
/// is shared with the EL via `tea_l1_cost` so the two cannot drift.
fn tea_l1_cost_multiplier<DB: Database>(db: &mut DB, chain_id: u64) -> Option<(U256, U256)> {
    if !tea_l1_cost::is_tea(chain_id) {
        return None;
    }
    // TEAO1-165: gate on L1Block.isCustomGasToken — the SAME flag the GasPriceOracle
    // reads — so the FPVM applies the multiplier only on custom-gas-token chains,
    // matching both the EL and the contract. On a non-CGT chain the price slot is
    // never written and must NOT become the 1,500,000× backup; `None` (identity)
    // keeps proof re-execution byte-identical to canonical, non-CGT execution.
    let cgt = db
        .storage(tea_l1_cost::L1_BLOCK_ATTRIBUTES_ADDR, tea_l1_cost::IS_CUSTOM_GAS_TOKEN_SLOT_U256)
        .ok()?;
    if !tea_l1_cost::cgt_enabled(cgt) {
        return None;
    }
    let raw = db
        .storage(tea_l1_cost::GAS_PRICE_ORACLE_ADDR, tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256)
        .ok()?;
    Some(tea_l1_cost::multiplier_from_oracle_value(raw))
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

/// The single selection point for the fault-proof EVM factory, shared by every
/// fault-proof execution path: the interop client replay
/// ([`kona_client::interop::run`]), the single-chain client
/// ([`kona_client::single::run`]), and the interop **host**'s optimistic-block
/// re-execution (`kona-host`'s `L2BlockData` handler).
///
/// Routing all of them through this one constructor is what keeps the host's
/// witness-collection re-execution byte-identical to the client replay it must
/// reproduce. TEAO1-143 was exactly the drift this guards against: the host
/// hand-rolled `alloy_op_evm::OpEvmFactory::default()`, which leaves
/// `ctx.chain.l1_cost_multiplier` unset, so it charged raw OP L1 fees and
/// derived a different header than the [`FpvmOpEvmFactory`] client path. Any
/// future change to fault-proof EVM construction (Tea config, precompiles)
/// lands here once and cannot diverge between host and client.
pub fn fpvm_op_evm_factory<H, O>(hint_writer: H, oracle_reader: O) -> FpvmOpEvmFactory<H, O>
where
    H: HintWriterClient + Clone + Send + Sync,
    O: PreimageOracleClient + Clone + Send + Sync,
{
    FpvmOpEvmFactory::new(hint_writer, oracle_reader)
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
        let chain_id = input.cfg_env.chain_id;
        // Read multiplier before db is moved into the Context.
        let multiplier = tea_l1_cost_multiplier(&mut db, chain_id);
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
        let chain_id = input.cfg_env.chain_id;
        let multiplier = tea_l1_cost_multiplier(&mut db, chain_id);
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
            } else if address == tea_l1_cost::L1_BLOCK_ATTRIBUTES_ADDR
                && index == tea_l1_cost::IS_CUSTOM_GAS_TOKEN_SLOT_U256
            {
                // These tests model a Tea custom-gas-token chain (TEAO1-165 gate).
                Ok(U256::from(1u64))
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
        let (rate, denom) = tea_l1_cost_multiplier(&mut db, tea_l1_cost::TEA_CHAIN_ID).expect("storage read succeeds");
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
        let (rate, denom) = tea_l1_cost_multiplier(&mut db, tea_l1_cost::TEA_CHAIN_ID).expect("storage read succeeds");
        assert_eq!(rate, U256::from(999u64) * tea_l1_cost::WAD);
        assert_eq!(denom, tea_l1_cost::WAD);
    }

    /// 1:1 exchange-rate scenario: oracle returns WAD, so `(WAD, WAD)` gives
    /// `l1_cost * 1 = l1_cost` — the no-op fallback for chains without a
    /// rate oracle.
    #[test]
    fn multiplier_one_to_one() {
        let mut db = OracleDb { slot_value: tea_l1_cost::WAD };
        let (rate, denom) = tea_l1_cost_multiplier(&mut db, tea_l1_cost::TEA_CHAIN_ID).expect("storage read succeeds");
        assert_eq!(rate, tea_l1_cost::WAD);
        assert_eq!(denom, tea_l1_cost::WAD);
    }

    /// A non-1.0 multiplier produces the same scaled cost the EL would
    /// compute. End-to-end check: read storage → extract price → apply.
    #[test]
    fn multiplier_scales_cost_identically_to_el() {
        let oracle_rate = U256::from(42u64) * tea_l1_cost::WAD;
        let mut db = OracleDb { slot_value: oracle_rate };
        let (rate, denom) = tea_l1_cost_multiplier(&mut db, tea_l1_cost::TEA_CHAIN_ID).expect("storage read succeeds");
        let fjord_cost = U256::from(3_203_000u64);
        // EL-side equivalent: tea_l1_cost::apply_tea_exchange_rate(fjord_cost, rate)
        let kona_scaled = fjord_cost * rate / denom;
        let el_scaled = tea_l1_cost::apply_tea_exchange_rate(fjord_cost, rate);
        assert_eq!(kona_scaled, el_scaled);
        assert_eq!(kona_scaled, fjord_cost * U256::from(42u64));
    }

    // ─────────────────────────────────────────── Storage-error path

    /// A `Database` whose `storage()` always returns an error. Used to assert
    /// that `tea_l1_cost_multiplier` propagates failures as `None` (which
    /// op-revm then interprets as multiplier=1 — matches the EL's behavior on
    /// chains where the GasPriceOracle account is missing entirely).
    #[derive(Debug, Default)]
    struct FailingStorageDb;

    /// Tiny error type that satisfies revm's `DBErrorMarker` (which requires
    /// `core::error::Error + Send + Sync + 'static`). Used so we can return
    /// `Err(...)` from `storage()` — `Infallible` cannot be constructed.
    #[derive(Debug)]
    struct FailingStorageErr;

    impl core::fmt::Display for FailingStorageErr {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("storage backend offline")
        }
    }

    impl core::error::Error for FailingStorageErr {}

    impl revm::database_interface::DBErrorMarker for FailingStorageErr {}

    impl Database for FailingStorageDb {
        type Error = FailingStorageErr;

        fn basic(
            &mut self,
            _address: Address,
        ) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
            Ok(None)
        }

        fn code_by_hash(
            &mut self,
            _code_hash: B256,
        ) -> Result<revm::state::Bytecode, Self::Error> {
            Ok(revm::state::Bytecode::default())
        }

        fn storage(&mut self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
            Err(FailingStorageErr)
        }

        fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    /// Storage backend errors → multiplier is `None` (not Some(backup)).
    /// op-revm patch at op-revm-l1-cost-multiplier.patch:55-60 treats `None`
    /// as "no scaling," which is the right behavior when the chain has no
    /// GasPriceOracle.
    #[test]
    fn multiplier_is_none_on_storage_error() {
        let mut db = FailingStorageDb;
        let multiplier = tea_l1_cost_multiplier(&mut db, tea_l1_cost::TEA_CHAIN_ID);
        assert!(
            multiplier.is_none(),
            "storage error must propagate as None, got: {multiplier:?}"
        );
    }

    // ─────────────────────────────────────────── End-to-end create_evm

    /// Macro: build an `FpvmOpEvmFactory` with mock hint/oracle channels
    /// for unit tests. Mirrors `provider.rs` test setup. Uses a macro instead
    /// of a function so type inference flows correctly through the channel
    /// types (which aren't named publicly).
    macro_rules! make_test_factory {
        () => {{
            let hint_chan = kona_preimage::BidirectionalChannel::new().unwrap();
            let preimage_chan = kona_preimage::BidirectionalChannel::new().unwrap();
            let hint_writer = kona_preimage::HintWriter::new(hint_chan.client);
            let oracle_reader = kona_preimage::OracleReader::new(preimage_chan.client);
            FpvmOpEvmFactory::new(hint_writer, oracle_reader)
        }};
    }

    fn make_test_env() -> EvmEnv<OpSpecId> {
        use revm::context::CfgEnv;
        EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(6122)
                .with_spec_and_mainnet_gas_params(OpSpecId::FJORD),
            ..Default::default()
        }
    }

    /// Use revm's `CacheDB` (real DB type, not a hand-rolled stub) to seed the
    /// oracle slot, then run `create_evm` and assert that the multiplier is
    /// observable on the resulting EVM's chain context. This is the integration
    /// proof that the wiring in `create_evm` actually executes.
    #[test]
    fn create_evm_sets_multiplier_from_oracle() {
        use revm::{database::CacheDB, database_interface::EmptyDBTyped};

        let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
        let oracle_rate = U256::from(12345u64) * tea_l1_cost::WAD;
        db.insert_account_storage(
            tea_l1_cost::GAS_PRICE_ORACLE_ADDR,
            tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
            oracle_rate,
        )
        .expect("seed oracle storage");

        let factory = make_test_factory!();
        let evm = <_ as EvmFactory>::create_evm(&factory, db, make_test_env());

        assert_eq!(
            evm.ctx().chain.l1_cost_multiplier,
            Some((oracle_rate, tea_l1_cost::WAD)),
            "create_evm must populate ctx.chain.l1_cost_multiplier from oracle"
        );
    }

    /// Empty CacheDB → storage returns U256::ZERO → backup-rate path engages
    /// inside the factory, propagated all the way to the EVM chain context.
    #[test]
    fn create_evm_uses_backup_when_oracle_missing() {
        use revm::{database::CacheDB, database_interface::EmptyDBTyped};

        let db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
        let factory = make_test_factory!();
        let evm = <_ as EvmFactory>::create_evm(&factory, db, make_test_env());

        let expected = U256::from(tea_l1_cost::BACKUP_TEA_PER_ETH) * tea_l1_cost::WAD;
        assert_eq!(
            evm.ctx().chain.l1_cost_multiplier,
            Some((expected, tea_l1_cost::WAD)),
            "empty DB must produce backup-rate multiplier"
        );
    }

    /// TEAO1-132: on a non-Tea chain the FPVM factory must leave the multiplier
    /// unset (`None`) even with a non-zero oracle slot, so generic OP fault-proof
    /// replay stays byte-identical to canonical Optimism. This mirrors the EL
    /// gate (both call `tea_l1_cost::is_tea`), keeping EL≡FPVM off Tea as well.
    #[test]
    fn create_evm_off_tea_leaves_multiplier_none() {
        use revm::{context::CfgEnv, database::CacheDB, database_interface::EmptyDBTyped};

        let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
        db.insert_account_storage(
            tea_l1_cost::GAS_PRICE_ORACLE_ADDR,
            tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
            U256::from(999u64) * tea_l1_cost::WAD,
        )
        .expect("seed oracle storage");

        // OP mainnet (chain id 10) — not a Tea chain.
        let env = EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(10)
                .with_spec_and_mainnet_gas_params(OpSpecId::FJORD),
            ..Default::default()
        };
        let factory = make_test_factory!();
        let evm = <_ as EvmFactory>::create_evm(&factory, db, env);

        assert_eq!(
            evm.ctx().chain.l1_cost_multiplier,
            None,
            "off-Tea chains must not receive the TEA multiplier in the FPVM (TEAO1-132)"
        );
    }

    /// Same as `create_evm_sets_multiplier_from_oracle` but exercises the
    /// `create_evm_with_inspector` codepath so both factory entry points are
    /// covered by an integration test. Inspector is a NoOpInspector instance.
    #[test]
    fn create_evm_with_inspector_sets_multiplier() {
        use revm::{database::CacheDB, database_interface::EmptyDBTyped, inspector::NoOpInspector};

        let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
        let oracle_rate = U256::from(7u64) * tea_l1_cost::WAD;
        db.insert_account_storage(
            tea_l1_cost::GAS_PRICE_ORACLE_ADDR,
            tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
            oracle_rate,
        )
        .expect("seed oracle storage");

        let factory = make_test_factory!();
        let evm = factory.create_evm_with_inspector(db, make_test_env(), NoOpInspector {});

        assert_eq!(
            evm.ctx().chain.l1_cost_multiplier,
            Some((oracle_rate, tea_l1_cost::WAD)),
            "create_evm_with_inspector must populate ctx.chain.l1_cost_multiplier"
        );
    }

    /// Packed slot value (timestamp upper, price lower 160 bits) — the
    /// extract_price_from_u256 helper must strip the timestamp, and the
    /// factory must propagate the cleaned price. Mirrors the EL's
    /// test_evm_factory_packed_slot_with_timestamp at
    /// tea-reth/tests/evm_integration.rs.
    #[test]
    fn create_evm_handles_packed_slot_with_timestamp() {
        use revm::{database::CacheDB, database_interface::EmptyDBTyped};

        let mut db = CacheDB::<EmptyDBTyped<core::convert::Infallible>>::default();
        // examplePriceRatio: timestamp = 0x67931924, price = 999 * WAD
        let packed = U256::from_be_bytes(alloy_primitives::hex!(
            "00000000000000006793192400000000000000000000003627e8f712373c0000"
        ));
        db.insert_account_storage(
            tea_l1_cost::GAS_PRICE_ORACLE_ADDR,
            tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256,
            packed,
        )
        .expect("seed oracle storage");

        let factory = make_test_factory!();
        let evm = <_ as EvmFactory>::create_evm(&factory, db, make_test_env());

        let expected_price = U256::from(999u64) * tea_l1_cost::WAD;
        assert_eq!(
            evm.ctx().chain.l1_cost_multiplier,
            Some((expected_price, tea_l1_cost::WAD)),
            "factory must strip timestamp from packed slot value"
        );
    }
}
