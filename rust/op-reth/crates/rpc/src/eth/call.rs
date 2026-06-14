use crate::{OpEthApi, OpEthApiError, eth::RpcNodeCore};
use alloy_consensus::transaction::TxHashRef;
use alloy_primitives::{B256, U256};
use reth_evm::{ConfigureEvm, Evm, EvmEnvFor, execute::ProviderError};
use reth_primitives_traits::Recovered;
use reth_revm::db::bal::EvmDatabaseError;
use reth_rpc_eth_api::{
    FromEvmError, RpcConvert,
    helpers::{Call, EthCall, estimate::EstimateCall},
};
use reth_storage_api::ProviderTx;
use revm::{Database, DatabaseCommit, context::Block};

impl<N, Rpc> EthCall for OpEthApi<N, Rpc>
where
    N: RpcNodeCore,
    OpEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = OpEthApiError, Evm = N::Evm>,
{
}

impl<N, Rpc> EstimateCall for OpEthApi<N, Rpc>
where
    N: RpcNodeCore,
    OpEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = OpEthApiError, Evm = N::Evm>,
{
}

impl<N, Rpc> Call for OpEthApi<N, Rpc>
where
    N: RpcNodeCore,
    OpEthApiError: FromEvmError<N::Evm>,
    Rpc: RpcConvert<Primitives = N::Primitives, Error = OpEthApiError, Evm = N::Evm>,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.eth_api.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.eth_api.max_simulate_blocks()
    }

    #[inline]
    fn evm_memory_limit(&self) -> u64 {
        self.inner.eth_api.evm_memory_limit()
    }

    /// Replays the block's transactions up to `target_tx_hash`, recording the
    /// block-start (parent-state) GasPriceOracle ratio for the Tea EVM factory
    /// to apply to the *target* transaction's fresh EVM (TEAO1-178).
    ///
    /// This default method is invoked by exactly the transaction-level
    /// trace/replay paths — `trace_transaction`, `trace_replayTransaction`,
    /// `debug_traceTransaction`, and otterscan — which replay the earlier
    /// transactions into `db` and then build a brand-new EVM for the target tx.
    /// On a Tea chain whose first (L1-attributes) transaction updates the oracle
    /// price-ratio slot, that fresh EVM would otherwise re-read the slot as
    /// mutated by the replay and charge a different `l1_cost_multiplier` than the
    /// chain charged, so trace fee/balance results would diverge from canonical
    /// execution (which freezes the multiplier at the block-start value).
    ///
    /// We capture the slot value *before* replaying — `db` is still the parent
    /// post-state plus pre-execution changes, which never touch the oracle — and
    /// publish it via `tea_trace_ctx` only *after* the upstream replay, so the
    /// replay's own EVM reads the parent ratio straight from its (still-parent)
    /// DB and never consumes the record meant for the target EVM. The factory
    /// consumes it (block-keyed, exactly once) when building the target EVM and
    /// leaves the DB untouched, so an in-transaction `SLOAD` of the slot still
    /// observes the post-update value, exactly as on-chain. Off-Tea chains and
    /// any state-read miss record nothing → the factory falls back to the live
    /// slot, identical to upstream behavior.
    fn replay_transactions_until<'a, DB, I>(
        &self,
        db: &mut DB,
        evm_env: EvmEnvFor<Self::Evm>,
        transactions: I,
        target_tx_hash: B256,
    ) -> Result<usize, Self::Error>
    where
        DB: Database<Error = EvmDatabaseError<ProviderError>> + DatabaseCommit + core::fmt::Debug,
        I: IntoIterator<Item = Recovered<&'a ProviderTx<Self::Provider>>>,
    {
        let chain_id = evm_env.cfg_env.chain_id;
        let block_number: u64 = evm_env.block_env.number().saturating_to();
        // Capture the block-start oracle ratio *before* the replay loop mutates
        // `db`. Extracted into a free fn so the slot/address/`is_tea` gate are
        // unit-testable against a mock DB without a full Eth API (TEAO1-178).
        let parent_oracle = capture_block_start_oracle(db, chain_id);

        // Upstream replay: execute every transaction before the target into `db`.
        let mut evm = self.evm_config().evm_with_env(db, evm_env);
        let mut index = 0;
        for tx in transactions {
            if *tx.tx_hash() == target_tx_hash {
                break;
            }
            let tx_env = self.evm_config().tx_env(tx);
            evm.transact_commit(tx_env).map_err(Self::Error::from_evm_err)?;
            index += 1;
        }
        drop(evm);

        // Record after replay (see method doc): the factory consumes this when it
        // builds the target EVM, so it charges the block-start multiplier.
        if let Some(raw) = parent_oracle {
            tea_trace_ctx::set_parent_oracle(block_number, raw);
        }

        Ok(index)
    }
}

/// Reads the block-start (parent-state) GasPriceOracle price-ratio slot that the
/// target trace/replay EVM must be charged with, or `None` off-Tea or on a
/// state-read miss (TEAO1-178).
///
/// Pulled out of [`Call::replay_transactions_until`] so the load-bearing details
/// — the `is_tea` chain gate, and reading the *exact* oracle address + price-ratio
/// slot — are unit-testable against a mock `Database`, without standing up a full
/// `OpEthApi`. The caller invokes this *before* replaying the block's earlier
/// transactions, so `db` is still the parent post-state (pre-execution changes
/// never touch the oracle slot) and the returned value is the block-start ratio.
/// Off-Tea / on a miss it returns `None`, so the factory falls back to the live
/// slot — identical to upstream behavior.
pub(crate) fn capture_block_start_oracle<DB>(db: &mut DB, chain_id: u64) -> Option<U256>
where
    DB: Database,
{
    if !tea_l1_cost::is_tea(chain_id) {
        return None;
    }
    db.storage(tea_l1_cost::GAS_PRICE_ORACLE_ADDR, tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256).ok()
}

#[cfg(test)]
mod tests {
    use super::capture_block_start_oracle;
    use alloy_primitives::{Address, B256, U256};

    const TEA_CHAIN_ID: u64 = 6122;
    const OFF_TEA_CHAIN_ID: u64 = 10; // OP mainnet — not a Tea chain.

    /// A `Database` stub returning a fixed value for the GasPriceOracle's
    /// `LATEST_PRICE_RATIO_SLOT` and defaults elsewhere — mirrors the factory-side
    /// `OracleDb` so both ends of the TEAO1-178 handoff exercise the same shape.
    #[derive(Debug, Default)]
    struct OracleDb {
        slot_value: U256,
    }

    impl revm::Database for OracleDb {
        type Error = core::convert::Infallible;

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
            Ok(B256::ZERO)
        }
    }

    /// On a Tea chain the capture reads the oracle price-ratio slot verbatim —
    /// this is the parent-state ratio the target EVM gets charged.
    #[test]
    fn captures_oracle_slot_on_tea_chain() {
        let rate = U256::from(42u64) * tea_l1_cost::WAD;
        let mut db = OracleDb { slot_value: rate };
        assert_eq!(capture_block_start_oracle(&mut db, TEA_CHAIN_ID), Some(rate));
    }

    /// A zero slot is still recorded (the factory maps it to the backup rate, the
    /// same as admission/execution) — `None` is reserved for off-Tea / read miss.
    #[test]
    fn captures_zero_slot_on_tea_chain() {
        let mut db = OracleDb { slot_value: U256::ZERO };
        assert_eq!(capture_block_start_oracle(&mut db, TEA_CHAIN_ID), Some(U256::ZERO));
    }

    /// Off-Tea the gate short-circuits and records nothing, so the factory keeps
    /// upstream behavior (reads the live slot, no parent override).
    #[test]
    fn records_nothing_off_tea_chain() {
        let rate = U256::from(42u64) * tea_l1_cost::WAD;
        let mut db = OracleDb { slot_value: rate };
        assert_eq!(capture_block_start_oracle(&mut db, OFF_TEA_CHAIN_ID), None);
    }
}
