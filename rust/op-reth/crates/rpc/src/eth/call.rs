use crate::{OpEthApi, OpEthApiError, eth::RpcNodeCore};
use alloy_consensus::transaction::TxHashRef;
use alloy_primitives::B256;
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
        let parent_oracle = if tea_l1_cost::is_tea(chain_id) {
            db.storage(tea_l1_cost::GAS_PRICE_ORACLE_ADDR, tea_l1_cost::LATEST_PRICE_RATIO_SLOT_U256)
                .ok()
        } else {
            None
        };

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
