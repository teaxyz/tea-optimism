use crate::{InvalidCrossTx, OpPooledTx, supervisor::SupervisorClient};
use alloy_consensus::{BlockHeader, Transaction};
use op_revm::L1BlockInfo;
use parking_lot::RwLock;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_evm::ConfigureEvm;
use reth_optimism_evm::RethL1BlockInfo;
use reth_optimism_forks::OpHardforks;
use reth_primitives_traits::{
    Block, BlockBody, BlockTy, GotExpected, SealedBlock,
    transaction::error::InvalidTransactionError,
};
use reth_storage_api::{AccountInfoReader, BlockReaderIdExt, StateProviderFactory};
use reth_transaction_pool::{
    EthPoolTransaction, EthTransactionValidator, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidator, error::InvalidPoolTransactionError,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// The interval for which we check transaction against supervisor, 1 hour.
const TRANSACTION_VALIDITY_WINDOW_SECS: u64 = 3600;

/// Tracks additional infos for the current block.
#[derive(Debug, Default)]
pub struct OpL1BlockInfo {
    /// The current L1 block info.
    l1_block_info: RwLock<L1BlockInfo>,
    /// Current block timestamp.
    timestamp: AtomicU64,
}

impl OpL1BlockInfo {
    /// Returns the most recent timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp.load(Ordering::Relaxed)
    }
}

/// Validator for Optimism transactions.
#[derive(Debug, Clone)]
pub struct OpTransactionValidator<Client, Tx, Evm> {
    /// The type that performs the actual validation.
    inner: Arc<EthTransactionValidator<Client, Tx, Evm>>,
    /// Additional block info required for validation.
    block_info: Arc<OpL1BlockInfo>,
    /// If true, ensure that the transaction's sender has enough balance to cover the L1 gas fee
    /// derived from the tracked L1 block info that is extracted from the first transaction in the
    /// L2 block.
    require_l1_data_gas_fee: bool,
    /// Client used to check transaction validity with op-supervisor
    supervisor_client: Option<SupervisorClient>,
    /// tracks activated forks relevant for transaction validation
    fork_tracker: Arc<OpForkTracker>,
}

impl<Client, Tx, Evm> OpTransactionValidator<Client, Tx, Evm> {
    /// Returns the configured chain spec
    pub fn chain_spec(&self) -> Arc<Client::ChainSpec>
    where
        Client: ChainSpecProvider,
    {
        self.inner.chain_spec()
    }

    /// Returns the configured client
    pub fn client(&self) -> &Client {
        self.inner.client()
    }

    /// Returns the current block timestamp.
    fn block_timestamp(&self) -> u64 {
        self.block_info.timestamp.load(Ordering::Relaxed)
    }

    /// Whether to ensure that the transaction's sender has enough balance to also cover the L1 gas
    /// fee.
    pub fn require_l1_data_gas_fee(self, require_l1_data_gas_fee: bool) -> Self {
        Self { require_l1_data_gas_fee, ..self }
    }

    /// Returns whether this validator also requires the transaction's sender to have enough balance
    /// to cover the L1 gas fee.
    pub const fn requires_l1_data_gas_fee(&self) -> bool {
        self.require_l1_data_gas_fee
    }
}

impl<Client, Tx, Evm> OpTransactionValidator<Client, Tx, Evm>
where
    Client:
        ChainSpecProvider<ChainSpec: OpHardforks> + StateProviderFactory + BlockReaderIdExt + Sync,
    Tx: EthPoolTransaction + OpPooledTx,
    Evm: ConfigureEvm,
{
    /// Create a new [`OpTransactionValidator`].
    pub fn new(inner: EthTransactionValidator<Client, Tx, Evm>) -> Self {
        let this = Self::with_block_info(inner, OpL1BlockInfo::default());
        if let Ok(Some(block)) =
            this.inner.client().block_by_number_or_tag(alloy_eips::BlockNumberOrTag::Latest)
        {
            // genesis block has no txs, so we can't extract L1 info, we set the block info to empty
            // so that we will accept txs into the pool before the first block
            if block.header().number() == 0 {
                this.block_info.timestamp.store(block.header().timestamp(), Ordering::Relaxed);
            } else {
                this.update_l1_block_info(block.header(), block.body().transactions().first());
            }
        }

        this
    }

    /// Create a new [`OpTransactionValidator`] with the given [`OpL1BlockInfo`].
    pub fn with_block_info(
        inner: EthTransactionValidator<Client, Tx, Evm>,
        block_info: OpL1BlockInfo,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            block_info: Arc::new(block_info),
            require_l1_data_gas_fee: true,
            supervisor_client: None,
            fork_tracker: Arc::new(OpForkTracker { interop: AtomicBool::from(false) }),
        }
    }

    /// Set the supervisor client and safety level
    pub fn with_supervisor(mut self, supervisor_client: SupervisorClient) -> Self {
        self.supervisor_client = Some(supervisor_client);
        self
    }

    /// Update the L1 block info for the given header and system transaction, if any.
    ///
    /// Note: this supports optional system transaction, in case this is used in a dev setup
    pub fn update_l1_block_info<H, T>(&self, header: &H, tx: Option<&T>)
    where
        H: BlockHeader,
        T: Transaction,
    {
        self.block_info.timestamp.store(header.timestamp(), Ordering::Relaxed);

        if let Some(Ok(l1_block_info)) = tx.map(reth_optimism_evm::extract_l1_info_from_tx) {
            *self.block_info.l1_block_info.write() = l1_block_info;
        }

        if self.chain_spec().is_interop_active_at_timestamp(header.timestamp()) {
            self.fork_tracker.interop.store(true, Ordering::Relaxed);
        }
    }

    /// Validates a single transaction.
    ///
    /// See also [`TransactionValidator::validate_transaction`]
    ///
    /// This behaves the same as [`OpTransactionValidator::validate_one_with_state`], but creates
    /// a new state provider internally.
    pub async fn validate_one(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
    ) -> TransactionValidationOutcome<Tx> {
        self.validate_one_with_state(origin, transaction, &mut None).await
    }

    /// Validates a single transaction with a provided state provider.
    ///
    /// This allows reusing the same state provider across multiple transaction validations.
    ///
    /// See also [`TransactionValidator::validate_transaction`]
    ///
    /// This behaves the same as [`EthTransactionValidator::validate_one_with_state`], but in
    /// addition applies OP validity checks:
    /// - ensures tx is not eip4844
    /// - ensures cross chain transactions are valid wrt locally configured safety level
    /// - ensures that the account has enough balance to cover the L1 gas cost
    pub async fn validate_one_with_state(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
        state: &mut Option<Box<dyn AccountInfoReader + Send>>,
    ) -> TransactionValidationOutcome<Tx> {
        if transaction.is_eip4844() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::TxTypeNotSupported.into(),
            );
        }

        // Interop cross tx validation
        match self.is_valid_cross_tx(&transaction).await {
            Some(Err(err)) => {
                let err = match err {
                    InvalidCrossTx::CrossChainTxPreInterop => {
                        InvalidTransactionError::TxTypeNotSupported.into()
                    }
                    err => InvalidPoolTransactionError::Other(Box::new(err)),
                };
                return TransactionValidationOutcome::Invalid(transaction, err);
            }
            Some(Ok(_)) => {
                // valid interop tx
                transaction.set_interop_deadline(
                    self.block_timestamp() + TRANSACTION_VALIDITY_WINDOW_SECS,
                );
            }
            _ => {}
        }

        let outcome = self.inner.validate_one_with_state(origin, transaction, state);

        self.apply_op_checks(outcome)
    }

    /// Scale a raw L1 data fee by the chain's TEA/ETH multiplier read from the
    /// GasPriceOracle price-ratio slot — the same `tea_l1_cost` math and `is_tea`
    /// chain gate the EVM uses for `l1_cost_multiplier`. Off-Tea chains and any
    /// state-read miss fall back to the unscaled cost, so the pool's affordability
    /// check stays in lockstep with what the EL charges at inclusion.
    /// TEAO1-175 / 186 / 151.
    fn tea_scale_l1_cost(&self, raw_l1_cost: alloy_primitives::U256) -> alloy_primitives::U256 {
        if !tea_l1_cost::is_tea(self.chain_spec().chain().id()) {
            return raw_l1_cost;
        }
        let Ok(state) = self.client().latest() else { return raw_l1_cost };
        let raw = state
            .storage(tea_l1_cost::GAS_PRICE_ORACLE_ADDR, tea_l1_cost::LATEST_PRICE_RATIO_SLOT)
            .ok()
            .flatten()
            .unwrap_or_default();
        scale_l1_cost_by_oracle(raw_l1_cost, raw)
    }

    /// Performs the necessary opstack specific checks based on top of the regular eth outcome.
    fn apply_op_checks(
        &self,
        outcome: TransactionValidationOutcome<Tx>,
    ) -> TransactionValidationOutcome<Tx> {
        if !self.requires_l1_data_gas_fee() {
            // no need to check L1 gas fee
            return outcome;
        }
        // ensure that the account has enough balance to cover the L1 gas cost
        if let TransactionValidationOutcome::Valid {
            balance,
            state_nonce,
            transaction: valid_tx,
            propagate,
            bytecode_hash,
            authorities,
        } = outcome
        {
            let mut l1_block_info = self.block_info.l1_block_info.read().clone();

            let encoded = valid_tx.transaction().encoded_2718();

            let cost_addition = match l1_block_info.l1_tx_data_fee(
                self.chain_spec(),
                self.block_timestamp(),
                &encoded,
                false,
            ) {
                Ok(cost) => cost,
                Err(err) => {
                    return TransactionValidationOutcome::Error(*valid_tx.hash(), Box::new(err));
                }
            };
            // TEA: scale the raw L1 data fee by the GasPriceOracle TEA/ETH multiplier so the
            // pool admits a tx only if it can pay what execution will charge at inclusion
            // (same `tea_l1_cost` math + `is_tea` gate as the EVM). TEAO1-175 / 186 / 151.
            let cost_addition = self.tea_scale_l1_cost(cost_addition);
            let cost = valid_tx.transaction().cost().saturating_add(cost_addition);

            // Checks for max cost
            if cost > balance {
                return TransactionValidationOutcome::Invalid(
                    valid_tx.into_transaction(),
                    InvalidTransactionError::InsufficientFunds(
                        GotExpected { got: balance, expected: cost }.into(),
                    )
                    .into(),
                );
            }

            return TransactionValidationOutcome::Valid {
                balance,
                state_nonce,
                transaction: valid_tx,
                propagate,
                bytecode_hash,
                authorities,
            };
        }
        outcome
    }

    /// Wrapper for is valid cross tx
    pub async fn is_valid_cross_tx(&self, tx: &Tx) -> Option<Result<(), InvalidCrossTx>> {
        // We don't need to check for deposit transaction in here, because they won't come from
        // txpool
        self.supervisor_client
            .as_ref()?
            .is_valid_cross_tx(
                tx.access_list(),
                tx.hash(),
                self.block_info.timestamp.load(Ordering::Relaxed),
                Some(TRANSACTION_VALIDITY_WINDOW_SECS),
                self.fork_tracker.is_interop_activated(),
            )
            .await
    }
}

impl<Client, Tx, Evm> TransactionValidator for OpTransactionValidator<Client, Tx, Evm>
where
    Client:
        ChainSpecProvider<ChainSpec: OpHardforks> + StateProviderFactory + BlockReaderIdExt + Sync,
    Tx: EthPoolTransaction + OpPooledTx,
    Evm: ConfigureEvm,
{
    type Transaction = Tx;
    type Block = BlockTy<Evm::Primitives>;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        self.validate_one(origin, transaction).await
    }

    fn on_new_head_block(&self, new_tip_block: &SealedBlock<Self::Block>) {
        self.inner.on_new_head_block(new_tip_block);
        self.update_l1_block_info(
            new_tip_block.header(),
            new_tip_block.body().transactions().first(),
        );
    }
}

/// Keeps track of whether certain forks are activated
#[derive(Debug)]
pub(crate) struct OpForkTracker {
    /// Tracks if interop is activated at the block's timestamp.
    interop: AtomicBool,
}

impl OpForkTracker {
    /// Returns `true` if Interop fork is activated.
    pub(crate) fn is_interop_activated(&self) -> bool {
        self.interop.load(Ordering::Relaxed)
    }
}

/// Scale a raw L1 data fee by the TEA/ETH multiplier derived from a GasPriceOracle
/// price-ratio slot value. Pure (no state/chain access) so the scaling is
/// unit-testable; mirrors the EVM's `l1_cost_multiplier`, where
/// [`tea_l1_cost::multiplier_from_oracle_value`] yields `(rate, WAD)` and the
/// scaled cost is `raw * rate / WAD`.
///
/// Shared with the head-driven eviction task (`crate::maintain`) so admission and
/// eviction scale the L1 cost by the exact same math (TEAO1-151).
pub(crate) fn scale_l1_cost_by_oracle(
    raw_l1_cost: alloy_primitives::U256,
    oracle_slot: alloy_primitives::U256,
) -> alloy_primitives::U256 {
    let (rate, denom) = tea_l1_cost::multiplier_from_oracle_value(oracle_slot);
    raw_l1_cost.saturating_mul(rate) / denom
}

#[cfg(test)]
mod tea_tests {
    use super::scale_l1_cost_by_oracle;
    use alloy_primitives::U256;

    /// A populated oracle ratio scales the L1 fee by exactly that ratio, matching
    /// the EVM's `tx_l1_cost * rate / WAD` so the pool admits a tx only if it can
    /// pay what execution charges (TEAO1-175 / 186 / 151).
    #[test]
    fn scales_l1_cost_by_oracle_ratio() {
        // 3x ratio, raw L1 fee 1000 wei -> 3000 wei.
        let ratio = U256::from(3u64) * tea_l1_cost::WAD;
        assert_eq!(
            scale_l1_cost_by_oracle(U256::from(1000u64), ratio),
            U256::from(3000u64)
        );
    }

    /// A 1x (WAD) ratio is a no-op.
    #[test]
    fn unit_ratio_is_noop() {
        assert_eq!(
            scale_l1_cost_by_oracle(U256::from(777u64), tea_l1_cost::WAD),
            U256::from(777u64)
        );
    }

    /// An unset (zero) oracle slot falls back to the backup TEA/ETH rate — the
    /// same fallback the EVM uses, so the pool and execution agree.
    #[test]
    fn zero_oracle_uses_backup_rate() {
        assert_eq!(
            scale_l1_cost_by_oracle(U256::from(1u64), U256::ZERO),
            U256::from(tea_l1_cost::BACKUP_TEA_PER_ETH)
        );
    }
}
