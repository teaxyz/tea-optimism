//! Optimism payload builder implementation.
use crate::{
    OpAttributes, OpPayloadBuilderAttributes, OpPayloadPrimitives, config::OpBuilderConfig,
    error::OpPayloadBuilderError, payload::OpBuiltPayload,
};
use alloy_consensus::{BlockHeader, Transaction, Typed2718, conditional::BlockConditionalAttributes};
use alloy_evm::Evm as AlloyEvm;
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_debug::ExecutionWitness;
use alloy_rpc_types_eth::erc4337::{AccountStorage, TransactionConditional};
use alloy_rpc_types_engine::PayloadId;
use reth_basic_payload_builder::*;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_evm::{
    ConfigureEvm, Database,
    block::BlockExecutorFor,
    execute::{
        BlockBuilder, BlockBuilderOutcome, BlockExecutionError, BlockExecutor, BlockValidationError,
    },
    op_revm::{L1BlockInfo, constants::L1_BLOCK_CONTRACT},
};
use reth_execution_types::BlockExecutionOutput;
use reth_optimism_forks::OpHardforks;
use reth_optimism_primitives::{L2_TO_L1_MESSAGE_PASSER_ADDRESS, transaction::OpTransaction};
use reth_optimism_txpool::{
    OpPooledTx,
    conditional::{MaybeConditionalTransaction, first_known_account_violation},
    estimated_da_size::DataAvailabilitySized,
    interop::{MaybeInteropTransaction, is_valid_interop},
};
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_payload_primitives::{BuildNextEnv, BuiltPayloadExecutedBlock, PayloadBuilderAttributes};
use reth_payload_util::{BestPayloadTransactions, NoopPayloadTransactions, PayloadTransactions};
use reth_primitives_traits::{
    HeaderTy, NodePrimitives, SealedHeader, SealedHeaderFor, SignedTransaction, TxTy,
};
use reth_revm::{
    cancelled::CancelOnDrop, database::StateProviderDatabase, db::State,
    witness::ExecutionWitnessRecord,
};
use reth_storage_api::{StateProvider, StateProviderFactory, errors::ProviderError};
use reth_transaction_pool::{BestTransactionsAttributes, PoolTransaction, TransactionPool};
use reth_trie_common::HashedStorage;
use revm::context::{Block, BlockEnv};
// Anonymous import: brings revm's `Database::storage` into method scope for the
// TEAO1-167 conditional re-check without shadowing the `Database` bound name.
use revm::Database as _;
use std::{collections::HashMap, marker::PhantomData, sync::Arc};
use tracing::{debug, trace, warn};

/// Builds the [`HashedStorage`] overlay for `address` from the executor's pending
/// in-block state (TEAO1-206).
///
/// During block building, every storage slot an account has read or written in
/// this block lives in the revm [`State`] cache (it is block-cumulative). Feeding
/// those slots — at their *current* in-block values — as an overlay to
/// [`StorageRootProvider::storage_root`] recomputes the account's storage root as
/// it stands at the point the next transaction would execute, so a watched root
/// that drifted *inside* this block (e.g. the `GasPriceOracle` slot refreshed by
/// the head's L1-attributes deposit) is reflected. Slots that were only read are
/// at their committed value and contribute nothing to the trie; only genuine
/// writes move the root. An account untouched this block has no cache entry and
/// yields an empty overlay, so the provider returns its committed root.
fn account_pending_overlay<DB>(state: &State<DB>, address: Address) -> HashedStorage {
    match state.cache.accounts.get(&address) {
        // Loaded with live storage: overlay its current in-block slot values.
        Some(acc) => match &acc.account {
            Some(plain) => HashedStorage::from_plain_storage(acc.status, plain.storage.iter()),
            // Loaded but empty/self-destructed in-block: the storage trie is wiped.
            None => HashedStorage::from_iter(true, std::iter::empty()),
        },
        // Untouched this block: no overlay → provider returns the committed root.
        None => HashedStorage::default(),
    }
}

/// Computes an account's storage root against the *pending* build state — the
/// parent storage trie (from `provider`) overlaid with this block's in-block
/// writes (from the executor's [`State`] cache).
///
/// Implemented for the OP block executor's EVM database (`&mut State<DB>`) so the
/// payload builder can honor `AccountStorage::RootHash` conditionals at the actual
/// inclusion-time decision point (TEAO1-206), rather than punting them to RPC
/// admission / head eviction (both of which run against committed state and miss
/// same-block root drift).
trait PendingStorageRoot {
    /// Storage root of `address` over `provider`'s state plus this block's pending
    /// writes for that account.
    fn pending_storage_root(
        &self,
        provider: &dyn StateProvider,
        address: Address,
    ) -> Result<B256, ProviderError>;
}

impl<DB> PendingStorageRoot for &mut State<DB> {
    fn pending_storage_root(
        &self,
        provider: &dyn StateProvider,
        address: Address,
    ) -> Result<B256, ProviderError> {
        provider.storage_root(address, account_pending_overlay(self, address))
    }
}

/// Outcome of recomputing pending storage roots for a conditional's `RootHash`
/// predicates at inclusion time (TEAO1-206).
#[derive(Debug, PartialEq, Eq)]
enum RootHashRecheck {
    /// Every `RootHash`-watched account's pending storage root was recomputed.
    Roots(HashMap<Address, B256>),
    /// At least one watched account's storage root could not be recomputed.
    /// Fail-closed: the transaction must be excluded rather than included under a
    /// `RootHash` predicate we could not verify.
    Unverifiable,
}

/// Recompute the pending storage root of every `RootHash`-watched account in
/// `cond` via `compute`, returning them keyed by address.
///
/// `Slots` predicates are ignored here — they are checked by the slot reader. The
/// policy is **fail-closed** (TEAO1-206): the first `compute` error returns
/// [`RootHashRecheck::Unverifiable`] so the caller excludes the transaction
/// instead of including it under an unverifiable predicate. (`Slots` keeps the
/// established TEAO1-167 fail-open behavior, applied separately by the caller.)
fn recompute_root_hash_roots<E>(
    cond: &TransactionConditional,
    mut compute: impl FnMut(Address) -> Result<B256, E>,
) -> RootHashRecheck {
    let mut roots = HashMap::new();
    for (address, storage) in &cond.known_accounts {
        if matches!(storage, AccountStorage::RootHash(_)) {
            match compute(*address) {
                Ok(root) => {
                    roots.insert(*address, root);
                }
                Err(_) => return RootHashRecheck::Unverifiable,
            }
        }
    }
    RootHashRecheck::Roots(roots)
}

/// Optimism's payload builder
#[derive(Debug)]
pub struct OpPayloadBuilder<
    Pool,
    Client,
    Evm,
    Txs = (),
    Attrs = OpPayloadBuilderAttributes<TxTy<<Evm as ConfigureEvm>::Primitives>>,
> {
    /// The rollup's compute pending block configuration option.
    pub compute_pending_block: bool,
    /// The type responsible for creating the evm.
    pub evm_config: Evm,
    /// Transaction pool.
    pub pool: Pool,
    /// Node client.
    pub client: Client,
    /// Settings for the builder, e.g. DA settings.
    pub config: OpBuilderConfig,
    /// The type responsible for yielding the best transactions for the payload if mempool
    /// transactions are allowed.
    pub best_transactions: Txs,
    /// Marker for the payload attributes type.
    _pd: PhantomData<Attrs>,
}

impl<Pool, Client, Evm, Txs, Attrs> Clone for OpPayloadBuilder<Pool, Client, Evm, Txs, Attrs>
where
    Pool: Clone,
    Client: Clone,
    Evm: ConfigureEvm,
    Txs: Clone,
{
    fn clone(&self) -> Self {
        Self {
            evm_config: self.evm_config.clone(),
            pool: self.pool.clone(),
            client: self.client.clone(),
            config: self.config.clone(),
            best_transactions: self.best_transactions.clone(),
            compute_pending_block: self.compute_pending_block,
            _pd: PhantomData,
        }
    }
}

impl<Pool, Client, Evm, Attrs> OpPayloadBuilder<Pool, Client, Evm, (), Attrs> {
    /// `OpPayloadBuilder` constructor.
    ///
    /// Configures the builder with the default settings.
    pub fn new(pool: Pool, client: Client, evm_config: Evm) -> Self {
        Self::with_builder_config(pool, client, evm_config, Default::default())
    }

    /// Configures the builder with the given [`OpBuilderConfig`].
    pub const fn with_builder_config(
        pool: Pool,
        client: Client,
        evm_config: Evm,
        config: OpBuilderConfig,
    ) -> Self {
        Self {
            pool,
            client,
            compute_pending_block: true,
            evm_config,
            config,
            best_transactions: (),
            _pd: PhantomData,
        }
    }
}

impl<Pool, Client, Evm, Txs, Attrs> OpPayloadBuilder<Pool, Client, Evm, Txs, Attrs> {
    /// Sets the rollup's compute pending block configuration option.
    pub const fn set_compute_pending_block(mut self, compute_pending_block: bool) -> Self {
        self.compute_pending_block = compute_pending_block;
        self
    }

    /// Configures the type responsible for yielding the transactions that should be included in the
    /// payload.
    pub fn with_transactions<T>(
        self,
        best_transactions: T,
    ) -> OpPayloadBuilder<Pool, Client, Evm, T, Attrs> {
        let Self { pool, client, compute_pending_block, evm_config, config, .. } = self;
        OpPayloadBuilder {
            pool,
            client,
            compute_pending_block,
            evm_config,
            best_transactions,
            config,
            _pd: PhantomData,
        }
    }

    /// Enables the rollup's compute pending block configuration option.
    pub const fn compute_pending_block(self) -> Self {
        self.set_compute_pending_block(true)
    }

    /// Returns the rollup's compute pending block configuration option.
    pub const fn is_compute_pending_block(&self) -> bool {
        self.compute_pending_block
    }
}

impl<Pool, Client, Evm, N, T, Attrs> OpPayloadBuilder<Pool, Client, Evm, T, Attrs>
where
    Pool: TransactionPool<Transaction: OpPooledTx<Consensus = N::SignedTx>>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: OpHardforks>,
    N: OpPayloadPrimitives,
    Evm: ConfigureEvm<
            Primitives = N,
            NextBlockEnvCtx: BuildNextEnv<Attrs, N::BlockHeader, Client::ChainSpec>,
        >,
    Attrs: OpAttributes<Transaction = TxTy<Evm::Primitives>>,
{
    /// Constructs an Optimism payload from the transactions sent via the
    /// Payload attributes by the sequencer. If the `no_tx_pool` argument is passed in
    /// the payload attributes, the transaction pool will be ignored and the only transactions
    /// included in the payload will be those sent through the attributes.
    ///
    /// Given build arguments including an Optimism client, transaction pool,
    /// and configuration, this function creates a transaction payload. Returns
    /// a result indicating success with the payload or an error in case of failure.
    fn build_payload<'a, Txs>(
        &self,
        args: BuildArguments<Attrs, OpBuiltPayload<N>>,
        best: impl FnOnce(BestTransactionsAttributes) -> Txs + Send + Sync + 'a,
    ) -> Result<BuildOutcome<OpBuiltPayload<N>>, PayloadBuilderError>
    where
        Txs:
            PayloadTransactions<Transaction: PoolTransaction<Consensus = N::SignedTx> + OpPooledTx>,
    {
        let BuildArguments { mut cached_reads, config, cancel, best_payload } = args;

        let ctx = OpPayloadBuilderCtx {
            evm_config: self.evm_config.clone(),
            builder_config: self.config.clone(),
            chain_spec: self.client.chain_spec(),
            config,
            cancel,
            best_payload,
        };

        let builder = OpBuilder::new(best);

        let state_provider = self.client.state_by_block_hash(ctx.parent().hash())?;
        let state = StateProviderDatabase::new(&state_provider);

        if ctx.attributes().no_tx_pool() {
            builder.build(state, &state_provider, ctx)
        } else {
            // sequencer mode we can reuse cachedreads from previous runs
            builder.build(cached_reads.as_db_mut(state), &state_provider, ctx)
        }
        .map(|out| out.with_cached_reads(cached_reads))
    }

    /// Computes the witness for the payload.
    pub fn payload_witness(
        &self,
        parent: SealedHeader<N::BlockHeader>,
        attributes: Attrs::RpcPayloadAttributes,
    ) -> Result<ExecutionWitness, PayloadBuilderError>
    where
        Attrs: PayloadBuilderAttributes,
    {
        let attributes =
            Attrs::try_new(parent.hash(), attributes, 3).map_err(PayloadBuilderError::other)?;

        let config = PayloadConfig { parent_header: Arc::new(parent), attributes };
        let ctx = OpPayloadBuilderCtx {
            evm_config: self.evm_config.clone(),
            builder_config: self.config.clone(),
            chain_spec: self.client.chain_spec(),
            config,
            cancel: Default::default(),
            best_payload: Default::default(),
        };

        let state_provider = self.client.state_by_block_hash(ctx.parent().hash())?;

        let builder = OpBuilder::new(|_| NoopPayloadTransactions::<Pool::Transaction>::default());
        builder.witness(state_provider, &ctx)
    }
}

/// Implementation of the [`PayloadBuilder`] trait for [`OpPayloadBuilder`].
impl<Pool, Client, Evm, N, Txs, Attrs> PayloadBuilder
    for OpPayloadBuilder<Pool, Client, Evm, Txs, Attrs>
where
    N: OpPayloadPrimitives,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: OpHardforks> + Clone,
    Pool: TransactionPool<Transaction: OpPooledTx<Consensus = N::SignedTx>>,
    Evm: ConfigureEvm<
            Primitives = N,
            NextBlockEnvCtx: BuildNextEnv<Attrs, N::BlockHeader, Client::ChainSpec>,
        >,
    Txs: OpPayloadTransactions<Pool::Transaction>,
    Attrs: OpAttributes<Transaction = N::SignedTx>,
{
    type Attributes = Attrs;
    type BuiltPayload = OpBuiltPayload<N>;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let pool = self.pool.clone();
        self.build_payload(args, |attrs| self.best_transactions.best_transactions(pool, attrs))
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        // we want to await the job that's already in progress because that should be returned as
        // is, there's no benefit in racing another job
        MissingPayloadBehaviour::AwaitInProgress
    }

    // NOTE: this should only be used for testing purposes because this doesn't have access to L1
    // system txs, hence on_missing_payload we return [MissingPayloadBehaviour::AwaitInProgress].
    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes, N::BlockHeader>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        let args = BuildArguments {
            config,
            cached_reads: Default::default(),
            cancel: Default::default(),
            best_payload: None,
        };
        self.build_payload(args, |_| NoopPayloadTransactions::<Pool::Transaction>::default())?
            .into_payload()
            .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// The type that builds the payload.
///
/// Payload building for optimism is composed of several steps.
/// The first steps are mandatory and defined by the protocol.
///
/// 1. first all System calls are applied.
/// 2. After canyon the forced deployed `create2deployer` must be loaded
/// 3. all sequencer transactions are executed (part of the payload attributes)
///
/// Depending on whether the node acts as a sequencer and is allowed to include additional
/// transactions (`no_tx_pool == false`):
/// 4. include additional transactions
///
/// And finally
/// 5. build the block: compute all roots (txs, state)
#[derive(derive_more::Debug)]
pub struct OpBuilder<'a, Txs> {
    /// Yields the best transaction to include if transactions from the mempool are allowed.
    #[debug(skip)]
    best: Box<dyn FnOnce(BestTransactionsAttributes) -> Txs + 'a>,
}

impl<'a, Txs> OpBuilder<'a, Txs> {
    /// Creates a new [`OpBuilder`].
    pub fn new(best: impl FnOnce(BestTransactionsAttributes) -> Txs + Send + Sync + 'a) -> Self {
        Self { best: Box::new(best) }
    }
}

impl<Txs> OpBuilder<'_, Txs> {
    /// Builds the payload on top of the state.
    pub fn build<Evm, ChainSpec, N, Attrs>(
        self,
        db: impl Database<Error = ProviderError>,
        state_provider: impl StateProvider,
        ctx: OpPayloadBuilderCtx<Evm, ChainSpec, Attrs>,
    ) -> Result<BuildOutcomeKind<OpBuiltPayload<N>>, PayloadBuilderError>
    where
        Evm: ConfigureEvm<
                Primitives = N,
                NextBlockEnvCtx: BuildNextEnv<Attrs, N::BlockHeader, ChainSpec>,
            >,
        ChainSpec: EthChainSpec + OpHardforks,
        N: OpPayloadPrimitives,
        Txs:
            PayloadTransactions<Transaction: PoolTransaction<Consensus = N::SignedTx> + OpPooledTx>,
        Attrs: OpAttributes<Transaction = N::SignedTx>,
    {
        let Self { best } = self;
        debug!(target: "payload_builder", id=%ctx.payload_id(), parent_header = ?ctx.parent().hash(), parent_number = ctx.parent().number(), "building new payload");

        let mut db = State::builder().with_database(db).with_bundle_update().build();

        // Load the L1 block contract into the database cache. If the L1 block contract is not
        // pre-loaded the database will panic when trying to fetch the DA footprint gas
        // scalar.
        db.load_cache_account(L1_BLOCK_CONTRACT).map_err(BlockExecutionError::other)?;

        let mut builder = ctx.block_builder(&mut db)?;

        // 1. apply pre-execution changes
        builder.apply_pre_execution_changes().map_err(|err| {
            warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;

        // 2. execute sequencer transactions
        let mut info = ctx.execute_sequencer_transactions(&mut builder)?;

        // 3. if mem pool transactions are requested we execute them
        if !ctx.attributes().no_tx_pool() {
            let best_txs = best(ctx.best_transaction_attributes(builder.evm_mut().block()));
            // `&state_provider` lets the conditional re-check recompute pending storage
            // roots for `RootHash` predicates (TEAO1-206); it is moved into `finish`
            // below, after this borrow ends.
            if ctx
                .execute_best_transactions(&mut info, &mut builder, best_txs, &state_provider)?
                .is_some()
            {
                return Ok(BuildOutcomeKind::Cancelled);
            }

            // check if the new payload is even more valuable
            if !ctx.is_better_payload(info.total_fees) {
                // can skip building the block
                return Ok(BuildOutcomeKind::Aborted { fees: info.total_fees });
            }
        }

        let BlockBuilderOutcome { execution_result, hashed_state, trie_updates, block } =
            builder.finish(state_provider)?;

        let sealed_block = Arc::new(block.sealed_block().clone());
        debug!(target: "payload_builder", id=%ctx.attributes().payload_id(), sealed_block_header = ?sealed_block.header(), "sealed built block");

        let execution_outcome =
            BlockExecutionOutput { state: db.take_bundle(), result: execution_result };

        // create the executed block data
        let executed: BuiltPayloadExecutedBlock<N> = BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(block),
            execution_output: Arc::new(execution_outcome),
            // Keep unsorted; conversion to sorted happens when needed downstream
            hashed_state: either::Either::Left(Arc::new(hashed_state)),
            trie_updates: either::Either::Left(Arc::new(trie_updates)),
        };

        let no_tx_pool = ctx.attributes().no_tx_pool();

        let payload =
            OpBuiltPayload::new(ctx.payload_id(), sealed_block, info.total_fees, Some(executed));

        if no_tx_pool {
            // if `no_tx_pool` is set only transactions from the payload attributes will be included
            // in the payload. In other words, the payload is deterministic and we can
            // freeze it once we've successfully built it.
            Ok(BuildOutcomeKind::Freeze(payload))
        } else {
            Ok(BuildOutcomeKind::Better { payload })
        }
    }

    /// Builds the payload and returns its [`ExecutionWitness`] based on the state after execution.
    pub fn witness<Evm, ChainSpec, N, Attrs>(
        self,
        state_provider: impl StateProvider,
        ctx: &OpPayloadBuilderCtx<Evm, ChainSpec, Attrs>,
    ) -> Result<ExecutionWitness, PayloadBuilderError>
    where
        Evm: ConfigureEvm<
                Primitives = N,
                NextBlockEnvCtx: BuildNextEnv<Attrs, N::BlockHeader, ChainSpec>,
            >,
        ChainSpec: EthChainSpec + OpHardforks,
        N: OpPayloadPrimitives,
        Txs: PayloadTransactions<Transaction: PoolTransaction<Consensus = N::SignedTx>>,
        Attrs: OpAttributes<Transaction = N::SignedTx>,
    {
        let mut db = State::builder()
            .with_database(StateProviderDatabase::new(&state_provider))
            .with_bundle_update()
            .build();
        let mut builder = ctx.block_builder(&mut db)?;

        builder.apply_pre_execution_changes()?;
        ctx.execute_sequencer_transactions(&mut builder)?;
        builder.into_executor().apply_post_execution_changes()?;

        if ctx.chain_spec.is_isthmus_active_at_timestamp(ctx.attributes().timestamp()) {
            // force load `L2ToL1MessagePasser.sol` so l2 withdrawals root can be computed even if
            // no l2 withdrawals in block
            _ = db.load_cache_account(L2_TO_L1_MESSAGE_PASSER_ADDRESS)?;
        }

        let ExecutionWitnessRecord { hashed_state, codes, keys, lowest_block_number: _ } =
            ExecutionWitnessRecord::from_executed_state(&db);
        let state = state_provider.witness(Default::default(), hashed_state)?;
        Ok(ExecutionWitness {
            state: state.into_iter().collect(),
            codes,
            keys,
            ..Default::default()
        })
    }
}

/// A type that returns a the [`PayloadTransactions`] that should be included in the pool.
pub trait OpPayloadTransactions<Transaction>: Clone + Send + Sync + Unpin + 'static {
    /// Returns an iterator that yields the transaction in the order they should get included in the
    /// new payload.
    fn best_transactions<Pool: TransactionPool<Transaction = Transaction>>(
        &self,
        pool: Pool,
        attr: BestTransactionsAttributes,
    ) -> impl PayloadTransactions<Transaction = Transaction>;
}

impl<T: PoolTransaction + MaybeInteropTransaction> OpPayloadTransactions<T> for () {
    fn best_transactions<Pool: TransactionPool<Transaction = T>>(
        &self,
        pool: Pool,
        attr: BestTransactionsAttributes,
    ) -> impl PayloadTransactions<Transaction = T> {
        BestPayloadTransactions::new(pool.best_transactions_with_attributes(attr))
    }
}

/// Holds the state after execution
#[derive(Debug)]
pub struct ExecutedPayload<N: NodePrimitives> {
    /// Tracked execution info
    pub info: ExecutionInfo,
    /// Withdrawal hash.
    pub withdrawals_root: Option<B256>,
    /// The transaction receipts.
    pub receipts: Vec<N::Receipt>,
    /// The block env used during execution.
    pub block_env: BlockEnv,
}

/// This acts as the container for executed transactions and its byproducts (receipts, gas used)
#[derive(Default, Debug)]
pub struct ExecutionInfo {
    /// All gas used so far
    pub cumulative_gas_used: u64,
    /// Estimated DA size
    pub cumulative_da_bytes_used: u64,
    /// Tracks fees from executed mempool transactions
    pub total_fees: U256,
}

impl ExecutionInfo {
    /// Create a new instance with allocated slots.
    pub const fn new() -> Self {
        Self { cumulative_gas_used: 0, cumulative_da_bytes_used: 0, total_fees: U256::ZERO }
    }

    /// Returns true if the transaction would exceed the block limits:
    /// - block gas limit: ensures the transaction still fits into the block.
    /// - tx DA limit: if configured, ensures the tx does not exceed the maximum allowed DA limit
    ///   per tx.
    /// - block DA limit: if configured, ensures the transaction's DA size does not exceed the
    ///   maximum allowed DA limit per block.
    pub fn is_tx_over_limits(
        &self,
        tx_da_size: u64,
        block_gas_limit: u64,
        tx_data_limit: Option<u64>,
        block_data_limit: Option<u64>,
        tx_gas_limit: u64,
        da_footprint_gas_scalar: Option<u16>,
    ) -> bool {
        if tx_data_limit.is_some_and(|da_limit| tx_da_size > da_limit) {
            return true;
        }

        let total_da_bytes_used = self.cumulative_da_bytes_used.saturating_add(tx_da_size);

        if block_data_limit.is_some_and(|da_limit| total_da_bytes_used > da_limit) {
            return true;
        }

        // Post Jovian: the tx DA footprint must be less than the block gas limit
        if let Some(da_footprint_gas_scalar) = da_footprint_gas_scalar {
            let tx_da_footprint =
                total_da_bytes_used.saturating_mul(da_footprint_gas_scalar as u64);
            if tx_da_footprint > block_gas_limit {
                return true;
            }
        }

        self.cumulative_gas_used + tx_gas_limit > block_gas_limit
    }
}

/// Container type that holds all necessities to build a new payload.
#[derive(derive_more::Debug)]
pub struct OpPayloadBuilderCtx<
    Evm: ConfigureEvm,
    ChainSpec,
    Attrs = OpPayloadBuilderAttributes<TxTy<<Evm as ConfigureEvm>::Primitives>>,
> {
    /// The type that knows how to perform system calls and configure the evm.
    pub evm_config: Evm,
    /// Additional config for the builder/sequencer, e.g. DA and gas limit
    pub builder_config: OpBuilderConfig,
    /// The chainspec
    pub chain_spec: Arc<ChainSpec>,
    /// How to build the payload.
    pub config: PayloadConfig<Attrs, HeaderTy<Evm::Primitives>>,
    /// Marker to check whether the job has been cancelled.
    pub cancel: CancelOnDrop,
    /// The currently best payload.
    pub best_payload: Option<OpBuiltPayload<Evm::Primitives>>,
}

impl<Evm, ChainSpec, Attrs> OpPayloadBuilderCtx<Evm, ChainSpec, Attrs>
where
    Evm: ConfigureEvm<
            Primitives: OpPayloadPrimitives,
            NextBlockEnvCtx: BuildNextEnv<Attrs, HeaderTy<Evm::Primitives>, ChainSpec>,
        >,
    ChainSpec: EthChainSpec + OpHardforks,
    Attrs: OpAttributes<Transaction = TxTy<Evm::Primitives>>,
{
    /// Returns the parent block the payload will be build on.
    pub fn parent(&self) -> &SealedHeaderFor<Evm::Primitives> {
        self.config.parent_header.as_ref()
    }

    /// Returns the builder attributes.
    pub const fn attributes(&self) -> &Attrs {
        &self.config.attributes
    }

    /// Returns the current fee settings for transactions from the mempool
    pub fn best_transaction_attributes(&self, block_env: impl Block) -> BestTransactionsAttributes {
        BestTransactionsAttributes::new(
            block_env.basefee(),
            block_env.blob_gasprice().map(|p| p as u64),
        )
    }

    /// Returns the unique id for this payload job.
    pub fn payload_id(&self) -> PayloadId {
        self.attributes().payload_id()
    }

    /// Returns true if the fees are higher than the previous payload.
    pub fn is_better_payload(&self, total_fees: U256) -> bool {
        is_better_payload(self.best_payload.as_ref(), total_fees)
    }

    /// Prepares a [`BlockBuilder`] for the next block.
    pub fn block_builder<'a, DB: Database>(
        &'a self,
        db: &'a mut State<DB>,
    ) -> Result<
        impl BlockBuilder<
            Primitives = Evm::Primitives,
            Executor: BlockExecutorFor<'a, Evm::BlockExecutorFactory, DB>,
        > + 'a,
        PayloadBuilderError,
    > {
        self.evm_config
            .builder_for_next_block(
                db,
                self.parent(),
                Evm::NextBlockEnvCtx::build_next_env(
                    self.attributes(),
                    self.parent(),
                    self.chain_spec.as_ref(),
                )
                .map_err(PayloadBuilderError::other)?,
            )
            .map_err(PayloadBuilderError::other)
    }

    /// Executes all sequencer transactions that are included in the payload attributes.
    pub fn execute_sequencer_transactions(
        &self,
        builder: &mut impl BlockBuilder<Primitives = Evm::Primitives>,
    ) -> Result<ExecutionInfo, PayloadBuilderError> {
        let mut info = ExecutionInfo::new();

        for sequencer_tx in self.attributes().sequencer_transactions() {
            // A sequencer's block should never contain blob transactions.
            if sequencer_tx.value().is_eip4844() {
                return Err(PayloadBuilderError::other(
                    OpPayloadBuilderError::BlobTransactionRejected,
                ));
            }

            // Convert the transaction to a [RecoveredTx]. This is
            // purely for the purposes of utilizing the `evm_config.tx_env`` function.
            // Deposit transactions do not have signatures, so if the tx is a deposit, this
            // will just pull in its `from` address.
            let sequencer_tx = sequencer_tx.value().try_clone_into_recovered().map_err(|_| {
                PayloadBuilderError::other(OpPayloadBuilderError::TransactionEcRecoverFailed)
            })?;

            let gas_used = match builder.execute_transaction(sequencer_tx.clone()) {
                Ok(gas_used) => gas_used,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
                    trace!(target: "payload_builder", %error, ?sequencer_tx, "Error in sequencer transaction, skipping.");
                    continue;
                }
                Err(err) => {
                    // this is an error that we should treat as fatal for this attempt
                    return Err(PayloadBuilderError::EvmExecutionError(Box::new(err)));
                }
            };

            // add gas used by the transaction to cumulative gas used, before creating the receipt
            info.cumulative_gas_used += gas_used;
        }

        Ok(info)
    }

    /// Executes the given best transactions and updates the execution info.
    ///
    /// Returns `Ok(Some(())` if the job was cancelled.
    pub fn execute_best_transactions<Builder>(
        &self,
        info: &mut ExecutionInfo,
        builder: &mut Builder,
        mut best_txs: impl PayloadTransactions<
            Transaction: PoolTransaction<Consensus = TxTy<Evm::Primitives>> + OpPooledTx,
        >,
        // Parent state, used to recompute a watched account's storage root over the
        // pending build state when a conditional carries an `AccountStorage::RootHash`
        // predicate (TEAO1-206).
        state_provider: &dyn StateProvider,
    ) -> Result<Option<()>, PayloadBuilderError>
    where
        Builder: BlockBuilder<Primitives = Evm::Primitives>,
        // `Database` for slot reads; `PendingStorageRoot` to recompute storage roots
        // over the pending build state for `RootHash` predicates (TEAO1-206).
        <<Builder::Executor as BlockExecutor>::Evm as AlloyEvm>::DB:
            Database + PendingStorageRoot,
    {
        let mut block_gas_limit = builder.evm_mut().block().gas_limit();
        if let Some(gas_limit_config) = self.builder_config.gas_limit_config.gas_limit() {
            // If a gas limit is configured, use that limit as target if it's smaller, otherwise use
            // the block's actual gas limit.
            block_gas_limit = gas_limit_config.min(block_gas_limit);
        };
        let block_da_limit = self.builder_config.da_config.max_da_block_size();
        let tx_da_limit = self.builder_config.da_config.max_da_tx_size();
        let base_fee = builder.evm_mut().block().basefee();

        while let Some(tx) = best_txs.next(()) {
            let interop = tx.interop_deadline();
            // Captured before `into_consensus()` drops the pooled wrapper; re-checked
            // against the pending build state just before execution (TEAO1-167).
            let conditional = tx.conditional().cloned();
            let tx_da_size = tx.estimated_da_size();
            let tx = tx.into_consensus();

            let da_footprint_gas_scalar = self
                .chain_spec
                .is_jovian_active_at_timestamp(self.attributes().timestamp())
                .then_some(
                    L1BlockInfo::fetch_da_footprint_gas_scalar(builder.evm_mut().db_mut()).expect(
                        "DA footprint should always be available from the database post jovian",
                    ),
                );

            if info.is_tx_over_limits(
                tx_da_size,
                block_gas_limit,
                tx_da_limit,
                block_da_limit,
                tx.gas_limit(),
                da_footprint_gas_scalar,
            ) {
                // we can't fit this transaction into the block, so we need to mark it as
                // invalid which also removes all dependent transaction from
                // the iterator before we can continue
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // A sequencer's block should never contain blob or deposit transactions from the pool.
            if tx.is_eip4844() || tx.is_deposit() {
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // We skip invalid cross chain txs, they would be removed on the next block update in
            // the maintenance job
            if let Some(interop) = interop &&
                !is_valid_interop(interop, self.config.attributes.timestamp())
            {
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }
            // check if the job was cancelled, if so we can exit early
            if self.cancel.is_cancelled() {
                return Ok(Some(()));
            }

            // Re-check the conditional's block-attribute ceilings (`blockNumberMax`
            // / `timestampMax`) against the candidate block being built, immediately
            // before inclusion. The maintenance task only evicts expired conditionals
            // on a post-commit `Commit` notification, so there is a window where the
            // next block is built (e.g. at T+2) before any eviction fires for a tx
            // whose `timestampMax`/`blockNumberMax` already expired (e.g. T+1). Use
            // the values of the block BEING BUILT — not the parent head — which is the
            // whole point of the finding. (Companion to the TEAO1-167 re-check below.)
            if let Some(cond) = &conditional {
                let block = builder.evm_mut().block();
                let block_attr = BlockConditionalAttributes {
                    number: block.number().saturating_to(),
                    timestamp: block.timestamp().saturating_to(),
                };
                if cond.has_exceeded_block_attributes(&block_attr) {
                    trace!(target: "payload_builder", ?tx, "skipping conditional tx whose blockNumberMax/timestampMax expired for the candidate block");
                    best_txs.mark_invalid(tx.signer(), tx.nonce());
                    continue;
                }
            }

            // TEAO1-167 / TEAO1-206: re-validate the conditional's `knownAccounts`
            // against the state this block actually executes on, immediately before
            // inclusion. The head's L1-attributes deposit (executed above) — and any
            // earlier tx in this block — can change a watched account inside the very
            // block being built, so admission (`Latest`) and head eviction (committed)
            // are both blind to same-block drift; the builder is the only inclusion-
            // time decision point. `Slots` are read from the builder's pending DB;
            // `RootHash` predicates are honored here by recomputing the account's
            // storage root over the pending build state (parent trie + this block's
            // writes) via the state provider.
            //
            // Read-error policy is split by predicate kind:
            // - `RootHash` is **fail-closed** — this is the inclusion-time invariant
            //   under audit (TEAO1-206), so if a watched account's storage root cannot
            //   be recomputed we must NOT include the tx under an unverified predicate.
            //   It is excluded and stays pooled for retry on the next block (no drop,
            //   no admission rejection).
            // - `Slots` stays **fail-open** — the established TEAO1-167 behavior; a
            //   transient slot read never drops an otherwise-includable tx.
            if let Some(cond) = &conditional {
                // Recompute pending storage roots for `RootHash`-watched accounts
                // against the pending build state. This needs both the executor
                // `State` (pending overlay) and the parent `state_provider`, so do it
                // before the slot-reader closure borrows the DB. Fail-closed: if any
                // watched root cannot be recomputed, exclude the tx (TEAO1-206).
                let pending_roots = match recompute_root_hash_roots(cond, |address| {
                    builder.evm_mut().db_mut().pending_storage_root(state_provider, address)
                }) {
                    RootHashRecheck::Roots(roots) => roots,
                    RootHashRecheck::Unverifiable => {
                        trace!(target: "payload_builder", ?tx, "excluding conditional tx whose RootHash predicate could not be re-verified (TEAO1-206)");
                        best_txs.mark_invalid(tx.signer(), tx.nonce());
                        continue;
                    }
                };

                let db = builder.evm_mut().db_mut();
                let violated = matches!(
                    first_known_account_violation(
                        cond,
                        |address, slot| db.storage(address, slot),
                        |address| Ok(pending_roots.get(&address).copied()),
                    ),
                    Ok(Some(_))
                );
                if violated {
                    trace!(target: "payload_builder", ?tx, "skipping conditional tx whose knownAccounts no longer hold (TEAO1-167/206)");
                    best_txs.mark_invalid(tx.signer(), tx.nonce());
                    continue;
                }
            }

            let gas_used = match builder.execute_transaction(tx.clone()) {
                Ok(gas_used) => gas_used,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
                    if error.is_nonce_too_low() {
                        // if the nonce is too low, we can skip this transaction
                        trace!(target: "payload_builder", %error, ?tx, "skipping nonce too low transaction");
                    } else {
                        // if the transaction is invalid, we can skip it and all of its
                        // descendants
                        trace!(target: "payload_builder", %error, ?tx, "skipping invalid transaction and its descendants");
                        best_txs.mark_invalid(tx.signer(), tx.nonce());
                    }
                    continue;
                }
                Err(err) => {
                    // this is an error that we should treat as fatal for this attempt
                    return Err(PayloadBuilderError::EvmExecutionError(Box::new(err)));
                }
            };

            // add gas used by the transaction to cumulative gas used, before creating the
            // receipt
            info.cumulative_gas_used += gas_used;
            info.cumulative_da_bytes_used += tx_da_size;

            // update and add to total fees
            let miner_fee = tx
                .effective_tip_per_gas(base_fee)
                .expect("fee is always valid; execution succeeded");
            info.total_fees += U256::from(miner_fee) * U256::from(gas_used);
        }

        Ok(None)
    }
}

#[cfg(test)]
mod root_hash_overlay_tests {
    //! Unit tests for [`account_pending_overlay`] — the load-bearing piece of the
    //! TEAO1-206 fix. It extracts an account's *pending* in-block storage (from the
    //! executor `State` cache) so the builder can recompute the watched storage root
    //! over the block being built. Correctness here means the overlay the builder
    //! hands to `StateProvider::storage_root` reflects same-block writes, so a
    //! `RootHash` predicate is enforced at inclusion rather than skipped.
    use super::*;
    use alloy_primitives::keccak256;
    use reth_optimism_txpool::conditional::KnownAccountViolation;
    use reth_provider::{providers::LatestStateProviderRef, test_utils::create_test_provider_factory};
    use reth_revm::db::{EmptyDB, states::CacheAccount, states::AccountStatus};
    use reth_storage_api::StorageRootProvider;
    use revm::primitives::HashMap as RevmMap;
    use revm::state::AccountInfo;
    use std::convert::Infallible;

    fn empty_state() -> State<EmptyDB> {
        State::builder().with_database(EmptyDB::default()).build()
    }

    fn plain_storage(slots: &[(U256, U256)]) -> RevmMap<U256, U256> {
        let mut s = RevmMap::default();
        for (k, v) in slots {
            s.insert(*k, *v);
        }
        s
    }

    /// A `State` whose pending cache holds `addr` with `slots` (modelling in-block
    /// writes the executor has accumulated for that account).
    fn state_with_pending(addr: Address, slots: &[(U256, U256)]) -> State<EmptyDB> {
        let mut state = empty_state();
        state
            .cache
            .accounts
            .insert(addr, CacheAccount::new_changed(AccountInfo::default(), plain_storage(slots)));
        state
    }

    fn cond_root(addr: Address, root: B256) -> TransactionConditional {
        let mut tc = TransactionConditional::default();
        tc.known_accounts.insert(addr, AccountStorage::RootHash(root));
        tc
    }

    /// The builder's inclusion decision for a conditional, given the storage root it
    /// recomputed for the watched account — exactly the shape `execute_best_transactions`
    /// feeds to `first_known_account_violation`.
    fn builder_decision(
        cond: &TransactionConditional,
        recomputed_root: B256,
    ) -> Option<KnownAccountViolation> {
        first_known_account_violation(
            cond,
            |_, _| Ok::<_, Infallible>(U256::ZERO),
            move |_| Ok::<_, Infallible>(Some(recomputed_root)),
        )
        .unwrap()
    }

    #[test]
    fn overlay_reflects_pending_slot_writes() {
        // An account changed inside the block (e.g. the GasPriceOracle ratio slot
        // refreshed by the head's L1-attributes deposit) must surface in the overlay
        // at its *new* value, so the recomputed storage root differs from the one the
        // conditional was admitted against.
        let addr = Address::with_last_byte(0x42);
        let (slot, val) = (U256::from(1), U256::from(9));
        let mut state = empty_state();
        state
            .cache
            .accounts
            .insert(addr, CacheAccount::new_changed(AccountInfo::default(), plain_storage(&[(slot, val)])));

        let overlay = account_pending_overlay(&state, addr);
        assert!(!overlay.wiped);
        assert_eq!(overlay.storage.get(&keccak256(B256::from(slot))), Some(&val));
    }

    #[test]
    fn overlay_is_empty_for_untouched_account() {
        // No cache entry => no overlay => the provider returns the committed root,
        // so an unchanged account's RootHash predicate still holds.
        let overlay = account_pending_overlay(&empty_state(), Address::with_last_byte(0x07));
        assert!(overlay.is_empty());
    }

    #[test]
    fn overlay_is_wiped_for_destroyed_account() {
        // A self-destructed account has an empty storage trie; the overlay must be
        // wiped so the recomputed root is the empty-storage root.
        let addr = Address::with_last_byte(0x09);
        let mut state = empty_state();
        state.cache.accounts.insert(addr, CacheAccount::new_destroyed());

        let overlay = account_pending_overlay(&state, addr);
        assert!(overlay.wiped);
        assert!(overlay.storage.is_empty());
    }

    /// Full inclusion-time enforcement against a **real DB-backed state provider**
    /// (TEAO1-206). This drives the entire fix chain end-to-end with real trie
    /// hashing — `account_pending_overlay` (overlay from the executor `State` cache)
    /// → `PendingStorageRoot::pending_storage_root` → `StorageRootProvider::storage_root`
    /// (`StorageRoot::overlay_root` over MDBX) → `first_known_account_violation` — and
    /// proves a `RootHash` conditional is included when the watched root holds and
    /// **excluded** once that root drifts inside the block being built. A mock
    /// provider can't show this: its `storage_root` is a stub, so only a real
    /// provider exercises the value-sensitive trie computation the fix relies on.
    #[test]
    fn pending_root_includes_when_unchanged_and_excludes_on_same_block_drift() {
        let factory = create_test_provider_factory();
        let db = factory.provider().expect("test provider");
        let provider = LatestStateProviderRef::new(&db);

        let addr = Address::with_last_byte(0x42);
        let slot = U256::from(1);
        let v_admit = U256::from(7); // value the conditional was admitted against
        let v_drift = U256::from(9); // value after a same-block write (e.g. oracle flip)

        // The storage root the submitter pinned via `RootHash`, captured at admission
        // (account storage = {slot: v_admit}). Computed through the real provider so
        // the trie hashing matches what the builder will recompute.
        let expected_root = provider
            .storage_root(addr, HashedStorage::from_plain_storage(AccountStatus::Loaded, [(&slot, &v_admit)].into_iter()))
            .expect("storage root");
        let cond = cond_root(addr, expected_root);

        // No same-block drift: the executor's pending cache still holds v_admit, so
        // the builder recomputes `expected_root` and the conditional is INCLUDED.
        let mut state_ok = state_with_pending(addr, &[(slot, v_admit)]);
        let root_ok = (&mut state_ok).pending_storage_root(&provider, addr).expect("pending root");
        assert_eq!(root_ok, expected_root, "unchanged account must recompute the admitted root");
        assert_eq!(builder_decision(&cond, root_ok), None, "matching root must be includable");

        // Same-block drift: an earlier tx wrote v_drift to the watched slot. The
        // builder recomputes a DIFFERENT root and EXCLUDES the conditional — the exact
        // behavior the finding's `read_root => None` builder leg failed to produce.
        let mut state_drift = state_with_pending(addr, &[(slot, v_drift)]);
        let root_drift =
            (&mut state_drift).pending_storage_root(&provider, addr).expect("pending root");
        assert_ne!(root_drift, expected_root, "a same-block write must move the storage root");
        assert_eq!(
            builder_decision(&cond, root_drift),
            Some(KnownAccountViolation::Root { address: addr }),
            "drifted root must be excluded at inclusion time"
        );
    }

    fn cond_slots(addr: Address, slot: U256, expected: B256) -> TransactionConditional {
        let mut slots = alloy_primitives::map::HashMap::default();
        slots.insert(slot, expected);
        let mut tc = TransactionConditional::default();
        tc.known_accounts.insert(addr, AccountStorage::Slots(slots));
        tc
    }

    // ── Fail-closed decision (TEAO1-206), unit-tested via the extracted
    //    `recompute_root_hash_roots` so the read-error branch is covered without a
    //    bespoke erroring `StateProvider`. ────────────────────────────────────────

    #[test]
    fn recompute_excludes_when_a_root_is_unverifiable() {
        // Fail-closed: a compute (storage_root) error for a RootHash-watched account
        // must yield `Unverifiable`, which the builder turns into `mark_invalid`.
        let a = Address::with_last_byte(1);
        let cond = cond_root(a, B256::with_last_byte(42));
        assert_eq!(
            recompute_root_hash_roots(&cond, |_| Err::<B256, ()>(())),
            RootHashRecheck::Unverifiable,
        );
    }

    #[test]
    fn recompute_collects_roots_when_all_ok() {
        let a = Address::with_last_byte(1);
        let cond = cond_root(a, B256::with_last_byte(42));
        let root = B256::with_last_byte(7);
        match recompute_root_hash_roots(&cond, |_| Ok::<B256, ()>(root)) {
            RootHashRecheck::Roots(roots) => {
                assert_eq!(roots.len(), 1);
                assert_eq!(roots.get(&a), Some(&root));
            }
            RootHashRecheck::Unverifiable => panic!("expected Roots"),
        }
    }

    #[test]
    fn recompute_ignores_slots_predicates() {
        // `Slots` predicates are handled by the slot reader; the root recompute must
        // not call `compute` for them and must not fail-close on them.
        let a = Address::with_last_byte(1);
        let cond = cond_slots(a, U256::from(1), B256::with_last_byte(7));
        let mut called = false;
        let res = recompute_root_hash_roots(&cond, |_| {
            called = true;
            Ok::<B256, ()>(B256::ZERO)
        });
        assert!(!called, "compute must not run for Slots predicates");
        assert_eq!(res, RootHashRecheck::Roots(HashMap::new()));
    }

    #[test]
    fn recompute_fail_closes_on_first_root_error_even_with_a_good_one() {
        // A mixed conditional: one RootHash resolves, another errors. Fail-closed
        // wins — the whole tx is excluded, never partially trusted.
        let good = Address::with_last_byte(1);
        let bad = Address::with_last_byte(2);
        let mut cond = cond_root(good, B256::with_last_byte(1));
        cond.known_accounts.insert(bad, AccountStorage::RootHash(B256::with_last_byte(2)));
        assert_eq!(
            recompute_root_hash_roots(&cond, |address| {
                if address == bad { Err::<B256, ()>(()) } else { Ok(B256::with_last_byte(9)) }
            }),
            RootHashRecheck::Unverifiable,
        );
    }
}
