//! Support for maintaining the state of the transaction pool

/// The interval for which we check transaction against supervisor, 10 min.
const TRANSACTION_VALIDITY_WINDOW: u64 = 600;
/// Interval in seconds at which the transaction should be revalidated.
const OFFSET_TIME: u64 = 60;
/// Maximum number of supervisor requests at the same time
const MAX_SUPERVISOR_QUERIES: usize = 10;

use crate::{
    OpPooledTx,
    conditional::{MaybeConditionalTransaction, first_known_account_violation},
    interop::{MaybeInteropTransaction, is_stale_interop, is_valid_interop},
    supervisor::SupervisorClient,
    validator::scale_l1_cost_by_oracle,
};
use alloy_consensus::{BlockHeader, conditional::BlockConditionalAttributes};
use alloy_primitives::{Address, StorageKey, U256};
use futures_util::{FutureExt, Stream, StreamExt, future::BoxFuture};
use metrics::{Gauge, Histogram};
use reth_chain_state::CanonStateNotification;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_metrics::{Metrics, metrics::Counter};
use reth_optimism_evm::{RethL1BlockInfo, extract_l1_info_from_tx};
use reth_optimism_forks::OpHardforks;
use reth_primitives_traits::{BlockBody, NodePrimitives};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_transaction_pool::{PoolTransaction, TransactionPool, error::PoolTransactionError};
use std::{collections::hash_map::Entry, collections::HashMap, time::Instant};
use tracing::{debug, warn};

/// Transaction pool maintenance metrics
#[derive(Metrics)]
#[metrics(scope = "transaction_pool")]
struct MaintainPoolConditionalMetrics {
    /// Counter indicating the number of conditional transactions removed from
    /// the pool because of exceeded block attributes or stale `knownAccounts`.
    removed_tx_conditional: Counter,
    /// Subset of the above removed specifically because their `knownAccounts`
    /// predicates no longer match the new head's state (TEAO1-167).
    removed_tx_conditional_known_accounts: Counter,
}

impl MaintainPoolConditionalMetrics {
    #[inline]
    fn inc_removed_tx_conditional(&self, count: usize) {
        self.removed_tx_conditional.increment(count as u64);
    }

    #[inline]
    fn inc_removed_tx_conditional_known_accounts(&self, count: usize) {
        self.removed_tx_conditional_known_accounts.increment(count as u64);
    }
}

/// Transaction pool maintenance metrics
#[derive(Metrics)]
#[metrics(scope = "transaction_pool")]
struct MaintainPoolInteropMetrics {
    /// Counter indicating the number of conditional transactions removed from
    /// the pool because of exceeded block attributes.
    removed_tx_interop: Counter,
    /// Number of interop transactions currently in the pool
    pooled_interop_transactions: Gauge,

    /// Counter for interop transactions that became stale and need revalidation
    stale_interop_transactions: Counter,
    // TODO: we also should add metric for (hash, counter) to check number of validation per tx
    /// Histogram for measuring supervisor revalidation duration (congestion metric)
    supervisor_revalidation_duration_seconds: Histogram,
}

impl MaintainPoolInteropMetrics {
    #[inline]
    fn inc_removed_tx_interop(&self, count: usize) {
        self.removed_tx_interop.increment(count as u64);
    }
    #[inline]
    fn set_interop_txs_in_pool(&self, count: usize) {
        self.pooled_interop_transactions.set(count as f64);
    }

    #[inline]
    fn inc_stale_tx_interop(&self, count: usize) {
        self.stale_interop_transactions.increment(count as u64);
    }

    /// Record supervisor revalidation duration
    #[inline]
    fn record_supervisor_duration(&self, duration: std::time::Duration) {
        self.supervisor_revalidation_duration_seconds.record(duration.as_secs_f64());
    }
}
/// Returns a spawnable future for maintaining the state of the conditional txs in the transaction
/// pool.
pub fn maintain_transaction_pool_conditional_future<N, Client, Pool, St>(
    client: Client,
    pool: Pool,
    events: St,
) -> BoxFuture<'static, ()>
where
    N: NodePrimitives,
    Client: StateProviderFactory + Send + Sync + 'static,
    Pool: TransactionPool + 'static,
    Pool::Transaction: MaybeConditionalTransaction,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
{
    async move {
        maintain_transaction_pool_conditional(client, pool, events).await;
    }
    .boxed()
}

/// Maintains the state of the conditional tx in the transaction pool by handling new blocks and
/// reorgs.
///
/// On every new canonical head this evicts a pooled conditional transaction when
/// either:
/// - its block-number / timestamp ceilings have been exceeded (the condition can
///   never be met again), or
/// - its `knownAccounts` predicates no longer match the new head's state
///   (TEAO1-167) — otherwise a transaction conditioned on, say, the
///   `GasPriceOracle` price-ratio slot would linger in the pool and could be
///   included under a different value than it required.
///
/// The `knownAccounts` re-check is **fail-open**: any state-read failure leaves
/// the transaction in place (we never evict on a bad read). It is also defence in
/// depth for the *cross-block* case — the same-block case, where the head's
/// L1-attributes transaction refreshes the watched slot before a later conditional
/// transaction in that very block, is closed in the payload builder, which
/// re-checks `knownAccounts` against the actual pending execution state.
pub async fn maintain_transaction_pool_conditional<N, Client, Pool, St>(
    client: Client,
    pool: Pool,
    mut events: St,
) where
    N: NodePrimitives,
    Client: StateProviderFactory + Send + Sync,
    Pool: TransactionPool,
    Pool::Transaction: MaybeConditionalTransaction,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
{
    let metrics = MaintainPoolConditionalMetrics::default();
    loop {
        let Some(event) = events.next().await else { break };
        if let CanonStateNotification::Commit { new } = event {
            let block_attr = BlockConditionalAttributes {
                number: new.tip().number(),
                timestamp: new.tip().timestamp(),
            };

            // Post-head state for re-checking `knownAccounts` predicates. Fail-open:
            // if it is unavailable we only apply the block-attribute ceilings this
            // round and never evict on a bad read.
            let state = client.latest().ok();

            let mut to_remove = Vec::new();
            let mut known_accounts_evicted = 0usize;
            for tx in &pool.pooled_transactions() {
                if tx.transaction.has_exceeded_block_attributes(&block_attr) {
                    to_remove.push(*tx.hash());
                    continue;
                }

                // TEAO1-167: evict conditionals whose watched `knownAccounts` no
                // longer hold against the new head.
                if let (Some(state), Some(cond)) = (state.as_ref(), tx.transaction.conditional()) &&
                    matches!(
                        first_known_account_violation(
                            cond,
                            |address, slot| state
                                .storage(address, StorageKey::from(slot))
                                .map(|v| v.unwrap_or_default()),
                            |address| state.storage_root(address, Default::default()).map(Some),
                        ),
                        Ok(Some(_))
                    )
                {
                    to_remove.push(*tx.hash());
                    known_accounts_evicted += 1;
                }
            }

            if !to_remove.is_empty() {
                let removed = pool.remove_transactions(to_remove);
                metrics.inc_removed_tx_conditional(removed.len());
            }
            if known_accounts_evicted > 0 {
                metrics.inc_removed_tx_conditional_known_accounts(known_accounts_evicted);
            }
        }
    }
}

/// Returns a spawnable future for maintaining the state of the interop tx in the transaction pool.
pub fn maintain_transaction_pool_interop_future<N, Pool, St>(
    pool: Pool,
    events: St,
    supervisor_client: SupervisorClient,
) -> BoxFuture<'static, ()>
where
    N: NodePrimitives,
    Pool: TransactionPool + 'static,
    Pool::Transaction: MaybeInteropTransaction,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
{
    async move {
        maintain_transaction_pool_interop(pool, events, supervisor_client).await;
    }
    .boxed()
}

/// Maintains the state of the interop tx in the transaction pool by handling new blocks and reorgs.
///
/// This listens for any new blocks and reorgs and updates the interop tx in the transaction pool's
/// state accordingly
pub async fn maintain_transaction_pool_interop<N, Pool, St>(
    pool: Pool,
    mut events: St,
    supervisor_client: SupervisorClient,
) where
    N: NodePrimitives,
    Pool: TransactionPool,
    Pool::Transaction: MaybeInteropTransaction,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
{
    let metrics = MaintainPoolInteropMetrics::default();

    loop {
        let Some(event) = events.next().await else { break };
        if let CanonStateNotification::Commit { new } = event {
            let timestamp = new.tip().timestamp();
            let mut to_remove = Vec::new();
            let mut to_revalidate = Vec::new();
            let mut interop_count = 0;

            // scan all pooled interop transactions
            for pooled_tx in pool.pooled_transactions() {
                if let Some(interop_deadline_val) = pooled_tx.transaction.interop_deadline() {
                    interop_count += 1;
                    if !is_valid_interop(interop_deadline_val, timestamp) {
                        to_remove.push(*pooled_tx.transaction.hash());
                    } else if is_stale_interop(interop_deadline_val, timestamp, OFFSET_TIME) {
                        to_revalidate.push(pooled_tx.transaction.clone());
                    }
                }
            }

            metrics.set_interop_txs_in_pool(interop_count);

            if !to_revalidate.is_empty() {
                metrics.inc_stale_tx_interop(to_revalidate.len());

                let revalidation_start = Instant::now();
                let revalidation_stream = supervisor_client.revalidate_interop_txs_stream(
                    to_revalidate,
                    timestamp,
                    TRANSACTION_VALIDITY_WINDOW,
                    MAX_SUPERVISOR_QUERIES,
                );

                futures_util::pin_mut!(revalidation_stream);

                while let Some((tx_item_from_stream, validation_result)) =
                    revalidation_stream.next().await
                {
                    match validation_result {
                        Some(Ok(())) => {
                            tx_item_from_stream
                                .set_interop_deadline(timestamp + TRANSACTION_VALIDITY_WINDOW);
                        }
                        Some(Err(err)) => {
                            if err.is_bad_transaction() {
                                to_remove.push(*tx_item_from_stream.hash());
                            }
                        }
                        None => {
                            warn!(
                                target: "txpool",
                                hash = %tx_item_from_stream.hash(),
                                "Interop transaction no longer considered cross-chain during revalidation; removing."
                            );
                            to_remove.push(*tx_item_from_stream.hash());
                        }
                    }
                }

                metrics.record_supervisor_duration(revalidation_start.elapsed());
            }

            if !to_remove.is_empty() {
                let removed = pool.remove_transactions(to_remove);
                metrics.inc_removed_tx_interop(removed.len());
            }
        }
    }
}

/// Transaction pool maintenance metrics for L1-fee-driven eviction.
#[derive(Metrics)]
#[metrics(scope = "transaction_pool")]
struct MaintainPoolL1FeeMetrics {
    /// Counter for transactions evicted because, after a new head, their sender
    /// can no longer cover the (Tea-multiplier-scaled) L1 data fee.
    removed_tx_l1_fee: Counter,
}

impl MaintainPoolL1FeeMetrics {
    #[inline]
    fn inc_removed_tx_l1_fee(&self, count: usize) {
        self.removed_tx_l1_fee.increment(count as u64);
    }
}

/// Affordability test: can the sender's `balance` cover the transaction's own
/// upfront `cost` plus the (already-scaled) L1 data fee?
///
/// Conservative by construction — a transaction that can't pay its own single
/// cost can never be included, so acting on this can never drop an *includable*
/// transaction. Multi-nonce cumulative affordability stays the generic pool's
/// job (this only adds the OP/Tea L1 dimension the generic pool is blind to).
#[inline]
fn is_unaffordable_at_l1_fee(balance: U256, tx_cost: U256, scaled_l1_fee: U256) -> bool {
    balance < tx_cost.saturating_add(scaled_l1_fee)
}

/// The complete per-transaction eviction policy for the head-driven L1-fee
/// eviction task (TEAO1-151). Returns `true` iff the pooled transaction should be
/// removed from the pool.
///
/// This is the single source of truth for the policy and is exhaustively
/// unit-tested; the maintenance loop is a thin I/O wrapper that supplies the
/// inputs (origin, balance, cost, raw OP L1 fee, oracle slot) and acts on the
/// result. Encodes three things:
/// - **local exemption**: the operator's own (local) txs are never evicted
///   (mirrors reth's stale-eviction local exemption);
/// - **Tea multiplier**: the raw OP L1 fee is scaled by the GasPriceOracle
///   TEA/ETH ratio via the *same* [`scale_l1_cost_by_oracle`] the validator uses
///   at admission (zero slot → backup rate), so eviction and admission/execution
///   agree;
/// - **affordability**: evict only when `balance < cost + scaled_l1_fee`.
#[inline]
fn should_evict(
    is_local: bool,
    balance: U256,
    tx_cost: U256,
    raw_l1_fee: U256,
    oracle_slot: U256,
) -> bool {
    if is_local {
        return false;
    }
    let scaled_l1_fee = scale_l1_cost_by_oracle(raw_l1_fee, oracle_slot);
    is_unaffordable_at_l1_fee(balance, tx_cost, scaled_l1_fee)
}

/// Returns a spawnable future for evicting pooled txs that can no longer pay the
/// Tea-scaled L1 data fee after a new head (TEAO1-151).
pub fn maintain_transaction_pool_tea_l1_fee_eviction_future<N, Client, Pool, St>(
    client: Client,
    pool: Pool,
    events: St,
) -> BoxFuture<'static, ()>
where
    N: NodePrimitives,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: OpHardforks>
        + Clone
        + Send
        + Sync
        + 'static,
    Pool: TransactionPool + 'static,
    Pool::Transaction: OpPooledTx,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
{
    async move {
        maintain_transaction_pool_tea_l1_fee_eviction(client, pool, events).await;
    }
    .boxed()
}

/// Evicts pooled transactions whose sender can no longer pay the Tea-scaled L1
/// data fee once a new head changes the fee state (TEAO1-151).
///
/// Background: reth's pool re-buckets pooled txs across pending/basefee/queued on
/// a new head using only each tx's static `cost` (`value + gas·max_fee (+ blob)`)
/// and the *changed* accounts' refreshed balances. It does **not** re-run the
/// validator (`apply_op_checks`) on pooled txs, so the OP/Tea L1 data-fee add-on
/// — which is computed at admission and never stored on the tx — is never
/// re-checked. A tx admitted while the TEA/ETH multiplier (or OP base fee) was
/// low therefore lingers in `pending` after a head raises it, resurfacing to the
/// payload builder until execution rejects it.
///
/// This task closes that gap: on each `Commit`, it recomputes the current
/// L1-fee inputs (from the new tip's L1-attributes tx plus the post-head
/// GasPriceOracle multiplier slot) and evicts any *external* pooled tx whose
/// sender can't afford `cost + scaled_l1_fee`.
///
/// Notes:
/// - **Local txs are exempt** (mirrors reth's stale-eviction local exemption):
///   pool pollution is the gossip problem, and we don't drop the operator's own
///   submissions.
/// - **Evict, not demote**: the public pool API only exposes
///   [`TransactionPool::remove_transactions`], so an evicted tx must be
///   resubmitted if the fee later falls. Acceptable because Tea's multiplier and
///   the fixed backup rate move slowly.
/// - **Fail-open**: any missing/erroring input (no L1-attributes tx, state read
///   error, fee-calc error) skips the round or the tx — never evict on bad data.
pub async fn maintain_transaction_pool_tea_l1_fee_eviction<N, Client, Pool, St>(
    client: Client,
    pool: Pool,
    mut events: St,
) where
    N: NodePrimitives,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: OpHardforks> + Clone + Send + Sync,
    Pool: TransactionPool,
    Pool::Transaction: OpPooledTx,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
{
    let metrics = MaintainPoolL1FeeMetrics::default();

    // Tea-only: off-Tea we never scale, and we deliberately do not change generic
    // OP eviction behavior (that is upstream's concern). The spawn site already
    // gates on `is_tea`; guard here too so the task is an inert no-op if misused.
    if !tea_l1_cost::is_tea(client.chain_spec().chain().id()) {
        return;
    }

    loop {
        let Some(event) = events.next().await else { break };
        let CanonStateNotification::Commit { new } = event else { continue };

        let tip = new.tip();
        let timestamp = tip.timestamp();

        // Post-head L1 fee inputs: rebuild L1BlockInfo from the new tip's first tx
        // (the L1-attributes deposit), exactly as the validator does on a new head.
        let Some(first_tx) = tip.body().transactions().first() else { continue };
        let Ok(l1_block_info) = extract_l1_info_from_tx(first_tx) else { continue };

        // Read post-head state once: the GasPriceOracle TEA/ETH multiplier slot.
        let Ok(state) = client.latest() else { continue };
        let oracle_slot = state
            .storage(tea_l1_cost::GAS_PRICE_ORACLE_ADDR, tea_l1_cost::LATEST_PRICE_RATIO_SLOT)
            .ok()
            .flatten()
            .unwrap_or_default();

        let chain_spec = client.chain_spec();
        let mut balances: HashMap<Address, U256> = HashMap::new();
        let mut to_remove = Vec::new();

        for vtx in pool.pooled_transactions() {
            // Cheap early exit for the operator's own txs — also encoded in
            // `should_evict`, but avoids the per-tx I/O below for exempt txs.
            let is_local = vtx.origin.is_local();
            if is_local {
                continue;
            }

            // Raw OP L1 data fee for this tx under the post-head L1 block info.
            let mut l1_info = l1_block_info.clone();
            let encoded = vtx.transaction.encoded_2718();
            let raw_l1 = match l1_info.l1_tx_data_fee(
                chain_spec.clone(),
                timestamp,
                encoded.as_ref(),
                false,
            ) {
                Ok(cost) => cost,
                // Fee-calc error: never evict on bad data.
                Err(_) => continue,
            };

            let sender = vtx.sender();
            let balance = match balances.entry(sender) {
                Entry::Occupied(e) => *e.get(),
                Entry::Vacant(e) => match state.account_balance(&sender) {
                    // `None` => non-existent/empty account => 0 balance.
                    Ok(b) => *e.insert(b.unwrap_or_default()),
                    // Provider error: skip this tx, never evict on a failed read.
                    Err(_) => continue,
                },
            };

            if should_evict(is_local, balance, *vtx.cost(), raw_l1, oracle_slot) {
                to_remove.push(*vtx.hash());
            }
        }

        if !to_remove.is_empty() {
            let count = to_remove.len();
            let removed = pool.remove_transactions(to_remove);
            metrics.inc_removed_tx_l1_fee(removed.len());
            debug!(
                target: "txpool",
                evicted = removed.len(),
                candidates = count,
                block = tip.number(),
                "Evicted pooled txs that can no longer pay the L1 data fee (TEAO1-151)"
            );
        }
    }
}

#[cfg(test)]
mod l1_fee_eviction_tests {
    //! Tests for the head-driven L1-fee eviction policy (TEAO1-151).
    //!
    //! Each test below maps to a specific item on the finding's fix checklist.
    //! `should_evict` is the single source of truth for the policy the
    //! maintenance loop applies per transaction, so exercising it covers the
    //! decision the loop makes on every new head.
    use super::{is_unaffordable_at_l1_fee, should_evict};
    use alloy_primitives::U256;

    const EXTERNAL: bool = false;
    const LOCAL: bool = true;

    fn wei(n: u64) -> U256 {
        U256::from(n)
    }

    /// 1× (WAD) oracle ratio: the raw OP L1 fee passes through unscaled, so we can
    /// reason about explicit fee amounts in the checklist tests below.
    fn unit() -> U256 {
        tea_l1_cost::WAD
    }

    // ── Checklist item 1: "Add an OP-aware affordability dimension to pooled
    //    transaction state." ───────────────────────────────────────────────────
    //
    // The eviction decision must include the OP/Tea L1 data fee — the dimension
    // the generic pool is blind to. A tx that is affordable on its base `cost`
    // alone becomes evictable once the L1 fee is folded in.
    #[test]
    fn item1_l1_fee_is_an_affordability_dimension() {
        let balance = wei(1_000);
        let tx_cost = wei(950);
        // Base cost alone fits (950 <= 1000): without the L1 dimension it'd stay.
        assert!(!should_evict(EXTERNAL, balance, tx_cost, U256::ZERO, unit()));
        // Add a raw L1 fee of 100 (950 + 100 > 1000): the L1 dimension flips it.
        assert!(should_evict(EXTERNAL, balance, tx_cost, wei(100), unit()));
    }

    // ── Checklist item 2: "Recompute OP execution affordability for existing
    //    pooled transactions after on_new_head_block()." ───────────────────────
    //
    // The loop rebuilds the L1 inputs (oracle ratio + L1 block info) on every
    // Commit, so the SAME pooled tx/balance is re-judged against the CURRENT
    // ratio. A head that raises the TEA/ETH ratio must flip a previously-kept tx
    // to evicted — that is the recompute behavior.
    #[test]
    fn item2_recompute_on_rate_rise_flips_to_evict() {
        let balance = wei(1_000);
        let tx_cost = wei(900);
        let raw_l1 = wei(50);
        // Head N: 1× ratio -> scaled fee 50 -> 900+50 <= 1000 -> kept.
        assert!(!should_evict(EXTERNAL, balance, tx_cost, raw_l1, unit()));
        // Head N+1 raises the ratio to 3× -> scaled fee 150 -> 900+150 > 1000 ->
        // recompute now evicts the very same tx.
        let triple = U256::from(3u64) * tea_l1_cost::WAD;
        assert!(should_evict(EXTERNAL, balance, tx_cost, raw_l1, triple));
    }

    // ── Checklist item 3: "Demote or evict transactions that fail the refreshed
    //    affordability check." ──────────────────────────────────────────────────
    //
    // (a) An external tx that fails the check is evicted; (b) an affordable tx is
    // kept (incl. the exact-balance boundary); (c) a LOCAL tx is exempt and is
    // never evicted even when unaffordable.
    #[test]
    fn item3a_evicts_failing_external_tx() {
        assert!(should_evict(EXTERNAL, wei(1_000), wei(900), wei(200), unit()));
    }

    #[test]
    fn item3b_keeps_affordable_tx_incl_exact_balance() {
        // Comfortably affordable.
        assert!(!should_evict(EXTERNAL, wei(1_000), wei(700), wei(100), unit()));
        // Exact boundary: balance == cost + fee is affordable, not evicted.
        assert!(!should_evict(EXTERNAL, wei(1_000), wei(800), wei(200), unit()));
    }

    #[test]
    fn item3c_local_tx_is_exempt_even_when_unaffordable() {
        // Identical inputs that evict an external tx must NOT evict a local one.
        assert!(should_evict(EXTERNAL, wei(100), wei(900), wei(200), unit()));
        assert!(!should_evict(LOCAL, wei(100), wei(900), wei(200), unit()));
    }

    // ── Checklist item 4: "Plumb l1_cost_multiplier into validator-side
    //    affordability." (Here: into eviction-side affordability, via the SAME
    //    `scale_l1_cost_by_oracle` the admission path uses — TEAO1-175/186.) ─────
    //
    // The oracle ratio scales the fee that feeds the decision: a populated ratio
    // multiplies it, and a zero/unset slot falls back to the 1,500,000× backup
    // rate — matching admission and execution so all three agree.
    #[test]
    fn item4_multiplier_scaling_feeds_eviction_decision() {
        let balance = wei(1_000);
        let tx_cost = wei(900);
        let raw_l1 = wei(40);
        // 1× ratio -> 40 -> affordable.
        assert!(!should_evict(EXTERNAL, balance, tx_cost, raw_l1, unit()));
        // 3× ratio -> 120 -> 900+120 > 1000 -> evict (multiplier plumbed through).
        let triple = U256::from(3u64) * tea_l1_cost::WAD;
        assert!(should_evict(EXTERNAL, balance, tx_cost, raw_l1, triple));
    }

    #[test]
    fn item4_zero_oracle_uses_backup_rate_in_eviction() {
        // Zero slot => backup 1,500,000× rate. Even a tiny raw L1 fee of 1 wei
        // scales to 1,500,000 wei, dwarfing a small balance -> evict.
        assert!(should_evict(EXTERNAL, wei(1_000), wei(0), wei(1), U256::ZERO));
        // ... and admission/execution apply the identical backup, so they agree.
    }

    // ── Conservativeness invariant: saturating arithmetic must never wrap a huge
    //    (cost + fee) back to "affordable". ─────────────────────────────────────
    #[test]
    fn saturating_add_never_wraps_to_affordable() {
        assert!(is_unaffordable_at_l1_fee(U256::MAX - U256::from(1u64), U256::MAX, U256::MAX));
    }
}
