//! TEAO1-178: per-thread handoff of the block-scoped (parent) GasPriceOracle
//! ratio from the RPC trace/replay machinery to the Tea EVM factory.
//!
//! # Why this exists
//!
//! Tea snapshots the TEA/ETH L1-cost multiplier once, at block-EVM
//! construction, from the GasPriceOracle price-ratio slot as it stands at the
//! *start* of the block (i.e. the parent block's settled state), and op-revm
//! preserves it across the per-tx `L1BlockInfo` reloads. Every tx in the block
//! is therefore charged with that one parent-state ratio — intentionally, so a
//! flash-loan-manipulable same-block oracle update can't move the fee
//! (Cantina TEAO1-147, Won't-fix).
//!
//! Transaction-level replay helpers (`trace_transaction`, `replay_transaction`,
//! `debug_traceTransaction`, otterscan) work differently: they replay the
//! earlier transactions of the block into a mutable DB and then build a *fresh*
//! EVM for the target transaction. On a block whose first (L1-attributes) tx
//! updates the oracle slot, that fresh EVM would re-read the *mutated* slot and
//! charge a different `l1_cost_multiplier` than canonical execution did — so the
//! trace's fee and balance results would diverge from the chain (TEAO1-178).
//!
//! The fix has to set the multiplier *field* (`ctx.chain.l1_cost_multiplier`)
//! to the parent-state ratio without altering the DB the target tx executes
//! against — a contract that `SLOAD`s the oracle slot during the traced tx must
//! still observe the post-update value, exactly as it would on-chain. Only the
//! concrete [`TeaEvmFactory`](../tea_reth) sets that field, and the RPC layer
//! that knows the parent-state ratio reaches the factory only through reth's
//! generic `ConfigureEvm` seam, whose trait bounds rule out wrapping the DB.
//!
//! This crate bridges the two with a tiny per-thread cell: the RPC replay
//! override [`set_parent_oracle`] records the parent-block ratio after replaying
//! the earlier txs, and the factory [`take_parent_oracle`] consumes it when it
//! builds the target EVM.
//!
//! # Safety of the handoff
//!
//! Reth runs each replay+trace closure synchronously on one blocking-pool
//! thread, so producer and consumer share a thread with no `await` between them.
//! [`take_parent_oracle`] is keyed by block number and *always* clears the cell,
//! so a record can be consumed at most once and a stale record (e.g. left by a
//! replay that errored before its target EVM was built) can never leak into an
//! unrelated EVM construction — at worst it is discarded. The producer records
//! *after* the replay loop, so the replay's own EVM reads the parent ratio
//! straight from its (still-parent) DB and never consumes the record meant for
//! the target.

use alloy_primitives::U256;
use std::cell::Cell;

thread_local! {
    /// `(block_number, raw_oracle_slot_value)` recorded for the next target EVM
    /// built on this thread, or `None`.
    static PARENT_ORACLE: Cell<Option<(u64, U256)>> = const { Cell::new(None) };
}

/// Record the parent-block GasPriceOracle price-ratio slot value that the target
/// trace/replay EVM for `block_number` must use, instead of the post-replay
/// (mutated) slot. Call this *after* replaying the block's earlier transactions.
pub fn set_parent_oracle(block_number: u64, oracle_raw: U256) {
    PARENT_ORACLE.with(|cell| cell.set(Some((block_number, oracle_raw))));
}

/// Consume the parent-block oracle ratio recorded for `block_number`.
///
/// Always clears the cell. Returns `Some(raw)` only when a record is present and
/// its block number matches, so a stale or mismatched record is discarded rather
/// than applied to the wrong EVM.
pub fn take_parent_oracle(block_number: u64) -> Option<U256> {
    PARENT_ORACLE.with(|cell| match cell.take() {
        Some((recorded_block, raw)) if recorded_block == block_number => Some(raw),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recorded ratio is returned exactly once for the matching block, then
    /// the cell is empty — the target EVM consumes it and nothing else can.
    #[test]
    fn records_and_consumes_once() {
        let raw = U256::from(123u64);
        set_parent_oracle(42, raw);
        assert_eq!(take_parent_oracle(42), Some(raw), "target EVM gets the recorded ratio");
        assert_eq!(take_parent_oracle(42), None, "second read finds the cell cleared");
    }

    /// A record for one block is never applied to an EVM built for another block,
    /// and the mismatched read still clears the cell so it cannot leak further.
    #[test]
    fn mismatched_block_is_discarded() {
        set_parent_oracle(7, U256::from(999u64));
        assert_eq!(take_parent_oracle(8), None, "ratio recorded for block 7 must not apply to 8");
        assert_eq!(take_parent_oracle(7), None, "the mismatched read cleared the stale record");
    }

    /// With no record (normal block execution / `eth_call`), the consumer gets
    /// `None` and falls back to its live DB read.
    #[test]
    fn absent_record_is_none() {
        // Ensure clean state on this thread first.
        let _ = take_parent_oracle(0);
        assert_eq!(take_parent_oracle(1), None);
    }
}
