//! Additional support for pooled transactions with [`TransactionConditional`]

use alloy_consensus::conditional::BlockConditionalAttributes;
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_eth::erc4337::{AccountStorage, TransactionConditional};

/// Helper trait that allows attaching a [`TransactionConditional`].
pub trait MaybeConditionalTransaction {
    /// Attach a [`TransactionConditional`].
    fn set_conditional(&mut self, conditional: TransactionConditional);

    /// Get attached [`TransactionConditional`] if any.
    fn conditional(&self) -> Option<&TransactionConditional>;

    /// Check if the conditional has exceeded the block attributes.
    fn has_exceeded_block_attributes(&self, block_attr: &BlockConditionalAttributes) -> bool {
        self.conditional().map(|tc| tc.has_exceeded_block_attributes(block_attr)).unwrap_or(false)
    }

    /// Helper that sets the conditional and returns the instance again
    fn with_conditional(mut self, conditional: TransactionConditional) -> Self
    where
        Self: Sized,
    {
        self.set_conditional(conditional);
        self
    }
}

/// A `knownAccounts` predicate that is *definitively* violated against some state.
///
/// "Definitively" means the state was read successfully and disagrees with the
/// required value — distinct from a read that could not be performed (surfaced as
/// `Err` from [`first_known_account_violation`]) or a predicate the caller's view
/// cannot evaluate at all (a `RootHash` against a reader with no storage trie,
/// which is skipped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownAccountViolation {
    /// A watched storage slot no longer holds the required value.
    Slot {
        /// Account whose slot changed.
        address: Address,
        /// The watched storage slot.
        slot: U256,
    },
    /// A watched account's storage root no longer matches the required hash.
    Root {
        /// Account whose storage root changed.
        address: Address,
    },
}

/// Evaluate a conditional's [`TransactionConditional::known_accounts`] predicates
/// against caller-supplied state readers, returning the first definitive
/// violation (if any).
///
/// This is the single source of truth for *what a `knownAccounts` predicate means*
/// and is shared by the three places that must agree (TEAO1-167): RPC admission
/// ([`send_raw_transaction_conditional`]), head-driven pool eviction, and the
/// payload builder's pre-execution re-check.
///
/// The readers are closures so each caller can supply whatever state view it has:
/// - `read_slot(address, slot)` returns the slot's current value (an absent slot
///   reads as zero — the caller's closure decides that).
/// - `read_root(address)` returns the account's storage root, or `None` when the
///   caller's view cannot compute one. The payload builder runs against a bare
///   revm `Database`, which has no storage trie, so it passes `|_| Ok(None)`;
///   `RootHash` predicates are then skipped at build time and remain enforced at
///   admission and head eviction (both of which run against a full state provider).
///
/// Returns `Ok(None)` when every *evaluable* predicate holds, `Ok(Some(..))` for
/// the first definitive violation, or `Err(E)` if a state read failed — the caller
/// decides whether a read error means reject (admission) or fail-open (eviction /
/// build, where acting on a bad read could drop an includable transaction).
///
/// [`send_raw_transaction_conditional`]: https://docs.optimism.io/builders/app-developers/transactions/conditional-transactions
pub fn first_known_account_violation<E, S, R>(
    cond: &TransactionConditional,
    mut read_slot: S,
    mut read_root: R,
) -> Result<Option<KnownAccountViolation>, E>
where
    S: FnMut(Address, U256) -> Result<U256, E>,
    R: FnMut(Address) -> Result<Option<B256>, E>,
{
    for (address, storage) in &cond.known_accounts {
        match storage {
            AccountStorage::Slots(slots) => {
                for (slot, expected) in slots {
                    if read_slot(*address, *slot)? != U256::from_be_bytes(expected.0) {
                        return Ok(Some(KnownAccountViolation::Slot { address: *address, slot: *slot }));
                    }
                }
            }
            AccountStorage::RootHash(expected_root) => {
                // Skipped when the reader cannot produce a root (e.g. the builder's
                // revm DB); enforced at admission + head eviction instead.
                if let Some(actual) = read_root(*address)? &&
                    *expected_root != actual
                {
                    return Ok(Some(KnownAccountViolation::Root { address: *address }));
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod known_accounts_tests {
    //! Tests for [`first_known_account_violation`] — the single decision shared by
    //! all three TEAO1-167 call sites (RPC admission, head-driven eviction, the
    //! payload builder's pre-execution re-check). Each test below is tagged with the
    //! fix-checklist item it covers and exercises the decision *through the exact
    //! reader shape* the corresponding leg uses, so passing here means the leg makes
    //! the right include / evict / reject call.
    use super::*;
    use alloy_primitives::map::HashMap as AlloyMap;
    use alloy_rpc_types_eth::erc4337::TransactionConditional;
    use std::convert::Infallible;

    fn addr(n: u8) -> Address {
        Address::with_last_byte(n)
    }

    /// A conditional watching one account's storage slots.
    fn cond_slots(account: Address, slots: &[(U256, B256)]) -> TransactionConditional {
        let mut map = AlloyMap::default();
        for (slot, expected) in slots {
            map.insert(*slot, *expected);
        }
        let mut tc = TransactionConditional::default();
        tc.known_accounts.insert(account, AccountStorage::Slots(map));
        tc
    }

    /// A conditional watching one account's storage root.
    fn cond_root(account: Address, root: B256) -> TransactionConditional {
        let mut tc = TransactionConditional::default();
        tc.known_accounts.insert(account, AccountStorage::RootHash(root));
        tc
    }

    /// Slot reader backed by an in-memory map (absent slot => zero), modelling the
    /// state a leg reads — the builder's pending revm DB or a full state provider.
    fn slot_reader(
        entries: Vec<((Address, U256), U256)>,
    ) -> impl FnMut(Address, U256) -> Result<U256, Infallible> {
        move |a, s| {
            Ok(entries
                .iter()
                .find(|((ea, es), _)| *ea == a && *es == s)
                .map(|(_, v)| *v)
                .unwrap_or_default())
        }
    }

    /// The **builder leg** decision: reads slots from the pending execution state and
    /// has no storage trie (revm `Database`), so `RootHash` predicates are skipped.
    /// Returns `true` when the builder would exclude the tx before execution.
    fn builder_excludes(cond: &TransactionConditional, db: Vec<((Address, U256), U256)>) -> bool {
        matches!(
            first_known_account_violation(cond, slot_reader(db), |_| Ok::<_, Infallible>(None)),
            Ok(Some(_))
        )
    }

    /// The **head-eviction leg** decision: a full state provider can read both slots
    /// and storage roots. Returns `true` when the tx would be evicted on the new head.
    fn head_evicts(
        cond: &TransactionConditional,
        db: Vec<((Address, U256), U256)>,
        root: Option<B256>,
    ) -> bool {
        matches!(
            first_known_account_violation(cond, slot_reader(db), move |_| Ok::<_, Infallible>(root)),
            Ok(Some(_))
        )
    }

    // ── Checklist item 1: "Revalidate `knownAccounts` immediately before executing
    //    each pooled conditional transaction." (payload builder leg) ──────────────
    //
    // This is the load-bearing fix: the watched slot (the GasPriceOracle TEA/ETH
    // ratio) is refreshed by the L1-attributes deposit at the top of the very block
    // being built, so the re-check must run against the pending build state. A tx
    // whose required slot value no longer holds must be excluded; one that still
    // holds must be admitted to execution.
    #[test]
    fn item1_builder_excludes_when_watched_slot_changed() {
        let oracle = addr(0x42);
        let ratio_slot = U256::from(1);
        // Conditioned on ratio == R_old (7).
        let cond = cond_slots(oracle, &[(ratio_slot, B256::with_last_byte(7))]);

        // Pending build state still holds R_old => included.
        assert!(!builder_excludes(&cond, vec![((oracle, ratio_slot), U256::from(7))]));
        // L1-attributes tx flipped it to R_new (9) => excluded before execution.
        assert!(builder_excludes(&cond, vec![((oracle, ratio_slot), U256::from(9))]));
    }

    #[test]
    fn item1_violation_identifies_the_offending_slot() {
        let a = addr(1);
        let cond = cond_slots(a, &[(U256::from(3), B256::with_last_byte(7))]);
        assert_eq!(
            first_known_account_violation(
                &cond,
                slot_reader(vec![((a, U256::from(3)), U256::from(9))]),
                |_| Ok::<_, Infallible>(None),
            ),
            Ok(Some(KnownAccountViolation::Slot { address: a, slot: U256::from(3) }))
        );
    }

    // ── Checklist item 2: "Evict pooled conditional transactions on new canonical
    //    heads when their account or storage predicates no longer match."
    //    (head-eviction leg — has a full state provider, so BOTH predicate kinds) ──
    #[test]
    fn item2_head_evicts_on_changed_slot() {
        let a = addr(1);
        let cond = cond_slots(a, &[(U256::from(3), B256::with_last_byte(7))]);
        // Unchanged => kept.
        assert!(!head_evicts(&cond, vec![((a, U256::from(3)), U256::from(7))], None));
        // Changed => evicted.
        assert!(head_evicts(&cond, vec![((a, U256::from(3)), U256::from(9))], None));
    }

    #[test]
    fn item2_head_evicts_on_changed_storage_root() {
        // RootHash predicates are evaluable on the eviction leg (full provider) even
        // though the builder leg skips them.
        let a = addr(1);
        let cond = cond_root(a, B256::with_last_byte(42));
        // Root matches => kept.
        assert!(!head_evicts(&cond, vec![], Some(B256::with_last_byte(42))));
        // Root changed => evicted.
        assert!(head_evicts(&cond, vec![], Some(B256::with_last_byte(99))));
        assert_eq!(
            first_known_account_violation(
                &cond,
                slot_reader(vec![]),
                |_| Ok::<_, Infallible>(Some(B256::with_last_byte(99))),
            ),
            Ok(Some(KnownAccountViolation::Root { address: a }))
        );
    }

    // ── Checklist item 3: "Validate admission against the actual pending execution
    //    state when sequencer builds can diverge from `Latest`." ───────────────────
    //
    // Admission validated the conditional against `Latest` (= R_old) and let it into
    // the pool. The builder must NOT trust that: it re-reads the slot from the state
    // it will actually execute on. Here the pending build state diverges from
    // `Latest` (it already applied the ratio flip to R_new), and the builder catches
    // it where a `Latest`-based check would have wrongly passed the tx.
    #[test]
    fn item3_builder_uses_pending_state_not_latest() {
        let oracle = addr(0x42);
        let ratio_slot = U256::from(1);
        let cond = cond_slots(oracle, &[(ratio_slot, B256::with_last_byte(7))]);

        // A `Latest`-shaped reader (still R_old) would see no violation...
        let latest = vec![((oracle, ratio_slot), U256::from(7))];
        assert!(!builder_excludes(&cond, latest));
        // ...but the builder reads the *pending* state (already R_new) and excludes.
        let pending = vec![((oracle, ratio_slot), U256::from(9))];
        assert!(builder_excludes(&cond, pending));
    }

    // ── Supporting mechanism guarantees relied on by the legs above. ─────────────

    #[test]
    fn absent_slot_reads_as_zero() {
        let a = addr(1);
        // Required value is zero and the slot is unset => matches (no violation).
        let cond = cond_slots(a, &[(U256::from(3), B256::ZERO)]);
        assert!(!builder_excludes(&cond, vec![]));
    }

    #[test]
    fn root_hash_is_skipped_by_builder_leg() {
        // A RootHash predicate must NOT be treated as violated just because the revm
        // DB cannot compute a root — it is enforced at admission + head eviction.
        let a = addr(1);
        let cond = cond_root(a, B256::with_last_byte(42));
        assert!(!builder_excludes(&cond, vec![]));
    }

    #[test]
    fn first_matching_predicate_holds_means_no_violation() {
        // Multiple slots across multiple accounts, all satisfied.
        let a = addr(1);
        let b = addr(2);
        let mut cond = cond_slots(a, &[(U256::from(1), B256::with_last_byte(10))]);
        cond.known_accounts.insert(b, {
            let mut m = AlloyMap::default();
            m.insert(U256::from(2), B256::with_last_byte(20));
            AccountStorage::Slots(m)
        });
        let db = vec![
            ((a, U256::from(1)), U256::from(10)),
            ((b, U256::from(2)), U256::from(20)),
        ];
        assert!(!builder_excludes(&cond, db));
    }

    #[test]
    fn read_error_is_surfaced_for_caller_policy() {
        // A failed read is Err so each caller applies its own policy: admission
        // rejects (propagates), while eviction/build fail-open. The `matches!(_,
        // Ok(Some(_)))` the latter two use treats Err as "not a violation".
        let a = addr(1);
        let cond = cond_slots(a, &[(U256::from(3), B256::with_last_byte(7))]);
        let err = first_known_account_violation(
            &cond,
            |_: Address, _: U256| Err::<U256, _>("boom"),
            |_: Address| Err::<Option<B256>, _>("boom"),
        );
        assert_eq!(err, Err("boom"));
        // Fail-open: eviction/build do not act on a read error.
        assert!(!matches!(err, Ok(Some(_))));
    }
}
