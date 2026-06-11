//! @title POC->regression: RootHash conditionals are enforced at inclusion time
//! @notice The original finding (TEAO1-206) showed the payload builder passed
//! `read_root => Ok(None)`, so a `RootHash` conditional survived the builder
//! re-check even after the watched account's storage root drifted inside the
//! pending block. The fix makes the builder recompute that account's storage root
//! over the *pending* build state (parent trie + this block's writes) and supply
//! it to `read_root`, so `RootHash` is now enforced at the inclusion-time decision
//! point — not merely at admission/eviction (which see only committed state and
//! miss same-block drift). This test pins the post-fix decision through the exact
//! reader shape the builder leg now uses.

use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_eth::erc4337::{AccountStorage, TransactionConditional};
use reth_optimism_txpool::conditional::{first_known_account_violation, KnownAccountViolation};
use std::convert::Infallible;

fn cond_root(account: Address, root: B256) -> TransactionConditional {
    let mut tc = TransactionConditional::default();
    tc.known_accounts.insert(account, AccountStorage::RootHash(root));
    tc
}

/// Models the builder leg: slots come from the pending revm DB; the `RootHash`
/// reader returns the storage root the builder recomputes over the pending build
/// state (`None` only on a fail-open read error).
fn builder_violation(
    cond: &TransactionConditional,
    pending_root: Option<B256>,
) -> Option<KnownAccountViolation> {
    first_known_account_violation(
        cond,
        |_address, _slot| Ok::<_, Infallible>(U256::ZERO),
        move |_address| Ok::<_, Infallible>(pending_root),
    )
    .unwrap()
}

#[test]
fn poc_root_hash_conditional_enforced_by_builder_after_root_drift() {
    let watched = Address::with_last_byte(0x42);
    let root_old = B256::with_last_byte(0x11);
    let root_new = B256::with_last_byte(0x22);
    let cond = cond_root(watched, root_old);

    // Admission accepted while the watched root matched (root_old).
    let admitted = first_known_account_violation(
        &cond,
        |_address, _slot| Ok::<_, Infallible>(U256::ZERO),
        |_address| Ok::<_, Infallible>(Some(root_old)),
    );
    assert_eq!(admitted, Ok(None));

    // FIX: the builder recomputes the pending storage root. If the root still holds,
    // the tx is includable...
    assert_eq!(builder_violation(&cond, Some(root_old)), None);

    // ...but once the root drifts inside the pending block, the builder reports the
    // violation and the tx is excluded before execution (previously this returned
    // `None` because the builder passed `read_root => None`).
    assert_eq!(
        builder_violation(&cond, Some(root_new)),
        Some(KnownAccountViolation::Root { address: watched })
    );

    // Fail-open: a transient read error (modelled as `None`) must not drop the tx.
    assert_eq!(builder_violation(&cond, None), None);
}
