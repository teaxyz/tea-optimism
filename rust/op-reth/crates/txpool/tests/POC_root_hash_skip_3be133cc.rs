//! @title POC->regression: RootHash conditionals are rejected at admission
//! @notice The payload-builder reader shape (`read_root => None`) cannot observe
//! storage-root drift, so a RootHash conditional could previously slip through
//! inclusion-time enforcement. This is now MOOT: RootHash conditionals are
//! rejected at RPC admission (`conditional_has_root_hash`), so they never enter
//! the pool or reach the builder. This test pins both facts.
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_eth::erc4337::{AccountStorage, TransactionConditional};
use reth_optimism_txpool::conditional::{
    conditional_has_root_hash, first_known_account_violation, KnownAccountViolation,
};
use std::convert::Infallible;

fn cond_root(account: Address, root: B256) -> TransactionConditional {
    let mut tc = TransactionConditional::default();
    tc.known_accounts.insert(account, AccountStorage::RootHash(root));
    tc
}

#[test]
fn root_hash_conditional_rejected_at_admission_so_builder_blindness_is_moot() {
    let watched = Address::with_last_byte(0x42);
    let root_old = B256::with_last_byte(0x11);
    let root_new = B256::with_last_byte(0x22);
    let cond = cond_root(watched, root_old);

    // Admission would have accepted on matching root...
    let admitted = first_known_account_violation(
        &cond,
        |_, _| Ok::<_, Infallible>(U256::ZERO),
        |_| Ok::<_, Infallible>(Some(root_old)),
    );
    assert_eq!(admitted, Ok(None));
    // ...and a root-aware reader detects later drift...
    let root_aware = first_known_account_violation(
        &cond,
        |_, _| Ok::<_, Infallible>(U256::ZERO),
        |_| Ok::<_, Infallible>(Some(root_new)),
    );
    assert_eq!(root_aware, Ok(Some(KnownAccountViolation::Root { address: watched })));
    // ...but the builder-shaped reader is blind to it (read_root => None).
    let builder_recheck = first_known_account_violation(
        &cond,
        |_, _| Ok::<_, Infallible>(U256::ZERO),
        |_| Ok::<_, Infallible>(None),
    );
    assert_eq!(builder_recheck, Ok(None));
    // FIX: because the builder can never see it, admission refuses RootHash entirely.
    assert!(
        conditional_has_root_hash(&cond),
        "RootHash conditional must be rejected at admission"
    );
}
