//! Tea chain specification and chain ID detection.
//!
//! The chain-ID constants and the [`is_tea`] gate live in the shared
//! `tea-l1-cost` crate so the execution layer (tea-reth) and the fault-proof
//! VM (kona) apply the exact same gate and cannot drift (TEAO1-132). They are
//! re-exported here to preserve the `crate::chainspec::*` paths used across the
//! crate.

pub use tea_l1_cost::{TEA_CHAIN_ID, TEA_TESTNET1_CHAIN_ID, is_tea};

#[cfg(test)]
mod tests {
    //! Ported from tea-geth commit 46ec0efe:
    //!   - `params/config.go` — IsTea() (line 1034), chain ID constants (lines 42-45)

    use super::*;

    /// Ported from: `IsTea()` (params/config.go:1034)
    /// Validates both Tea chain IDs and negative cases.
    #[test]
    fn test_is_tea() {
        assert!(is_tea(TEA_CHAIN_ID));
        assert!(is_tea(TEA_TESTNET1_CHAIN_ID));
        assert!(!is_tea(1)); // Ethereum mainnet
        assert!(!is_tea(10)); // OP mainnet
        assert!(!is_tea(0));
    }

    // === Additional tests from PR #5 review feedback ===

    /// Boundary values: chain IDs adjacent to Tea IDs should all return false.
    #[test]
    fn test_is_tea_boundary_values() {
        // Off-by-one for each Tea chain ID
        assert!(!is_tea(TEA_CHAIN_ID - 1)); // 6121
        assert!(!is_tea(TEA_CHAIN_ID + 1)); // 6123
        assert!(!is_tea(TEA_TESTNET1_CHAIN_ID - 1)); // 10217
        assert!(!is_tea(TEA_TESTNET1_CHAIN_ID + 1)); // 10219
    }

    /// u64::MAX should not be a Tea chain ID.
    #[test]
    fn test_is_tea_u64_max() {
        assert!(!is_tea(u64::MAX));
    }
}
