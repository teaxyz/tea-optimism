//! Tea chain specification and chain ID detection.

/// Tea mainnet chain ID
pub const TEA_CHAIN_ID: u64 = 6122;

/// Tea testnet 1 chain ID
pub const TEA_TESTNET1_CHAIN_ID: u64 = 10218;

/// Tea testnet 2 chain ID
pub const TEA_TESTNET2_CHAIN_ID: u64 = 14314;

/// Nethermind Tea test network chain ID
pub const NETHERMIND_TEA_TESTNET_CHAIN_ID: u64 = 3257160925;

/// Returns `true` if the given chain ID is a Tea network.
pub fn is_tea(chain_id: u64) -> bool {
    matches!(
        chain_id,
        TEA_CHAIN_ID
            | TEA_TESTNET1_CHAIN_ID
            | TEA_TESTNET2_CHAIN_ID
            | NETHERMIND_TEA_TESTNET_CHAIN_ID
    )
}

#[cfg(test)]
mod tests {
    //! Ported from tea-geth commit 46ec0efe:
    //!   - `params/config.go` — IsTea() (line 1034), chain ID constants (lines 42-45)

    use super::*;

    /// Ported from: `IsTea()` (params/config.go:1034)
    /// Validates all four Tea chain IDs and negative cases.
    #[test]
    fn test_is_tea() {
        assert!(is_tea(TEA_CHAIN_ID));
        assert!(is_tea(TEA_TESTNET1_CHAIN_ID));
        assert!(is_tea(TEA_TESTNET2_CHAIN_ID));
        assert!(is_tea(NETHERMIND_TEA_TESTNET_CHAIN_ID));
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
        assert!(!is_tea(TEA_TESTNET2_CHAIN_ID - 1)); // 14313
        assert!(!is_tea(TEA_TESTNET2_CHAIN_ID + 1)); // 14315
        assert!(!is_tea(NETHERMIND_TEA_TESTNET_CHAIN_ID - 1)); // 3257160924
        assert!(!is_tea(NETHERMIND_TEA_TESTNET_CHAIN_ID + 1)); // 3257160926
    }

    /// u64::MAX should not be a Tea chain ID.
    #[test]
    fn test_is_tea_u64_max() {
        assert!(!is_tea(u64::MAX));
    }
}
