//! TEA-denominated L1 cost helpers.
//!
//! Shared between tea-reth (execution layer) and kona (fault-proof VM) so
//! the on-chain GasPriceOracle slot layout, exchange-rate arithmetic, and
//! backup-rate fallback are defined in exactly one place. Drift between
//! EL and FPVM versions of these constants is exactly the bug fixed by
//! introducing this crate.
//!
//! Wraps the standard Fjord L1 cost calculation with a TEA/ETH exchange
//! rate read from the on-chain GasPriceOracle.

#![no_std]
#![cfg_attr(not(test), warn(missing_docs))]

use alloy_primitives::{Address, B256, U256, address};

/// GasPriceOracle contract address on L2.
pub const GAS_PRICE_ORACLE_ADDR: Address = address!("0x420000000000000000000000000000000000000F");

/// Storage slot for the latest TEA/ETH price ratio.
pub const LATEST_PRICE_RATIO_SLOT: B256 = B256::new([
    0xd0, 0xdd, 0x2c, 0x45, 0xa4, 0x7f, 0x8f, 0x6c, 0x6a, 0x17, 0xd4, 0x5e, 0xff, 0x20, 0xf1, 0xe8,
    0x5e, 0x01, 0x3b, 0x02, 0x44, 0x79, 0x31, 0x69, 0xbc, 0xa5, 0x9b, 0x0c, 0xad, 0x5e, 0x4e, 0x86,
]);

/// Storage slot for the latest TEA/ETH price ratio, as U256 for direct use with
/// `Database::storage()`.
pub const LATEST_PRICE_RATIO_SLOT_U256: U256 = U256::from_be_bytes(LATEST_PRICE_RATIO_SLOT.0);

/// Backup TEA per ETH exchange rate (1,500,000 TEA per ETH).
pub const BACKUP_TEA_PER_ETH: u64 = 1_500_000;

/// Tea mainnet chain ID.
pub const TEA_CHAIN_ID: u64 = 6122;
/// Tea testnet 1 chain ID.
pub const TEA_TESTNET1_CHAIN_ID: u64 = 10218;
/// Tea testnet 2 chain ID.
pub const TEA_TESTNET2_CHAIN_ID: u64 = 14314;
/// Nethermind Tea test network chain ID.
pub const NETHERMIND_TEA_TESTNET_CHAIN_ID: u64 = 3257160925;

/// Returns `true` if `chain_id` is a Tea network.
///
/// The TEA/ETH L1-cost multiplier — including the 1,500,000× backup-rate
/// fallback — MUST only be applied on Tea chains. Off Tea, callers must leave
/// `l1_cost_multiplier` unset (`None`) so generic OP replay stays byte-identical
/// to canonical Optimism (TEAO1-132). This predicate lives here, in the crate
/// shared by both the execution layer (tea-reth) and the fault-proof VM (kona),
/// so the gate cannot drift between the two.
pub fn is_tea(chain_id: u64) -> bool {
    matches!(
        chain_id,
        TEA_CHAIN_ID
            | TEA_TESTNET1_CHAIN_ID
            | TEA_TESTNET2_CHAIN_ID
            | NETHERMIND_TEA_TESTNET_CHAIN_ID
    )
}

/// WAD = 1e18, used as scaling denominator.
pub const WAD: U256 = U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);

/// Computes the TEA-denominated L1 cost from a Fjord L1 cost and the exchange rate.
///
/// `tea_cost = fjord_cost * tea_per_wad_eth / WAD`
///
/// Where `tea_per_wad_eth` is the oracle value (price * 1e18).
pub fn apply_tea_exchange_rate(fjord_cost: U256, tea_per_wad_eth: U256) -> U256 {
    fjord_cost * tea_per_wad_eth / WAD
}

/// Extracts the TEA/ETH price from the oracle storage slot value (B256).
///
/// The price is stored in bytes [12..32] of the 32-byte slot value
/// (the lower 20 bytes, i.e., a uint160).
pub fn extract_price_from_slot(slot_value: B256) -> U256 {
    U256::from_be_slice(&slot_value[12..])
}

/// Extracts the TEA/ETH price from the oracle storage value (U256).
///
/// The price occupies the lower 160 bits of the packed slot value. This is
/// the invariant the op-revm patch's `saturating_mul(numerator, tx_l1_cost)`
/// relies on for overflow-safety: with a 160-bit-capped numerator and a
/// realistic tx_l1_cost (~2^60 max), the product is bounded by 2^220, far
/// below `U256::MAX` (2^256). Tests pin this in [`tests::test_mask_160_caps_at_160_bits`].
pub fn extract_price_from_u256(value: U256) -> U256 {
    // U256 limbs are little-endian: limb[0] = bits 0..64, limb[1] = bits
    // 64..128, limb[2] = bits 128..192, limb[3] = bits 192..256. To mask
    // the lower 160 bits we keep limbs 0 and 1 fully (128 bits) and the
    // low 32 bits of limb 2 (32 more bits) → 128 + 32 = 160. Limb 3 cleared.
    const MASK_160: U256 = U256::from_limbs([u64::MAX, u64::MAX, 0x00000000FFFFFFFF, 0]);
    value & MASK_160
}

/// Returns the TEA per WAD ETH value, using the backup rate if the oracle value is zero.
pub fn tea_per_wad_eth_or_backup(oracle_value: U256) -> U256 {
    if oracle_value.is_zero() { U256::from(BACKUP_TEA_PER_ETH) * WAD } else { oracle_value }
}

/// Build the op-revm `l1_cost_multiplier` value `(numerator, denominator)`
/// from a raw oracle slot value.
///
/// Combines [`extract_price_from_u256`] (which enforces the 160-bit mask
/// — load-bearing for the op-revm patch's `saturating_mul` safety) with
/// [`tea_per_wad_eth_or_backup`]. Use this from EvmFactory `create_evm`
/// implementations rather than chaining the primitives manually — keeps
/// EL (tea-reth) and FPVM (kona) from drifting on a single-pipeline change.
///
/// Returns `(rate, WAD)` such that the op-revm patch computes
/// `tx_l1_cost.saturating_mul(rate) / WAD` — matching
/// [`apply_tea_exchange_rate`].
pub fn multiplier_from_oracle_value(raw: U256) -> (U256, U256) {
    let price = extract_price_from_u256(raw);
    let rate = tea_per_wad_eth_or_backup(price);
    (rate, WAD)
}

#[cfg(test)]
mod tests {
    //! Tests ported from tea-geth commit 46ec0efe:
    //!   - `core/types/rollup_cost.go` — NewL1CostFuncTea (line 376)
    //!   - `core/types/rollup_cost_test.go` — TestTeaL1CostFuncWithBackup (line 577),
    //!     TestTeaL1CostFuncWithStorageRead (line 600)
    //!
    //! Constants from Go:
    //!   - BackupTeaPerEth = 1_500_000 (rollup_cost.go)
    //!   - Wad = 1e18 (rollup_cost.go)
    //!   - GasPriceOracleAddr = 0x420...00F (rollup_cost.go)
    //!   - LatestPriceRatioSlot = 0xd0dd2c45... (rollup_cost.go)
    //!   - examplePriceRatio = 0x0000...3627e8f712373c0000 (rollup_cost_test.go:44)
    //!   - priceRatioInExample = 999 (rollup_cost_test.go:45)
    //!   - fjordFee = 3_203_000 (rollup_cost_test.go:36)

    use super::*;

    /// Ported from tea-geth `IsTea()` (params/config.go:1034). The gate now
    /// lives in this shared crate so EL and FPVM cannot disagree (TEAO1-132).
    #[test]
    fn test_is_tea() {
        assert!(is_tea(TEA_CHAIN_ID));
        assert!(is_tea(TEA_TESTNET1_CHAIN_ID));
        assert!(is_tea(TEA_TESTNET2_CHAIN_ID));
        assert!(is_tea(NETHERMIND_TEA_TESTNET_CHAIN_ID));
        // Non-Tea chains, boundaries, and extremes.
        assert!(!is_tea(1)); // Ethereum mainnet
        assert!(!is_tea(10)); // OP mainnet
        assert!(!is_tea(0));
        assert!(!is_tea(TEA_CHAIN_ID - 1));
        assert!(!is_tea(TEA_CHAIN_ID + 1));
        assert!(!is_tea(u64::MAX));
    }

    // Fjord fee for the emptyTx from Go tests (rollup_cost_test.go:36):
    // 100_000_000 * (2 * 1000 * 1e6 * 16 + 3 * 10 * 1e6) / 1e12 = 3_203_000
    const FJORD_FEE: u64 = 3_203_000;

    #[test]
    fn test_wad_constant() {
        assert_eq!(WAD, U256::from(10u64.pow(18)));
    }

    /// Validates LatestPriceRatioSlot constant matches Go's rollup_cost.go.
    #[test]
    fn test_slot_constant() {
        let expected = B256::new(alloy_primitives::hex!(
            "d0dd2c45a47f8f6c6a17d45eff20f1e85e013b0244793169bca59b0cad5e4e86"
        ));
        assert_eq!(LATEST_PRICE_RATIO_SLOT, expected);
    }

    #[test]
    fn test_backup_rate() {
        let backup = tea_per_wad_eth_or_backup(U256::ZERO);
        assert_eq!(backup, U256::from(BACKUP_TEA_PER_ETH) * WAD);
    }

    #[test]
    fn test_oracle_rate_preferred() {
        let oracle_value = U256::from(999u64) * WAD;
        assert_eq!(tea_per_wad_eth_or_backup(oracle_value), oracle_value);
    }

    /// Validates examplePriceRatio extraction (rollup_cost_test.go:44-45).
    /// The slot stores timestamp|price packed; bytes [12..32] hold the price.
    #[test]
    fn test_extract_price_from_slot() {
        let slot_bytes = alloy_primitives::hex!(
            "00000000000000006793192400000000000000000000003627e8f712373c0000"
        );
        let price = extract_price_from_slot(B256::from(slot_bytes));
        assert_eq!(price, U256::from(999u64) * WAD);
    }

    /// Validates the U256 extraction matches the B256 extraction.
    #[test]
    fn test_extract_price_from_u256() {
        let slot_bytes = alloy_primitives::hex!(
            "00000000000000006793192400000000000000000000003627e8f712373c0000"
        );
        let from_b256 = extract_price_from_slot(B256::from(slot_bytes));
        let from_u256 = extract_price_from_u256(U256::from_be_bytes(slot_bytes));
        assert_eq!(from_b256, from_u256);
    }

    /// Validates LATEST_PRICE_RATIO_SLOT_U256 matches the B256 version.
    #[test]
    fn test_slot_u256_matches_b256() {
        assert_eq!(LATEST_PRICE_RATIO_SLOT_U256, U256::from_be_bytes(LATEST_PRICE_RATIO_SLOT.0),);
    }

    /// Ported from: `TestTeaL1CostFuncWithBackup` (rollup_cost_test.go:577)
    ///
    /// Go test creates NewL1CostFuncTea with BackupTeaPerEth * Wad as the exchange rate,
    /// then asserts tea_cost == fjord_cost * BackupTeaPerEth and tea_gas == fjord_gas.
    #[test]
    fn test_tea_l1_cost_func_with_backup() {
        let fjord_cost = U256::from(FJORD_FEE);
        let backup_exchange_rate = U256::from(BACKUP_TEA_PER_ETH) * WAD;
        let tea_cost = apply_tea_exchange_rate(fjord_cost, backup_exchange_rate);
        assert_eq!(tea_cost, fjord_cost * U256::from(BACKUP_TEA_PER_ETH));
    }

    /// Ported from: `TestTeaL1CostFuncWithStorageRead` (rollup_cost_test.go:600)
    ///
    /// Go test reads examplePriceRatio[12:] to get teaPerWadEth (999 * 1e18),
    /// then asserts tea_cost == fjord_cost * priceRatioInExample (999) and
    /// tea_gas == fjord_gas.
    #[test]
    fn test_tea_l1_cost_func_with_storage_read() {
        let fjord_cost = U256::from(FJORD_FEE);
        let slot_bytes = alloy_primitives::hex!(
            "00000000000000006793192400000000000000000000003627e8f712373c0000"
        );
        let tea_per_wad_eth = extract_price_from_slot(B256::from(slot_bytes));
        let tea_cost = apply_tea_exchange_rate(fjord_cost, tea_per_wad_eth);
        assert_eq!(tea_cost, fjord_cost * U256::from(999u64));
    }

    /// Verify the full pipeline: extract → backup fallback → multiply
    #[test]
    fn test_full_pipeline_zero_oracle() {
        let fjord_cost = U256::from(FJORD_FEE);
        let oracle_value = extract_price_from_slot(B256::ZERO);
        let tea_per_wad = tea_per_wad_eth_or_backup(oracle_value);
        let tea_cost = apply_tea_exchange_rate(fjord_cost, tea_per_wad);
        assert_eq!(tea_cost, fjord_cost * U256::from(BACKUP_TEA_PER_ETH));
    }

    /// Exchange rate math preserves precision for large values.
    #[test]
    fn test_large_fjord_cost() {
        let fjord_cost = U256::from(u64::MAX);
        let rate = U256::from(1_500_000u64) * WAD;
        let tea_cost = apply_tea_exchange_rate(fjord_cost, rate);
        assert_eq!(tea_cost, fjord_cost * U256::from(1_500_000u64));
    }

    // === Additional tests from PR #5 review feedback ===

    /// 1:1 exchange rate: apply_tea_exchange_rate(cost, WAD) == cost.
    #[test]
    fn test_exchange_rate_one_to_one() {
        let fjord_cost = U256::from(FJORD_FEE);
        assert_eq!(apply_tea_exchange_rate(fjord_cost, WAD), fjord_cost);
    }

    /// Fractional rate: rate = WAD / 2 → cost should halve.
    #[test]
    fn test_exchange_rate_fractional() {
        let fjord_cost = U256::from(FJORD_FEE);
        let half_wad = WAD / U256::from(2);
        let tea_cost = apply_tea_exchange_rate(fjord_cost, half_wad);
        assert_eq!(tea_cost, fjord_cost / U256::from(2));
    }

    /// Rounding: values that don't divide evenly by WAD should truncate (floor),
    /// matching Go's big.Int.Div behavior.
    #[test]
    fn test_exchange_rate_rounding() {
        // fjord_cost * rate = 7 * (WAD / 3) = 7 * 333333333333333333 = 2333333333333333331
        // 2333333333333333331 / WAD = 2333333333333333331 / 1e18 = 2 (floor division)
        let fjord_cost = U256::from(7u64);
        let rate = WAD / U256::from(3); // 333333333333333333
        let tea_cost = apply_tea_exchange_rate(fjord_cost, rate);
        // 7 * 333333333333333333 = 2333333333333333331
        // 2333333333333333331 / 1e18 = 2 (floor)
        assert_eq!(tea_cost, U256::from(2u64));
    }

    /// Extract price ignores timestamps correctly — different timestamps, same price.
    #[test]
    fn test_extract_price_with_various_timestamps() {
        // Same price (999 * WAD) with different timestamp prefixes
        // Timestamp 0x67931924
        let slot1 = alloy_primitives::hex!(
            "00000000000000006793192400000000000000000000003627e8f712373c0000"
        );
        // Timestamp 0xFFFFFFFF (different)
        let slot2 = alloy_primitives::hex!(
            "0000000000000000FFFFFFFF00000000000000000000003627e8f712373c0000"
        );
        // Timestamp 0x00000000 (zero)
        let slot3 = alloy_primitives::hex!(
            "00000000000000000000000000000000000000000000003627e8f712373c0000"
        );

        let price1 = extract_price_from_slot(B256::from(slot1));
        let price2 = extract_price_from_slot(B256::from(slot2));
        let price3 = extract_price_from_slot(B256::from(slot3));

        let expected = U256::from(999u64) * WAD;
        assert_eq!(price1, expected, "price should be same regardless of timestamp");
        assert_eq!(price2, expected, "price should be same regardless of timestamp");
        assert_eq!(price3, expected, "price should be same regardless of timestamp");
    }

    /// Zero oracle value triggers backup rate.
    #[test]
    fn test_tea_per_wad_eth_or_backup_zero() {
        let result = tea_per_wad_eth_or_backup(U256::ZERO);
        assert_eq!(result, U256::from(BACKUP_TEA_PER_ETH) * WAD);
    }

    /// Non-zero oracle value is returned as-is.
    #[test]
    fn test_tea_per_wad_eth_or_backup_nonzero() {
        let custom_rate = U256::from(42u64) * WAD;
        assert_eq!(tea_per_wad_eth_or_backup(custom_rate), custom_rate);
    }

    /// Mask invariant: `extract_price_from_u256` MUST always produce a value
    /// that fits in 160 bits, regardless of input.
    ///
    /// This is the load-bearing precondition for the op-revm patch's
    /// `tx_l1_cost.saturating_mul(numerator) / denominator` safety: with a
    /// 160-bit-capped numerator and a realistic tx_l1_cost ≤ 2^60, the
    /// product is bounded by 2^220 — far below `U256::MAX`. If this test
    /// ever fails (e.g., a refactor of `MASK_160` drops a bit), the
    /// saturation-divergence risk noted in PR #11's audit becomes real.
    #[test]
    fn test_mask_160_caps_at_160_bits() {
        let two_pow_160 = U256::from(1u128) << 160;
        // U256::MAX must mask down to exactly (2^160 - 1).
        let masked_max = extract_price_from_u256(U256::MAX);
        assert_eq!(masked_max, two_pow_160 - U256::from(1u64));
        assert!(masked_max < two_pow_160);

        // A value with bits set only in the upper 96 bits must mask to zero.
        let upper_only = U256::MAX << 160;
        assert_eq!(extract_price_from_u256(upper_only), U256::ZERO);

        // Spot check: a value with the boundary bit (bit 159) set survives,
        // and a value with bit 160 set is stripped.
        let bit_159 = U256::from(1u64) << 159;
        let bit_160 = U256::from(1u64) << 160;
        assert_eq!(extract_price_from_u256(bit_159), bit_159);
        assert_eq!(extract_price_from_u256(bit_160), U256::ZERO);
    }

    /// `multiplier_from_oracle_value` always produces a numerator that's safe
    /// to feed into the op-revm patch's `saturating_mul` against any realistic
    /// `tx_l1_cost`. Concretely: for a corrupted oracle slot at `U256::MAX`
    /// and `tx_l1_cost = 2^60` (above any plausible real value), the product
    /// fits in 220 bits and never saturates.
    #[test]
    fn test_multiplier_from_oracle_value_never_saturates_realistic_cost() {
        let (numerator, denominator) = multiplier_from_oracle_value(U256::MAX);

        // Numerator is post-mask, so ≤ 2^160 - 1.
        let two_pow_160 = U256::from(1u128) << 160;
        assert!(numerator < two_pow_160);
        assert_eq!(denominator, WAD);

        // 2^60 is two orders of magnitude above any plausible Fjord cost
        // (~1e16 ≈ 2^53). Product fits comfortably in U256 with headroom.
        let realistic_max_cost: U256 = U256::from(1u128) << 60;
        let product = realistic_max_cost.checked_mul(numerator).expect("no overflow at 2^60");
        // Headroom: product < 2^220, U256::MAX = 2^256 - 1. Margin: 36 bits.
        assert!(product < U256::MAX >> 36, "leaves >=36 bits of headroom under U256::MAX");
    }

    /// `multiplier_from_oracle_value(0)` engages backup-rate just like the
    /// raw primitives — confirms the new helper doesn't change behavior.
    #[test]
    fn test_multiplier_from_oracle_value_backup_path() {
        let (numerator, denominator) = multiplier_from_oracle_value(U256::ZERO);
        assert_eq!(numerator, U256::from(BACKUP_TEA_PER_ETH) * WAD);
        assert_eq!(denominator, WAD);
    }

    /// `multiplier_from_oracle_value` agrees with the raw primitives on
    /// `examplePriceRatio` — the canonical Go-test packed-slot value.
    #[test]
    fn test_multiplier_from_oracle_value_packed_slot() {
        let packed = U256::from_be_bytes(alloy_primitives::hex!(
            "00000000000000006793192400000000000000000000003627e8f712373c0000"
        ));
        let (numerator, denominator) = multiplier_from_oracle_value(packed);
        assert_eq!(numerator, U256::from(999u64) * WAD);
        assert_eq!(denominator, WAD);
    }

    /// Exchange rate of zero → cost is zero.
    #[test]
    fn test_exchange_rate_zero() {
        let fjord_cost = U256::from(FJORD_FEE);
        assert_eq!(apply_tea_exchange_rate(fjord_cost, U256::ZERO), U256::ZERO);
    }

    /// Extract price from U256 and B256 should always agree, even for edge values.
    #[test]
    fn test_extract_price_u256_b256_agreement_edge_cases() {
        // All zeros
        assert_eq!(
            extract_price_from_slot(B256::ZERO),
            extract_price_from_u256(U256::ZERO)
        );

        // Max 160-bit price (lower 20 bytes all 0xFF)
        let max_price_slot = alloy_primitives::hex!(
            "000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        );
        let from_b256 = extract_price_from_slot(B256::from(max_price_slot));
        let from_u256 = extract_price_from_u256(U256::from_be_bytes(max_price_slot));
        assert_eq!(from_b256, from_u256, "max 160-bit price should match");

        // Price = 1
        let one_slot = alloy_primitives::hex!(
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
        let from_b256 = extract_price_from_slot(B256::from(one_slot));
        let from_u256 = extract_price_from_u256(U256::from_be_bytes(one_slot));
        assert_eq!(from_b256, from_u256, "price = 1 should match");
    }
}
