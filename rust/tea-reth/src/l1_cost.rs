//! TEA-denominated L1 cost function.
//!
//! Wraps the standard Fjord L1 cost calculation with a TEA/ETH exchange rate
//! read from the on-chain GasPriceOracle.

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
/// The price occupies the lower 160 bits of the packed slot value.
pub fn extract_price_from_u256(value: U256) -> U256 {
    // Lower 160 bits: 2 full 64-bit limbs + 32 bits
    const MASK_160: U256 = U256::from_limbs([u64::MAX, u64::MAX, 0x00000000FFFFFFFF, 0]);
    value & MASK_160
}

/// Returns the TEA per WAD ETH value, using the backup rate if the oracle value is zero.
pub fn tea_per_wad_eth_or_backup(oracle_value: U256) -> U256 {
    if oracle_value.is_zero() { U256::from(BACKUP_TEA_PER_ETH) * WAD } else { oracle_value }
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
}
