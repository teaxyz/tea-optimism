//! TEA-denominated L1 cost helpers.
//!
//! All logic lives in the `tea-l1-cost` crate so the FPVM (kona) and the
//! EL (tea-reth) consume identical constants and arithmetic. This module
//! preserves the prior `crate::l1_cost::*` import paths used inside
//! tea-reth.

pub use tea_l1_cost::{
    BACKUP_TEA_PER_ETH, GAS_PRICE_ORACLE_ADDR, LATEST_PRICE_RATIO_SLOT,
    LATEST_PRICE_RATIO_SLOT_U256, WAD, apply_tea_exchange_rate, extract_price_from_slot,
    extract_price_from_u256, tea_per_wad_eth_or_backup,
};
