//! Tea-specific precompiles and L1 cost logic for OP Stack chains.
//!
//! This crate is intentionally independent of op-reth and tea-reth so it can be
//! used as a dependency of `alloy-op-evm` without creating circular dependencies.
//!
//! Provides:
//! 1. GPG signature verification precompile at address `0x0696`
//! 2. TEA/ETH L1 cost multiplier (reads on-chain oracle, wraps Fjord cost)
//! 3. Chain ID detection for Tea networks
//! 4. A combined precompile map (OP precompiles + Tea-specific ones)

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod chainspec;
pub mod gpg_verify;
pub mod l1_cost;

use alloy_evm::{Database, precompiles::PrecompilesMap};
use alloy_primitives::U256;
use op_revm::{OpSpecId, precompiles::OpPrecompiles};
use revm::precompile::Precompiles;
use std::sync::OnceLock;

/// Returns the complete precompile map for Tea: standard OP precompiles plus GPG verify.
pub fn tea_precompiles(spec_id: OpSpecId) -> PrecompilesMap {
    static INSTANCE: OnceLock<Precompiles> = OnceLock::new();

    PrecompilesMap::from_static(INSTANCE.get_or_init(|| {
        let mut precompiles = OpPrecompiles::new_with_spec(spec_id).precompiles().clone();
        precompiles.extend([gpg_verify::precompile()]);
        precompiles
    }))
}

/// Read the TEA/ETH exchange rate from the GasPriceOracle and return the
/// L1 cost multiplier as `(numerator, denominator)`.
pub fn tea_l1_cost_multiplier<DB: Database>(db: &mut DB) -> Option<(U256, U256)> {
    let raw =
        db.storage(l1_cost::GAS_PRICE_ORACLE_ADDR, l1_cost::LATEST_PRICE_RATIO_SLOT_U256).ok()?;
    let price = l1_cost::extract_price_from_u256(raw);
    let rate = l1_cost::tea_per_wad_eth_or_backup(price);
    Some((rate, l1_cost::WAD))
}
