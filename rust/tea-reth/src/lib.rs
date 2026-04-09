//! Tea-reth: Custom OP Stack execution client for the Tea L2 chain.
//!
//! Tea is an Optimism L2 chain that uses a custom gas token (TEA) with an on-chain oracle
//! for TEA/ETH pricing. This crate extends op-reth with:
//!
//! 1. A TEA-denominated L1 cost function (wraps Fjord cost with TEA/ETH exchange rate)
//! 2. A GPG signature verification precompile (at address `0x0696`)
//! 3. Chain ID detection for Tea networks
//!
//! All Tea-specific EVM logic lives in the `tea-precompiles` crate and is injected
//! into `OpEvmFactory` at the `alloy-op-evm` layer. This crate re-exports for convenience.

pub use tea_precompiles as precompiles;
pub use tea_precompiles::{chainspec, gpg_verify, l1_cost};
