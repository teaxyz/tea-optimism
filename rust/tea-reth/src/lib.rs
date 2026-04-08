//! Tea-reth: Custom OP Stack execution client for the Tea L2 chain.
//!
//! Tea is an Optimism L2 chain that uses a custom gas token (TEA) with an on-chain oracle
//! for TEA/ETH pricing. This crate extends op-reth with:
//!
//! 1. A TEA-denominated L1 cost function (wraps Fjord cost with TEA/ETH exchange rate)
//! 2. A GPG signature verification precompile (at address `0x0696`)
//! 3. Chain ID detection for Tea networks
//!
//! lib.rs is necessary for the implementation tests to access the Tea-specific components
//! (e.g. TeaEvmFactory) without having to run through the bin wrapper.

pub mod chainspec;
pub mod evm;
pub mod l1_cost;
pub mod node;
pub mod precompiles;
