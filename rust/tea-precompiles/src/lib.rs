//! Tea L2 verification precompiles.
//!
//! Three custom precompiles power Tea's on-chain identity / attestation flows:
//!
//! - `0x0696` — [`gpg_verify`]: detached OpenPGP signature verification
//! - `0x0697` — [`ssh_verify`]: raw SSH signature verification
//! - `0x0698` — [`ssh_sig_verify`]: SSHSIG (`ssh-keygen -Y sign`) envelope verification
//!
//! # Why this is its own crate, and why it is feature-gated
//!
//! The crypto runs in **two** places that must agree byte-for-byte:
//!
//! 1. the execution layer (`tea-reth`), where the precompiles execute natively, and
//! 2. the fault-proof host (`kona-host`), which re-runs the precompile off the
//!    interactive MIPS/RISC-V FPVM and serves the result back through the
//!    preimage oracle (kona's "accelerated precompile" mechanism).
//!
//! Both link this crate with the default `std` feature, so the crypto is defined
//! exactly once — mirroring how [`tea-l1-cost`] is shared for the L1-fee
//! multiplier so the EL and fault proof cannot drift.
//!
//! The `no_std` FPVM *client* cannot run the crypto (pgp/rsa/ed25519 are
//! `std`-only) — it hints the precompile address+input to the host and reads the
//! result. But it must still charge gas itself and return the same `gas_used`,
//! so it links this crate with `default-features = false` and uses only the
//! [`gas`] module: addresses + gas schedule, pure arithmetic, no crypto deps.
//!
//! [`tea-l1-cost`]: https://docs.rs/tea-l1-cost
#![cfg_attr(not(feature = "std"), no_std)]

pub mod gas;

#[cfg(feature = "std")]
pub mod gpg_verify;
#[cfg(feature = "std")]
pub mod ssh_common;
#[cfg(feature = "std")]
pub mod ssh_sig_verify;
#[cfg(feature = "std")]
pub mod ssh_verify;
