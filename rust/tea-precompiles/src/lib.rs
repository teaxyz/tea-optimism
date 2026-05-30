//! Tea L2 verification precompiles.
//!
//! Three custom precompiles power Tea's on-chain identity / attestation flows:
//!
//! - `0x0696` — [`gpg_verify`]: detached OpenPGP signature verification
//! - `0x0697` — [`ssh_verify`]: raw SSH signature verification
//! - `0x0698` — [`ssh_sig_verify`]: SSHSIG (`ssh-keygen -Y sign`) envelope verification
//!
//! # Why this is its own crate
//!
//! The crypto runs in **two** places that must agree byte-for-byte:
//!
//! 1. the execution layer (`tea-reth`), where the precompiles execute natively, and
//! 2. the fault-proof host (`kona-host`), which re-runs the precompile off the
//!    interactive MIPS/RISC-V FPVM and serves the result back through the
//!    preimage oracle (kona's "accelerated precompile" mechanism).
//!
//! Keeping the implementation in one std crate consumed by both means the EL and
//! the fault proof can never drift — mirroring how [`tea-l1-cost`] is shared for
//! the L1-fee multiplier. The `no_std` FPVM *client* never links this crate; it
//! only hints the precompile address+input to the host and reads the result.
//!
//! [`tea-l1-cost`]: https://docs.rs/tea-l1-cost

pub mod gpg_verify;
pub mod ssh_common;
pub mod ssh_sig_verify;
pub mod ssh_verify;
