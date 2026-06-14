//! Precompile addresses and gas schedule — the **only** part of this crate the
//! `no_std` kona FPVM links.
//!
//! The fault-proof FPVM cannot run the crypto (pgp/rsa/ed25519 are `std`-only),
//! so it offloads execution to the host via kona's accelerated-precompile
//! mechanism. But the FPVM must still charge gas *itself*, before the call, and
//! return the same `gas_used` the EL does — otherwise the gas left after the
//! call differs and the EL and proof diverge. So the gas schedule has to be a
//! single source of truth shared by the EL, the host, and the FPVM. That is
//! exactly this module: pure arithmetic + address constants, no_std-clean, with
//! no crypto dependency. The `std` crypto modules re-export these names so their
//! call sites are unchanged.

use alloy_primitives::{Address, address};

// ---- 0x0696 — GPG detached-signature verify ----------------------------------

/// GPG verify precompile address.
pub const GPG_VERIFY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000696");
/// Base gas cost for GPG verification.
pub const GPG_VERIFY_BASE_GAS: u64 = 23_500;
/// Per-byte gas cost above the kink point.
pub const GPG_VERIFY_GAS_PER_BYTE: u64 = 16;
/// Input length kink point — below this, only base gas is charged.
pub const GPG_VERIFY_INPUT_LENGTH_KINK: usize = 3264;

/// Calculates the gas required for GPG verification.
pub fn gpg_required_gas(input: &[u8]) -> u64 {
    if input.len() <= GPG_VERIFY_INPUT_LENGTH_KINK {
        return GPG_VERIFY_BASE_GAS;
    }
    let additional_bytes = input.len() - GPG_VERIFY_INPUT_LENGTH_KINK;
    GPG_VERIFY_BASE_GAS
        .saturating_add(GPG_VERIFY_GAS_PER_BYTE.saturating_mul(additional_bytes as u64))
}

// ---- 0x0697 — raw SSH signature verify ---------------------------------------

/// SSH verify precompile address.
pub const SSH_VERIFY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000697");
/// Base gas cost for SSH verification.
pub const SSH_VERIFY_BASE_GAS: u64 = 23_500;
/// Per-byte gas cost above the kink point.
pub const SSH_VERIFY_GAS_PER_BYTE: u64 = 16;
/// Input length kink point — below this, only base gas is charged.
pub const SSH_VERIFY_INPUT_LENGTH_KINK: usize = 3264;

/// Calculates the gas required for SSH verification.
pub fn ssh_required_gas(input: &[u8]) -> u64 {
    if input.len() <= SSH_VERIFY_INPUT_LENGTH_KINK {
        return SSH_VERIFY_BASE_GAS;
    }
    let additional_bytes = input.len() - SSH_VERIFY_INPUT_LENGTH_KINK;
    SSH_VERIFY_BASE_GAS
        .saturating_add(SSH_VERIFY_GAS_PER_BYTE.saturating_mul(additional_bytes as u64))
}

// ---- 0x0698 — SSHSIG (ssh-keygen -Y sign) envelope verify ---------------------

/// SSHSIG verify precompile address.
pub const SSHSIG_VERIFY_ADDRESS: Address =
    address!("0x0000000000000000000000000000000000000698");
/// Base gas cost for SSHSIG verification.
pub const SSHSIG_VERIFY_BASE_GAS: u64 = 25_000;
/// Per-byte gas cost above the kink point.
pub const SSHSIG_VERIFY_GAS_PER_BYTE: u64 = 16;
/// Input length kink point — below this, only base gas is charged.
pub const SSHSIG_VERIFY_INPUT_LENGTH_KINK: usize = 3264;

/// Calculates the gas required for SSHSIG verification.
pub fn sshsig_required_gas(input: &[u8]) -> u64 {
    if input.len() <= SSHSIG_VERIFY_INPUT_LENGTH_KINK {
        return SSHSIG_VERIFY_BASE_GAS;
    }
    let additional_bytes = input.len() - SSHSIG_VERIFY_INPUT_LENGTH_KINK;
    SSHSIG_VERIFY_BASE_GAS
        .saturating_add(SSHSIG_VERIFY_GAS_PER_BYTE.saturating_mul(additional_bytes as u64))
}
