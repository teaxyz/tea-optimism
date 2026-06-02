//! Accelerated precompile runner for the host program.

use crate::{HostError, Result};
use alloy_primitives::{Address, Bytes};
use revm::precompile::{self, Precompile};
use tea_precompiles::{gas, gpg_verify, ssh_sig_verify, ssh_verify};

/// List of precompiles that are accelerated by the host program.
pub(crate) const ACCELERATED_PRECOMPILES: &[Precompile] = &[
    precompile::secp256k1::ECRECOVER,          // ecRecover
    precompile::bn254::pair::ISTANBUL,         // ecPairing
    precompile::bls12_381::g1_add::PRECOMPILE, // BLS12-381 G1 Point Addition
    precompile::bls12_381::g1_msm::PRECOMPILE, /* BLS12-381 G1 Point Multi-scalar
                                                * Multiplication */
    precompile::bls12_381::g2_add::PRECOMPILE, // BLS12-381 G2 Point Addition
    precompile::bls12_381::g2_msm::PRECOMPILE, // BLS12-381 G2 Point Multi-scalar Multiplication
    precompile::bls12_381::map_fp2_to_g2::PRECOMPILE, // BLS12-381 FP2 to G2 Point Mapping
    precompile::bls12_381::map_fp_to_g1::PRECOMPILE, // BLS12-381 FP to G1 Point Mapping
    precompile::bls12_381::pairing::PRECOMPILE, // BLS12-381 pairing
    precompile::kzg_point_evaluation::POINT_EVALUATION, // KZG point evaluation
];

/// Tea's custom verification precompiles (`0x0696`-`0x0698`).
///
/// These can't live in [`ACCELERATED_PRECOMPILES`] because the [`Precompile`]
/// carries a non-`const` [`revm::precompile::PrecompileId`]. Returning the
/// matching one on demand lets the fault-proof host run the *exact same*
/// `tea-precompiles` crypto the EL runs, so a state mutation derived from one of
/// these precompiles produces the same result in the EL and the proof
/// (TEAO1-174). The `no_std` FPVM client cannot run this crypto, so it hints the
/// address+input here and reads the result back through the preimage oracle.
fn tea_accelerated_precompile(address: Address) -> Option<Precompile> {
    if address == gas::GPG_VERIFY_ADDRESS {
        Some(gpg_verify::precompile())
    } else if address == gas::SSH_VERIFY_ADDRESS {
        Some(ssh_verify::precompile())
    } else if address == gas::SSHSIG_VERIFY_ADDRESS {
        Some(ssh_sig_verify::precompile())
    } else {
        None
    }
}

/// Runs a resolved precompile and returns its output bytes.
fn run(precompile: &Precompile, input: &Bytes, gas: u64) -> Result<Vec<u8>> {
    let output = precompile.precompile()(input, gas)
        .map_err(|e| HostError::PrecompileExecutionFailed(e.to_string()))?;
    Ok(output.bytes.into())
}

/// Executes an accelerated precompile on [revm].
pub(crate) fn execute<T: Into<Bytes>>(address: Address, input: T, gas: u64) -> Result<Vec<u8>> {
    let input = input.into();

    // Standard EVM precompiles accelerated by revm.
    if let Some(precompile) =
        ACCELERATED_PRECOMPILES.iter().find(|precompile| *precompile.address() == address)
    {
        return run(precompile, &input, gas);
    }

    // Tea's custom verification precompiles, run via the shared `tea-precompiles`
    // crate so the proof host executes the same crypto as the EL.
    if let Some(precompile) = tea_accelerated_precompile(address) {
        return run(&precompile, &input, gas);
    }

    Err(HostError::PrecompileNotAccelerated)
}
