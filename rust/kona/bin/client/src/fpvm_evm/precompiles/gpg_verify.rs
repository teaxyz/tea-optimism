//! Accelerated `0x0696` GPG signature-verification precompile (Tea).
//!
//! The pgp/rsa/ed25519 crypto is `std`-only and cannot run inside the no_std
//! FPVM, so — exactly like [`super::ecrecover`] and [`super::bn128_pair`] — this
//! stub hints the precompile address + input to the host, which re-runs the
//! shared `tea-precompiles` crypto and serves the 32-byte result back through
//! the preimage oracle. Gas is metered here from the same no_std
//! [`tea_precompiles::gas`] schedule the EL uses, so the gas charged is
//! byte-identical between the EL and the proof (TEAO1-174).

use crate::fpvm_evm::precompiles::utils::precompile_run;
use alloc::string::ToString;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use tea_precompiles::gas::{GPG_VERIFY_ADDRESS, gpg_required_gas};

/// Runs the FPVM-accelerated `0x0696` GPG verify precompile call.
pub(crate) fn fpvm_gpg_verify<H, O>(
    input: &[u8],
    gas_limit: u64,
    hint_writer: &H,
    oracle_reader: &O,
) -> PrecompileResult
where
    H: HintWriterClient + Send + Sync,
    O: PreimageOracleClient + Send + Sync,
{
    let gas_used = gpg_required_gas(input);
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    // The native precompile always returns a 32-byte result (never empty), so a
    // host error must propagate and fail the proof rather than silently return
    // empty bytes — that would itself be a divergence from the EL.
    let result_data = kona_proof::block_on(precompile_run! {
        hint_writer,
        oracle_reader,
        &[GPG_VERIFY_ADDRESS.as_slice(), &gas_used.to_be_bytes(), input]
    })
    .map_err(|e| PrecompileError::Other(e.to_string().into()))?;

    Ok(PrecompileOutput::new(gas_used, result_data.into()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fpvm_evm::precompiles::test_utils::{
        execute_native_precompile, test_accelerated_precompile,
    };
    use alloy_primitives::hex;

    /// Real ed25519-signed GPG fixture (a *valid* signature → bytes32(1)). The
    /// same fixture the EL's `tea-precompiles` unit tests use, included from the
    /// shared crate so the proof and EL exercise byte-identical input.
    const ED25519_INPUT_HEX: &str =
        include_str!("../../../../../../tea-precompiles/src/testdata_gpg_verify_ed25519.hex");

    #[tokio::test(flavor = "multi_thread")]
    async fn test_accelerated_gpg_verify_matches_native() {
        test_accelerated_precompile(|hint_writer, oracle_reader| {
            let input = hex::decode(ED25519_INPUT_HEX.trim()).expect("valid hex");
            let accelerated =
                fpvm_gpg_verify(&input, u64::MAX, hint_writer, oracle_reader).unwrap();
            let native =
                execute_native_precompile(GPG_VERIFY_ADDRESS, input.clone(), u64::MAX).unwrap();

            // The FPVM charges gas itself and reads the result from the host; both
            // the output bytes and the gas charged must equal the native EL run.
            assert_eq!(accelerated.bytes, native.bytes);
            assert_eq!(accelerated.gas_used, native.gas_used);
            // Sanity: this fixture verifies, so the result is bytes32(1).
            assert_eq!(accelerated.bytes.len(), 32);
            assert_eq!(accelerated.bytes[31], 1);
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_accelerated_gpg_verify_out_of_gas() {
        test_accelerated_precompile(|hint_writer, oracle_reader| {
            let err = fpvm_gpg_verify(&[0u8; 64], 0, hint_writer, oracle_reader).unwrap_err();
            assert!(matches!(err, PrecompileError::OutOfGas));
        })
        .await;
    }
}
