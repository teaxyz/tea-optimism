//! Accelerated `0x0697` SSH signature-verification precompile (Tea).
//!
//! See [`super::gpg_verify`] for the host-accelerated pattern; this only differs
//! in the precompile address and gas schedule. The crypto runs on the host via
//! the shared `tea-precompiles` crate; gas is metered from the shared no_std
//! [`tea_precompiles::gas`] schedule so the EL and the proof agree (TEAO1-174).

use crate::fpvm_evm::precompiles::utils::precompile_run;
use alloc::string::ToString;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use tea_precompiles::gas::{SSH_VERIFY_ADDRESS, ssh_required_gas};

/// Runs the FPVM-accelerated `0x0697` SSH verify precompile call.
pub(crate) fn fpvm_ssh_verify<H, O>(
    input: &[u8],
    gas_limit: u64,
    hint_writer: &H,
    oracle_reader: &O,
) -> PrecompileResult
where
    H: HintWriterClient + Send + Sync,
    O: PreimageOracleClient + Send + Sync,
{
    let gas_used = ssh_required_gas(input);
    if gas_used > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    // A host error must propagate (the native precompile never returns empty
    // bytes); silently returning empty would diverge from the EL.
    let result_data = kona_proof::block_on(precompile_run! {
        hint_writer,
        oracle_reader,
        &[SSH_VERIFY_ADDRESS.as_slice(), &gas_used.to_be_bytes(), input]
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

    /// Real ed25519 SSH-signature fixture (valid → bytes32(1)), shared with the
    /// EL's `tea-precompiles` unit tests via the crate's testdata.
    const ED25519_INPUT_HEX: &str =
        include_str!("../../../../../../tea-precompiles/src/testdata_ssh_verify_ed25519.hex");

    #[tokio::test(flavor = "multi_thread")]
    async fn test_accelerated_ssh_verify_matches_native() {
        test_accelerated_precompile(|hint_writer, oracle_reader| {
            let input = hex::decode(ED25519_INPUT_HEX.trim()).expect("valid hex");
            let accelerated =
                fpvm_ssh_verify(&input, u64::MAX, hint_writer, oracle_reader).unwrap();
            let native =
                execute_native_precompile(SSH_VERIFY_ADDRESS, input.clone(), u64::MAX).unwrap();

            assert_eq!(accelerated.bytes, native.bytes);
            assert_eq!(accelerated.gas_used, native.gas_used);
            assert_eq!(accelerated.bytes.len(), 32);
            assert_eq!(accelerated.bytes[31], 1);
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_accelerated_ssh_verify_out_of_gas() {
        test_accelerated_precompile(|hint_writer, oracle_reader| {
            let err = fpvm_ssh_verify(&[0u8; 64], 0, hint_writer, oracle_reader).unwrap_err();
            assert!(matches!(err, PrecompileError::OutOfGas));
        })
        .await;
    }
}
