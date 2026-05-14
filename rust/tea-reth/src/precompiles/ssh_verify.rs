//! SSH signature verification precompile.
//!
//! Verifies ed25519 and RSA SSH signatures on-chain. Registered at address `0x0697`.
//!
//! # Input format
//!
//! `abi.encode(bytes32 message, bytes publicKey, bytes signature)`
//!
//! - `publicKey`: SSH wire format (RFC 4253) public key bytes
//! - `signature`: SSH wire format signature (`string algorithm, string sig_blob`)
//!
//! # Output
//!
//! Returns `bytes32(1)` for valid signatures, `bytes32(0)` for invalid. Inputs
//! that fail to decode return `bytes32(0)` as well — only out-of-gas returns
//! an `Err`. This matches the `ecrecover` precompile convention so callers
//! cannot accidentally revert on "the signature didn't verify."
//!
//! # Supported algorithms
//!
//! - `ssh-ed25519`: Ed25519 signatures (64-byte sig, 32-byte pubkey).
//!   Verified with `verify_strict` to reject non-canonical S / small-subgroup R.
//! - `rsa-sha2-256`: RSA with SHA-256 (PKCS#1 v1.5).
//! - `rsa-sha2-512`: RSA with SHA-512 (PKCS#1 v1.5).
//!
//! RSA modulus must be 2048..=4096 bits. Deprecated `ssh-rsa` (SHA-1) signatures
//! are rejected explicitly.
//!
//! All SSH wire-format parsing and signature verification is delegated to
//! [`crate::precompiles::ssh_common`] so this precompile and `0x0698` share a
//! single audited implementation.

use alloy_primitives::{Address, Bytes, address};
use revm::precompile::{Precompile, PrecompileId, PrecompileOutput, PrecompileResult};

use super::ssh_common::{read_ssh_string, verify_ssh_ed25519, verify_ssh_rsa};

/// SSH verify precompile address.
pub const SSH_VERIFY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000697");

/// Base gas cost for SSH verification.
pub const SSH_VERIFY_BASE_GAS: u64 = 23_500;

/// Per-byte gas cost above the kink point.
pub const SSH_VERIFY_GAS_PER_BYTE: u64 = 16;

/// Input length kink point — below this, only base gas is charged.
pub const SSH_VERIFY_INPUT_LENGTH_KINK: usize = 3264;

/// Returns the SSH verify precompile for registration.
pub fn precompile() -> Precompile {
    Precompile::new(PrecompileId::custom("ssh_verify"), SSH_VERIFY_ADDRESS, ssh_verify_run)
}

/// Calculates the gas required for SSH verification.
pub fn required_gas(input: &[u8]) -> u64 {
    if input.len() <= SSH_VERIFY_INPUT_LENGTH_KINK {
        return SSH_VERIFY_BASE_GAS;
    }
    let additional_bytes = input.len() - SSH_VERIFY_INPUT_LENGTH_KINK;
    SSH_VERIFY_BASE_GAS + SSH_VERIFY_GAS_PER_BYTE * additional_bytes as u64
}

/// 32-byte result indicating success (1).
fn success_result() -> Bytes {
    let mut result = [0u8; 32];
    result[31] = 1;
    Bytes::copy_from_slice(&result)
}

/// 32-byte result indicating failure (0).
fn failure_result() -> Bytes {
    Bytes::copy_from_slice(&[0u8; 32])
}

// ─────────────────────────────────────────── ABI decoding

/// Decoded SSH verify precompile input.
struct SshVerifyInput {
    message: [u8; 32],
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

/// ABI-decode the SSH verify input.
///
/// Expected: `abi.encode(bytes32 message, bytes publicKey, bytes signature)`
fn decode_input(input: &[u8]) -> Result<SshVerifyInput, &'static str> {
    // ABI encoding layout:
    // [0..32]   bytes32 message (static)
    // [32..64]  offset to publicKey (dynamic)
    // [64..96]  offset to signature (dynamic)

    if input.len() < 96 {
        return Err("input too short");
    }

    let mut message = [0u8; 32];
    message.copy_from_slice(&input[0..32]);

    let pub_key_offset = u256_to_usize(&input[32..64])?;
    let sig_offset = u256_to_usize(&input[64..96])?;

    let public_key = read_dynamic_bytes(input, pub_key_offset)?;
    let signature = read_dynamic_bytes(input, sig_offset)?;

    Ok(SshVerifyInput { message, public_key, signature })
}

/// Read a uint256 as usize (for ABI offsets).
///
/// Rejects offsets whose upper 24 bytes are non-zero (those are definitionally
/// beyond any practical input length) and uses `usize::try_from` so a u64
/// value larger than `usize::MAX` on a 32-bit target is an error rather than
/// a silent truncation.
fn u256_to_usize(data: &[u8]) -> Result<usize, &'static str> {
    if data.len() != 32 {
        return Err("invalid uint256 length");
    }
    if data[0..24].iter().any(|&b| b != 0) {
        return Err("offset too large");
    }
    let val = u64::from_be_bytes(data[24..32].try_into().map_err(|_| "conversion error")?);
    usize::try_from(val).map_err(|_| "offset exceeds usize::MAX")
}

/// Read ABI-encoded dynamic bytes from a given offset.
///
/// Uses `checked_add` throughout so an adversarial `offset` or `length` near
/// `usize::MAX` cannot wrap into a valid slice index — without this, a crafted
/// ABI input could pass the bounds check and then panic at `&input[a..b]`
/// when `a > b`, which inside a precompile means a consensus halt.
fn read_dynamic_bytes(input: &[u8], offset: usize) -> Result<Vec<u8>, &'static str> {
    let header_end = offset.checked_add(32).ok_or("offset overflow")?;
    if header_end > input.len() {
        return Err("offset out of bounds");
    }
    let length = u256_to_usize(&input[offset..header_end])?;
    let data_end = header_end.checked_add(length).ok_or("length overflow")?;
    if data_end > input.len() {
        return Err("data out of bounds");
    }
    Ok(input[header_end..data_end].to_vec())
}

// ─────────────────────────────────────────── Verification dispatch

/// SSH verify precompile entry point.
fn ssh_verify_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_cost = required_gas(input);
    if gas_limit < gas_cost {
        return PrecompileResult::Err(revm::precompile::PrecompileError::OutOfGas);
    }

    let SshVerifyInput { message, public_key, signature } = match decode_input(input) {
        Ok(decoded) => decoded,
        // Decode failure → bytes32(0) (ecrecover convention — never revert on
        // parsed-but-unverifiable input).
        Err(_) => return PrecompileResult::Ok(PrecompileOutput::new(gas_cost, failure_result())),
    };

    let verified = run_verification(&public_key, &signature, message.as_slice());

    if verified {
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, success_result()))
    } else {
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, failure_result()))
    }
}

/// Parse the SSH wire-format public key + signature and dispatch on key type.
/// Returns `false` for any parse failure or unsupported algorithm — never panics.
fn run_verification(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let mut key_offset = 0usize;
    let key_type = match read_ssh_string(public_key, &mut key_offset) {
        Ok(t) => t,
        Err(_) => return false,
    };

    let mut sig_parse_offset = 0usize;
    let sig_algo = match read_ssh_string(signature, &mut sig_parse_offset) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_blob = match read_ssh_string(signature, &mut sig_parse_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };

    match key_type {
        b"ssh-ed25519" => verify_ssh_ed25519(public_key, key_offset, message, sig_algo, sig_blob),
        b"ssh-rsa" => verify_ssh_rsa(public_key, key_offset, message, sig_algo, sig_blob),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the SSH signature verification precompile.
    //!
    //! Test vectors generated using Python's `cryptography` library with known seeds.
    //! Ed25519 seed: 9d61b19d...7f60 (RFC 8032 test vector 2 seed)

    use super::*;

    // Pre-generated test data (ABI-encoded precompile inputs)
    const ED25519_INPUT: &str = include_str!("testdata_ssh_verify_ed25519.hex");
    const RSA_INPUT: &str = include_str!("testdata_ssh_verify_rsa.hex");

    const SUCCESS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const FAILURE_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn hex_decode(s: &str) -> Vec<u8> {
        alloy_primitives::hex::decode(s.trim()).expect("valid hex")
    }

    fn assert_precompile_ok(result: &PrecompileResult, expected_gas: u64, expected_output: &str) {
        let output = result.as_ref().expect("expected Ok result");
        assert_eq!(output.gas_used, expected_gas);
        assert_eq!(alloy_primitives::hex::encode(&output.bytes), expected_output);
    }

    fn assert_precompile_oog(result: &PrecompileResult) {
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::OutOfGas)),
            "expected OutOfGas, got: {result:?}"
        );
    }

    // === Gas calculation tests ===

    #[test]
    fn test_gas_calculation_base() {
        assert_eq!(required_gas(&vec![0u8; SSH_VERIFY_INPUT_LENGTH_KINK]), SSH_VERIFY_BASE_GAS);
        assert_eq!(required_gas(&vec![0u8; 100]), SSH_VERIFY_BASE_GAS);
        assert_eq!(required_gas(&[]), SSH_VERIFY_BASE_GAS);
    }

    #[test]
    fn test_gas_calculation_above_kink() {
        assert_eq!(
            required_gas(&vec![0u8; SSH_VERIFY_INPUT_LENGTH_KINK + 1]),
            SSH_VERIFY_BASE_GAS + SSH_VERIFY_GAS_PER_BYTE,
        );
    }

    #[test]
    fn test_gas_kink_boundary() {
        assert_eq!(required_gas(&vec![0u8; SSH_VERIFY_INPUT_LENGTH_KINK - 1]), SSH_VERIFY_BASE_GAS);
        assert_eq!(required_gas(&vec![0u8; SSH_VERIFY_INPUT_LENGTH_KINK]), SSH_VERIFY_BASE_GAS);
        assert_eq!(
            required_gas(&vec![0u8; SSH_VERIFY_INPUT_LENGTH_KINK + 1]),
            SSH_VERIFY_BASE_GAS + SSH_VERIFY_GAS_PER_BYTE,
        );
    }

    // === ABI decoding tests ===

    #[test]
    fn test_decode_ed25519_input() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        assert_eq!(decoded.message.len(), 32);
        assert!(!decoded.public_key.is_empty());
        assert!(!decoded.signature.is_empty());
    }

    #[test]
    fn test_decode_rsa_input() {
        let input = hex_decode(RSA_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        assert_eq!(decoded.message.len(), 32);
        assert!(!decoded.public_key.is_empty());
        assert!(!decoded.signature.is_empty());
    }

    // === Full verification tests ===

    #[test]
    fn test_ssh_verify_ed25519() {
        let input = hex_decode(ED25519_INPUT);
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, SUCCESS_HEX);
    }

    #[test]
    fn test_ssh_verify_rsa_sha256() {
        let input = hex_decode(RSA_INPUT);
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, SUCCESS_HEX);
    }

    // === Out-of-gas tests ===

    #[test]
    fn test_ssh_verify_oog() {
        let input = hex_decode(ED25519_INPUT);
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS - 1);
        assert_precompile_oog(&result);
    }

    #[test]
    fn test_ssh_verify_zero_gas() {
        let input = hex_decode(ED25519_INPUT);
        let result = ssh_verify_run(&input, 0);
        assert_precompile_oog(&result);
    }

    // === Wrong message tests ===

    #[test]
    fn test_ssh_verify_ed25519_wrong_message() {
        let mut input = hex_decode(ED25519_INPUT);
        input[0] ^= 0xFF;
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_rsa_wrong_message() {
        let mut input = hex_decode(RSA_INPUT);
        input[0] ^= 0xFF;
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    // === Error case tests ===
    //
    // The precompile follows the `ecrecover` convention: only out-of-gas
    // returns `Err`. Parsed-but-unverifiable inputs (malformed ABI, corrupt
    // SSH wire format, unsupported key type) all return `bytes32(0)` so a
    // caller cannot accidentally revert on "the signature didn't verify."

    #[test]
    fn test_ssh_verify_empty_input() {
        let result = ssh_verify_run(&[], SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_truncated_input() {
        let input = vec![0u8; 95];
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_crafted_offset_no_panic() {
        // Regression: pre-hardening, `u256_to_usize` returned an attacker-
        // chosen usize and `read_dynamic_bytes` ran `offset + 32` unchecked.
        // With offset = usize::MAX - 10, the addition wrapped past
        // input.len(), the bounds check trivially passed, and slicing
        // `&input[(usize::MAX - 10)..22]` panicked. A panic inside a
        // precompile is a consensus halt, so this test must return cleanly
        // (any non-panicking outcome is acceptable; we just don't want crash).
        let mut input = vec![0u8; 96];
        // Set pub_key_offset = usize::MAX - 10 (lower 8 bytes), upper 24 = 0.
        let huge = (usize::MAX - 10) as u64;
        input[32..56].fill(0);
        input[56..64].copy_from_slice(&huge.to_be_bytes());
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_offset_upper_bytes_rejected() {
        // u256 with non-zero upper bytes (any of bytes [0..24] non-zero) is
        // definitionally beyond input length — reject at decode.
        let mut input = vec![0u8; 96];
        input[32] = 0x01; // first byte of pub_key_offset → non-zero in upper 24
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_corrupt_public_key() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        let garbage_key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let corrupt = encode_ssh_verify_input(&decoded.message, &garbage_key, &decoded.signature);
        let result = ssh_verify_run(&corrupt, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_corrupt_signature() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        let garbage_sig = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let corrupt = encode_ssh_verify_input(&decoded.message, &decoded.public_key, &garbage_sig);
        let result = ssh_verify_run(&corrupt, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_unsupported_algo() {
        // Build an input with key type "ssh-dss" (unsupported)
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        fn ssh_string(data: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
            buf
        }
        let fake_key = [ssh_string(b"ssh-dss"), ssh_string(&[0u8; 32])].concat();
        let corrupt = encode_ssh_verify_input(&decoded.message, &fake_key, &decoded.signature);
        let result = ssh_verify_run(&corrupt, SSH_VERIFY_BASE_GAS);
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_algo_mismatch() {
        // Ed25519 key but RSA signature algorithm — should fail verification
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        fn ssh_string(data: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
            buf
        }
        // Forge a signature with rsa-sha2-256 algo but ed25519 sig blob
        let mut sig_offset = 0;
        let _ = read_ssh_string(&decoded.signature, &mut sig_offset); // skip algo
        let sig_blob = read_ssh_string(&decoded.signature, &mut sig_offset).unwrap();
        let mismatched_sig = [ssh_string(b"rsa-sha2-256"), ssh_string(sig_blob)].concat();

        let corrupt = encode_ssh_verify_input(&decoded.message, &decoded.public_key, &mismatched_sig);
        let result = ssh_verify_run(&corrupt, SSH_VERIFY_BASE_GAS);
        // Should return 0 (invalid), not an error
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    // === RSA key size cap ===

    #[test]
    fn test_ssh_verify_rsa_key_too_large() {
        // Construct a fake 8192-bit RSA key (1024-byte modulus) — should be rejected.
        fn ssh_string(data: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
            buf
        }

        // Build an oversized SSH RSA public key
        let e_bytes = vec![0x01, 0x00, 0x01]; // 65537
        let n_bytes = vec![0x01; 1024]; // 8192-bit modulus (> MAX_RSA_MODULUS_BYTES)
        let oversized_key = [
            ssh_string(b"ssh-rsa"),
            ssh_string(&e_bytes),
            ssh_string(&n_bytes),
        ].concat();

        // Build a fake rsa-sha2-256 signature (content doesn't matter, we should
        // reject before we even try to verify)
        let fake_sig = [
            ssh_string(b"rsa-sha2-256"),
            ssh_string(&vec![0xAA; 256]),
        ].concat();

        let message = [0x42u8; 32];
        let input = encode_ssh_verify_input(&message, &oversized_key, &fake_sig);
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS);

        // Should return bytes32(0) — rejected, not an error
        assert_precompile_ok(&result, SSH_VERIFY_BASE_GAS, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_rsa_key_at_max_size() {
        // Real RSA-4096 keypair signing a real message, verified end-to-end.
        // RSA-N keygen always produces a modulus with bit_length == N, so the
        // high bit is always set and the SSH mpint encoding always prepends a
        // 0x00 — RSA-4096 mpint payload is therefore 513 bytes. Before the
        // strip_mpint_pad fix at verify_rsa(), this hit the size gate and was
        // wrongly rejected. This test asserts SUCCESS_HEX, so it locks in the
        // strip behavior.
        use rand_08::SeedableRng;
        use rsa::pkcs1v15::SigningKey;
        use rsa::traits::PublicKeyParts;
        use sha2::Sha256;
        use signature::{SignatureEncoding, Signer};

        fn ssh_string(data: &[u8]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(4 + data.len());
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
            buf
        }

        /// SSH mpint encoding per RFC 4251 §5: strip extraneous leading zeros,
        /// then prepend 0x00 if the high bit is set so positive numbers don't
        /// decode as negative.
        fn ssh_mpint(value: &[u8]) -> Vec<u8> {
            let mut start = 0;
            while start < value.len() - 1 && value[start] == 0 {
                start += 1;
            }
            let trimmed = &value[start..];
            let needs_pad = trimmed.first().is_some_and(|b| *b & 0x80 != 0);
            let mut payload = Vec::with_capacity(trimmed.len() + needs_pad as usize);
            if needs_pad {
                payload.push(0u8);
            }
            payload.extend_from_slice(trimmed);
            ssh_string(&payload)
        }

        // Deterministic key for reproducible CI runs.
        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let private_key =
            rsa::RsaPrivateKey::new(&mut rng, 4096).expect("RSA-4096 keygen succeeds");
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let mut pub_blob = ssh_string(b"ssh-rsa");
        pub_blob.extend_from_slice(&ssh_mpint(&public_key.e().to_bytes_be()));
        pub_blob.extend_from_slice(&ssh_mpint(&public_key.n().to_bytes_be()));

        let message = [0x42u8; 32];
        let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
        let signature = signing_key.sign(&message);
        let sig_bytes = signature.to_bytes();

        let mut sig_blob = ssh_string(b"rsa-sha2-256");
        sig_blob.extend_from_slice(&ssh_string(&sig_bytes));

        let input = encode_ssh_verify_input(&message, &pub_blob, &sig_blob);
        let gas = required_gas(&input);
        let result = ssh_verify_run(&input, gas);
        assert_precompile_ok(&result, gas, SUCCESS_HEX);
    }

    // === Helper: ABI-encode SSH verify input ===
    //
    // (SSH wire-format parser tests live in ssh_common.rs alongside the
    // shared implementation.)

    fn encode_ssh_verify_input(
        message: &[u8; 32],
        public_key: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        // [0..32] bytes32 message
        buf.extend_from_slice(message);

        // [32..64] offset to publicKey = 96 (3 * 32 bytes of header)
        buf.extend_from_slice(&u256_bytes(96));

        // [64..96] offset to signature
        let pub_key_padded_len = (public_key.len() + 31) / 32 * 32;
        let sig_offset = 96 + 32 + pub_key_padded_len;
        buf.extend_from_slice(&u256_bytes(sig_offset));

        // publicKey: length + data (padded to 32 bytes)
        buf.extend_from_slice(&u256_bytes(public_key.len()));
        buf.extend_from_slice(public_key);
        let pub_key_padding = pub_key_padded_len - public_key.len();
        buf.extend_from_slice(&vec![0u8; pub_key_padding]);

        // signature: length + data (padded to 32 bytes)
        buf.extend_from_slice(&u256_bytes(signature.len()));
        buf.extend_from_slice(signature);
        let sig_padded_len = (signature.len() + 31) / 32 * 32;
        let sig_padding = sig_padded_len - signature.len();
        buf.extend_from_slice(&vec![0u8; sig_padding]);

        buf
    }

    fn u256_bytes(val: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&(val as u64).to_be_bytes());
        out
    }
}
