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
//! Returns `bytes32(1)` for valid signatures, `bytes32(0)` for invalid.
//!
//! # Supported algorithms
//!
//! - `ssh-ed25519`: Ed25519 signatures (64-byte sig, 32-byte pubkey)
//! - `rsa-sha2-256`: RSA with SHA-256 (PKCS#1 v1.5), max 4096-bit key
//! - `rsa-sha2-512`: RSA with SHA-512 (PKCS#1 v1.5), max 4096-bit key

use alloy_primitives::{Address, Bytes, address};
use revm::precompile::{Precompile, PrecompileId, PrecompileOutput, PrecompileResult};

/// SSH verify precompile address.
pub const SSH_VERIFY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000697");

/// Base gas cost for SSH verification.
pub const SSH_VERIFY_BASE_GAS: u64 = 23_500;

/// Per-byte gas cost above the kink point.
pub const SSH_VERIFY_GAS_PER_BYTE: u64 = 16;

/// Input length kink point — below this, only base gas is charged.
pub const SSH_VERIFY_INPUT_LENGTH_KINK: usize = 3264;

/// Maximum RSA modulus size in bytes (4096-bit = 512 bytes).
/// Bump this and release a new tea-reth if 8192-bit keys are ever needed.
pub const MAX_RSA_MODULUS_BYTES: usize = 512;

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

// ─────────────────────────────────────────── SSH wire format helpers

/// Strip the leading 0x00 disambiguation byte from an SSH mpint payload.
///
/// RFC 4251 §5 prepends 0x00 to positive integers whose high bit is set so they
/// don't decode as negative. Canonical mpints have at most one leading 0x00.
fn strip_mpint_pad(bytes: &[u8]) -> &[u8] {
    if bytes.first() == Some(&0u8) {
        &bytes[1..]
    } else {
        bytes
    }
}

/// Read a length-prefixed string from SSH wire format.
///
/// SSH wire format uses `uint32` big-endian length prefix followed by raw bytes.
/// Returns the string data and advances the offset.
fn read_ssh_string<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], &'static str> {
    if *offset + 4 > data.len() {
        return Err("truncated string length");
    }
    let len = u32::from_be_bytes(
        data[*offset..*offset + 4]
            .try_into()
            .map_err(|_| "length conversion error")?,
    ) as usize;
    *offset += 4;
    if *offset + len > data.len() {
        return Err("truncated string data");
    }
    let result = &data[*offset..*offset + len];
    *offset += len;
    Ok(result)
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
fn u256_to_usize(data: &[u8]) -> Result<usize, &'static str> {
    if data.len() != 32 {
        return Err("invalid uint256 length");
    }
    let val = u64::from_be_bytes(data[24..32].try_into().map_err(|_| "conversion error")?);
    Ok(val as usize)
}

/// Read ABI-encoded dynamic bytes from a given offset.
fn read_dynamic_bytes(input: &[u8], offset: usize) -> Result<Vec<u8>, &'static str> {
    if offset + 32 > input.len() {
        return Err("offset out of bounds");
    }
    let length = u256_to_usize(&input[offset..offset + 32])?;
    let data_start = offset + 32;
    if data_start + length > input.len() {
        return Err("data out of bounds");
    }
    Ok(input[data_start..data_start + length].to_vec())
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
        Err(_) => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "failed to decode ssh verify input".into(),
            ));
        }
    };

    // Parse SSH public key wire format to get key type
    let mut key_offset = 0usize;
    let key_type = match read_ssh_string(&public_key, &mut key_offset) {
        Ok(t) => t,
        Err(_) => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "invalid ssh public key".into(),
            ));
        }
    };

    // Parse SSH signature wire format to get algorithm and blob
    let mut sig_parse_offset = 0usize;
    let sig_algo = match read_ssh_string(&signature, &mut sig_parse_offset) {
        Ok(a) => a,
        Err(_) => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "invalid ssh signature".into(),
            ));
        }
    };
    let sig_blob = match read_ssh_string(&signature, &mut sig_parse_offset) {
        Ok(b) => b,
        Err(_) => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "invalid ssh signature blob".into(),
            ));
        }
    };

    // Dispatch verification based on key type
    let verified = match key_type {
        b"ssh-ed25519" => verify_ed25519(&public_key, key_offset, &message, sig_algo, sig_blob),
        b"ssh-rsa" => verify_rsa(&public_key, key_offset, &message, sig_algo, sig_blob),
        _ => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "unsupported ssh key type".into(),
            ));
        }
    };

    if verified {
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, success_result()))
    } else {
        // Invalid signature is not an error — return 0
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, failure_result()))
    }
}

/// Verify an ed25519 SSH signature.
fn verify_ed25519(
    pub_key_data: &[u8],
    offset: usize,
    message: &[u8; 32],
    sig_algo: &[u8],
    sig_blob: &[u8],
) -> bool {
    // Verify algorithm consistency: key type and sig algo must both be ssh-ed25519
    if sig_algo != b"ssh-ed25519" {
        return false;
    }

    // Extract 32-byte ed25519 public key from SSH wire format
    let mut key_offset = offset;
    let key_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(k) if k.len() == 32 => k,
        _ => return false,
    };

    // Verify ed25519 signature (must be exactly 64 bytes)
    if sig_blob.len() != 64 {
        return false;
    }

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(
        key_bytes.try_into().unwrap_or(&[0u8; 32]),
    ) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let signature = ed25519_dalek::Signature::from_bytes(sig_blob.try_into().unwrap_or(&[0u8; 64]));

    use ed25519_dalek::Verifier;
    verifying_key.verify(message, &signature).is_ok()
}

/// Verify an RSA SSH signature (rsa-sha2-256 or rsa-sha2-512).
fn verify_rsa(
    pub_key_data: &[u8],
    offset: usize,
    message: &[u8; 32],
    sig_algo: &[u8],
    sig_blob: &[u8],
) -> bool {
    // Parse RSA public key: mpint e, mpint n
    let mut key_offset = offset;
    let e_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let n_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Strip the leading 0x00 that SSH mpint encoding (RFC 4251 §5) prepends to
    // positive integers whose high bit is set, so MAX_RSA_MODULUS_BYTES applies
    // to the modulus itself. RSA-N keygen always produces a modulus with
    // bit_length == N (high bit set), so RSA-4096 always mpint-encodes to 513
    // bytes — without the strip, every real RSA-4096 key fails the size gate.
    let n_unpadded = strip_mpint_pad(n_bytes);

    // Reject RSA keys larger than 4096-bit. Bump MAX_RSA_MODULUS_BYTES and
    // release a new tea-reth binary if larger keys are ever needed.
    if n_unpadded.len() > MAX_RSA_MODULUS_BYTES {
        return false;
    }

    // Construct RSA public key
    let e = rsa::BigUint::from_bytes_be(e_bytes);
    let n = rsa::BigUint::from_bytes_be(n_unpadded);
    let pub_key = match rsa::RsaPublicKey::new(n, e) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // Dispatch based on signature algorithm
    match sig_algo {
        b"rsa-sha2-256" => {
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use sha2::Sha256;
            use signature::Verifier;

            let verifying_key = VerifyingKey::<Sha256>::new(pub_key);
            let sig = match Signature::try_from(sig_blob) {
                Ok(s) => s,
                Err(_) => return false,
            };
            verifying_key.verify(message.as_slice(), &sig).is_ok()
        }
        b"rsa-sha2-512" => {
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use sha2::Sha512;
            use signature::Verifier;

            let verifying_key = VerifyingKey::<Sha512>::new(pub_key);
            let sig = match Signature::try_from(sig_blob) {
                Ok(s) => s,
                Err(_) => return false,
            };
            verifying_key.verify(message.as_slice(), &sig).is_ok()
        }
        // Reject deprecated ssh-rsa (SHA-1) — insecure
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

    // === rsa-sha2-512 round-trip tests (runtime-signed) ===
    //
    // The `rsa-sha2-512` arm at verify_rsa() lines 299-310 was only declared
    // and unit-tested via the rsa-sha2-256 fixture (testdata_ssh_verify_rsa.hex).
    // These tests sign a fresh message with SHA-512 at test runtime, wire-format
    // encode the result, and run it through the precompile end-to-end. Proves
    // that the SHA-512 dispatch arm is actually reachable and produces the
    // expected accept/reject signal — no Python or external fixture needed.

    /// Encodes a uint32 length followed by the bytes (SSH RFC 4251 `string`).
    fn ssh_wire_string(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// Encodes an mpint per RFC 4251 §5: prepends 0x00 if the high bit is set
    /// (positive-number ambiguity guard).
    fn ssh_wire_mpint(value: &[u8]) -> Vec<u8> {
        // Trim leading zeros first
        let mut start = 0;
        while start < value.len() - 1 && value[start] == 0 {
            start += 1;
        }
        let trimmed = &value[start..];
        let needs_pad = trimmed.first().is_some_and(|b| *b & 0x80 != 0);
        let mut buf = Vec::with_capacity(4 + trimmed.len() + needs_pad as usize);
        let total_len = trimmed.len() + needs_pad as usize;
        buf.extend_from_slice(&(total_len as u32).to_be_bytes());
        if needs_pad {
            buf.push(0u8);
        }
        buf.extend_from_slice(trimmed);
        buf
    }

    /// Builds an SSH wire-format RSA public key blob:
    ///   string("ssh-rsa") + mpint(e) + mpint(n)
    fn build_rsa_public_key_blob(
        pub_key: &rsa::RsaPublicKey,
    ) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        let mut out = Vec::new();
        out.extend_from_slice(&ssh_wire_string(b"ssh-rsa"));
        out.extend_from_slice(&ssh_wire_mpint(&pub_key.e().to_bytes_be()));
        out.extend_from_slice(&ssh_wire_mpint(&pub_key.n().to_bytes_be()));
        out
    }

    /// Builds an SSH wire-format signature blob:
    ///   string(algorithm) + string(sig_bytes)
    fn build_signature_blob(algorithm: &[u8], sig_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ssh_wire_string(algorithm));
        out.extend_from_slice(&ssh_wire_string(sig_bytes));
        out
    }

    /// Signs `message` with a freshly-generated 2048-bit RSA key using
    /// PKCS#1 v1.5 + SHA-512 and returns `(precompile_input, public_key_blob)`.
    fn sign_rsa_sha512_at_runtime(
        message: &[u8; 32],
    ) -> (Vec<u8>, rsa::RsaPublicKey) {
        use rand_08::SeedableRng;
        use rsa::pkcs1v15::SigningKey;
        use sha2::Sha512;
        use signature::{SignatureEncoding, Signer};

        // Deterministic key for reproducible CI runs. Test value, not a real key.
        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
            .expect("RSA-2048 keygen succeeds");
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let signing_key: SigningKey<Sha512> = SigningKey::new(private_key);
        let signature = signing_key.sign(message);
        let sig_bytes = signature.to_bytes();

        let pub_key_blob = build_rsa_public_key_blob(&public_key);
        let sig_blob = build_signature_blob(b"rsa-sha2-512", &sig_bytes);
        let input = encode_ssh_verify_input(message, &pub_key_blob, &sig_blob);
        (input, public_key)
    }

    #[test]
    fn test_ssh_verify_rsa_sha512_round_trip() {
        // 32-byte message, signed with rsa-sha2-512, verified by 0x0697.
        let message = [0xAAu8; 32];
        let (input, _pubkey) = sign_rsa_sha512_at_runtime(&message);
        let gas = required_gas(&input);
        let result = ssh_verify_run(&input, gas);
        assert_precompile_ok(&result, gas, SUCCESS_HEX);
    }

    #[test]
    fn test_ssh_verify_rsa_sha512_wrong_message() {
        // Sign one message, but flip the first byte before feeding to the
        // precompile. The SHA-512 hash now differs, so PKCS#1 v1.5 verification
        // must fail — but the precompile call itself succeeds with bytes32(0).
        let message = [0xBBu8; 32];
        let (mut input, _pubkey) = sign_rsa_sha512_at_runtime(&message);
        input[0] ^= 0xFF; // First byte of the ABI-encoded message field.
        let gas = required_gas(&input);
        let result = ssh_verify_run(&input, gas);
        assert_precompile_ok(&result, gas, FAILURE_HEX);
    }

    #[test]
    fn test_ssh_verify_rsa_sha512_distinct_from_sha256() {
        // Proves the algorithm string actually matters: a SHA-512 signature
        // labelled as rsa-sha2-256 must NOT verify (the precompile will
        // hash the message with SHA-256 and compare against a SHA-512 sig
        // — totally different bytes). Defends against future refactors that
        // accidentally merge the dispatch arms.
        let message = [0xCCu8; 32];
        let (mut input, _pubkey) = sign_rsa_sha512_at_runtime(&message);

        // Locate the signature's algorithm string inside the ABI-encoded
        // payload and replace b"rsa-sha2-512" with b"rsa-sha2-256" (same length).
        let needle = b"rsa-sha2-512";
        let replacement = b"rsa-sha2-256";
        let pos = input
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("algorithm string must appear in ABI payload");
        input[pos..pos + needle.len()].copy_from_slice(replacement);

        let gas = required_gas(&input);
        let result = ssh_verify_run(&input, gas);
        assert_precompile_ok(&result, gas, FAILURE_HEX);
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

    #[test]
    fn test_ssh_verify_empty_input() {
        let result = ssh_verify_run(&[], SSH_VERIFY_BASE_GAS);
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "expected decode error for empty input, got: {result:?}"
        );
    }

    #[test]
    fn test_ssh_verify_truncated_input() {
        let input = vec![0u8; 95];
        let result = ssh_verify_run(&input, SSH_VERIFY_BASE_GAS);
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "expected decode error for truncated input, got: {result:?}"
        );
    }

    #[test]
    fn test_ssh_verify_corrupt_public_key() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        let garbage_key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let corrupt = encode_ssh_verify_input(&decoded.message, &garbage_key, &decoded.signature);
        let result = ssh_verify_run(&corrupt, SSH_VERIFY_BASE_GAS);
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "expected error for corrupt key, got: {result:?}"
        );
    }

    #[test]
    fn test_ssh_verify_corrupt_signature() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        let garbage_sig = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let corrupt = encode_ssh_verify_input(&decoded.message, &decoded.public_key, &garbage_sig);
        let result = ssh_verify_run(&corrupt, SSH_VERIFY_BASE_GAS);
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "expected error for corrupt sig, got: {result:?}"
        );
    }

    #[test]
    fn test_ssh_verify_unsupported_algo() {
        // Build an input with key type "ssh-dss" (unsupported)
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        // Construct a fake DSA key (just the type string + garbage)
        fn ssh_string(data: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
            buf
        }
        let fake_key = [ssh_string(b"ssh-dss"), ssh_string(&[0u8; 32])].concat();
        let corrupt = encode_ssh_verify_input(&decoded.message, &fake_key, &decoded.signature);
        let result = ssh_verify_run(&corrupt, SSH_VERIFY_BASE_GAS);
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "expected unsupported algo error, got: {result:?}"
        );
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

    // === SSH wire format parsing tests ===

    #[test]
    fn test_read_ssh_string_valid() {
        let data = [0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'];
        let mut offset = 0;
        let result = read_ssh_string(&data, &mut offset).unwrap();
        assert_eq!(result, b"hello");
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_read_ssh_string_truncated_length() {
        let data = [0, 0, 0];
        let mut offset = 0;
        assert!(read_ssh_string(&data, &mut offset).is_err());
    }

    #[test]
    fn test_read_ssh_string_truncated_data() {
        let data = [0, 0, 0, 10, b'h', b'i'];
        let mut offset = 0;
        assert!(read_ssh_string(&data, &mut offset).is_err());
    }

    // === Helper: ABI-encode SSH verify input ===

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
