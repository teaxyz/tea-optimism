//! GPG signature verification precompile.
//!
//! Verifies ed25519 and RSA GPG signatures. Registered at address `0x0696`.
//!
//! Input format: `abi.encode(bytes32 message, bytes8 keyId, bytes publicKey, bytes signature)`
//! Returns `bytes32(1)` for valid signatures, `bytes32(0)` for invalid.
//!
//! # Hash algorithm policy
//!
//! This precompile verifies the GPG signature primitive **mathematically** —
//! given (message, pubkey, signature), it returns whether the signature is a
//! valid GPG signature over the message under the pubkey. It does not opine
//! on the *strength* of the hash algorithm the signer chose.
//!
//! GPG signatures using SHA-1, MD5, or RIPEMD-160 are still cryptographically
//! valid per the OpenPGP protocol; rejecting them at the precompile layer
//! would break legacy keys (pre-2014 GPG defaulted to SHA-1, and a significant
//! fraction of long-lived signing keys still emit SHA-1 sigs by configuration
//! or by certificate). The relevant attack (chosen-prefix collision against
//! SHA-1/MD5) also requires the attacker to control content the legitimate
//! signer is willing to sign — a constraint that depends entirely on the
//! application semantics around the signature, not on the precompile.
//!
//! **Callers wanting cryptographic-strength guarantees** (e.g., that the
//! signature was made under SHA-256 or stronger) must enforce that policy
//! at the application layer *before* invoking this precompile. The OpenPGP
//! signature packet exposes the hash algorithm in a fixed offset; parsing
//! it out is a few lines of Solidity. In the tea-protocol contract suite,
//! `PrecompileClaimVerifier.sol` is the canonical place for that gate —
//! contributor-claim verifications and on-chain identity claims that rely on
//! a hash-strength guarantee should reject weak-hash sigs at that layer.
//!
//! Changing this behavior here would silently break every legacy key that
//! existing callers may already trust — a policy change of that magnitude
//! belongs at the policy layer, not buried in a verification precompile.

use alloy_primitives::Bytes;
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedPublicSubKey};
use pgp::packet::{Signature, SignatureType};
use pgp::types::KeyDetails;
use revm::precompile::{Precompile, PrecompileId, PrecompileOutput, PrecompileResult};
use std::cmp::Ordering;
use std::io::Cursor;

/// Address + gas schedule live in the no_std [`crate::gas`] module so the FPVM
/// can charge identical gas without linking this crate's crypto. Re-exported
/// here so internal call sites and the public API are unchanged.
pub use crate::gas::{
    GPG_VERIFY_ADDRESS, GPG_VERIFY_BASE_GAS, GPG_VERIFY_GAS_PER_BYTE,
    GPG_VERIFY_INPUT_LENGTH_KINK, gpg_required_gas as required_gas,
};

/// Returns the GPG verify precompile for registration.
pub fn precompile() -> Precompile {
    Precompile::new(PrecompileId::custom("gpg_verify"), GPG_VERIFY_ADDRESS, gpg_verify_run)
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

/// Extract 8-byte legacy key ID from a fingerprint (last 8 bytes for v4 keys).
fn fingerprint_to_key_id(fp: &pgp::types::Fingerprint) -> [u8; 8] {
    let bytes: &[u8] = fp.as_ref();
    let mut id = [0u8; 8];
    if bytes.len() >= 8 {
        id.copy_from_slice(&bytes[bytes.len() - 8..]);
    }
    id
}

/// Parse exactly one OpenPGP object from `bytes`, rejecting empty or
/// multi-object streams.
///
/// `Deserializable::from_bytes` silently returns only the *first* object in a
/// stream, so an attacker can append additional key or signature objects to a
/// blob and have them ignored — producing multiple distinct byte strings that
/// all verify identically (TEAO1-172). Requiring exactly one object removes that
/// ambiguity: the verified bytes are the only bytes.
fn parse_single<T: Deserializable>(bytes: &[u8]) -> Result<T, &'static str> {
    let mut iter = T::from_bytes_many(Cursor::new(bytes)).map_err(|_| "parse error")?;
    let first = match iter.next() {
        Some(Ok(obj)) => obj,
        _ => return Err("no parseable object"),
    };
    if iter.next().is_some() {
        return Err("trailing object");
    }
    Ok(first)
}

/// Whether a subkey's **effective** self-signature authorizes signing.
///
/// A subkey's capability is governed by its single most recent self-signature
/// — the latest valid `SubkeyBinding` or `SubkeyRevocation` packet — not by the
/// union of every binding it has ever carried. The previous `any()` form
/// unioned the `sign` flag across all retained bindings, so a stale
/// signing-capable binding kept a subkey eligible even after a later valid
/// non-signing re-binding or a revocation (TEAO1-193). We instead resolve the
/// effective packet and honor only it: an encryption-only subkey (TEAO1-160), a
/// re-bound non-signing subkey, or a revoked subkey is rejected.
///
/// The packets consulted here are the same `SubkeyBinding`/`SubkeyRevocation`
/// self-signatures that [`SignedPublicSubKey::verify_bindings`] has already
/// cryptographically validated against the primary key, so a forged flag or
/// timestamp cannot pass without also forging the primary's signature.
fn subkey_can_sign(sk: &SignedPublicSubKey) -> bool {
    // Restrictiveness rank used only to break creation-time ties. Lower = more
    // restrictive and therefore "wins" an equal-timestamp tie so we fail closed:
    // a revocation beats a binding, and a non-signing binding beats a signing
    // one. (`new()` retains only Binding/Revocation packets, so the catch-all is
    // unreachable; it ranks as most-restrictive defensively.)
    fn rank(sig: &Signature) -> u8 {
        match (sig.typ(), sig.key_flags().sign()) {
            (Some(SignatureType::SubkeyRevocation), _) => 0,
            (Some(SignatureType::SubkeyBinding), false) => 1,
            (Some(SignatureType::SubkeyBinding), true) => 2,
            _ => 0,
        }
    }

    // The effective self-signature is the one with the latest creation time.
    // Packets lacking a creation-time subpacket are malformed self-signatures
    // and cannot establish recency, so they are ignored for selection — a
    // signing binding with no timestamp therefore fails closed rather than
    // silently outranking a later non-signing binding.
    let effective = sk
        .signatures
        .iter()
        .filter(|sig| {
            matches!(
                sig.typ(),
                Some(SignatureType::SubkeyBinding) | Some(SignatureType::SubkeyRevocation)
            ) && sig.created().is_some()
        })
        .max_by(|a, b| {
            // Both `created()` are `Some` (filtered above); `Timestamp` is a
            // `u32` newtype so `partial_cmp` never returns `None`.
            let by_time = a
                .created()
                .partial_cmp(&b.created())
                .unwrap_or(Ordering::Equal);
            // On equal creation time, treat the more restrictive packet (lower
            // rank) as the greater one so `max_by` selects it.
            by_time.then_with(|| rank(b).cmp(&rank(a)))
        });

    matches!(
        effective.map(|sig| (sig.typ(), sig.key_flags().sign())),
        Some((Some(SignatureType::SubkeyBinding), true))
    )
}

/// Decoded GPG verify precompile input.
struct GpgVerifyInput {
    message: [u8; 32],
    key_id: [u8; 8],
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

/// ABI-decode the GPG verify input.
///
/// Expected: `abi.encode(bytes32 message, bytes8 keyId, bytes publicKey, bytes signature)`
fn decode_input(input: &[u8]) -> Result<GpgVerifyInput, &'static str> {
    // ABI encoding layout:
    // [0..32]   bytes32 message (static)
    // [32..64]  bytes8 keyId (right-padded to 32 bytes)
    // [64..96]  offset to publicKey (dynamic)
    // [96..128] offset to signature (dynamic)
    // Then dynamic data for publicKey and signature

    if input.len() < 128 {
        return Err("input too short");
    }

    // Extract message (bytes32)
    let mut message = [0u8; 32];
    message.copy_from_slice(&input[0..32]);

    // Extract keyId (bytes8, left-aligned in 32-byte slot)
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&input[32..40]);

    // Read offsets for dynamic data
    let pub_key_offset = u256_to_usize(&input[64..96])?;
    let sig_offset = u256_to_usize(&input[96..128])?;

    // Read publicKey
    let pub_key = read_dynamic_bytes(input, pub_key_offset)?;
    // Read signature
    let signature = read_dynamic_bytes(input, sig_offset)?;

    Ok(GpgVerifyInput { message, key_id, public_key: pub_key, signature })
}

/// Read a uint256 as usize (for ABI offsets).
///
/// Rejects offsets whose upper 24 bytes are non-zero (those are definitionally
/// beyond any practical input length) and uses `usize::try_from` so a u64
/// value larger than `usize::MAX` on a 32-bit target is an error rather than a
/// silent truncation. Mirrors the hardened decoder in `ssh_verify.rs`.
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
/// ABI input could pass the bounds check and then panic at `&input[a..b]` when
/// `a > b`, which inside a precompile means a consensus halt. The field is
/// implicitly bounded by `input.len()` (itself gas-bounded on-chain); unlike
/// the SSH precompiles, no fixed byte cap is imposed because a GPG transferable
/// public key with subkeys legitimately exceeds several KiB.
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

/// Only Binary-class signatures bind the exact 32-byte message digest the
/// precompile is asked to verify. Text signatures canonicalize line endings, so
/// distinct byte strings collide (TEAO1-166); Timestamp and Standalone
/// signatures bind no message data at all (TEAO1-148). Accept Binary only.
fn is_accepted_sig_type(typ: Option<SignatureType>) -> bool {
    typ == Some(SignatureType::Binary)
}

/// GPG verify precompile entry point.
///
/// Signature: `fn(&[u8], u64) -> PrecompileResult`
fn gpg_verify_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_cost = required_gas(input);
    if gas_limit < gas_cost {
        return PrecompileResult::Err(revm::precompile::PrecompileError::OutOfGas);
    }

    let GpgVerifyInput {
        message,
        key_id: expected_key_id,
        public_key: pub_key_bytes,
        signature: sig_bytes,
    } = match decode_input(input) {
        Ok(decoded) => decoded,
        Err(_) => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "failed to decode gpg verify input".into(),
            ));
        }
    };

    // Parse public key — reject empty or multi-object streams (TEAO1-172).
    let pub_key: SignedPublicKey = match parse_single(&pub_key_bytes) {
        Ok(key) => key,
        Err(_) => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "invalid public key".into(),
            ));
        }
    };

    let primary_id = fingerprint_to_key_id(&pub_key.fingerprint());

    // Determine which subkeys may act as signing authorities. A subkey is only
    // eligible if its binding to the primary is cryptographically valid
    // (TEAO1-141 — a grafted subkey from another cert has no valid binding) AND
    // it advertises signing capability (TEAO1-160 — an encryption-only subkey
    // must not sign).
    let eligible_subkeys: Vec<&SignedPublicSubKey> = pub_key
        .public_subkeys
        .iter()
        .filter(|sk| sk.verify_bindings(&pub_key.primary_key).is_ok() && subkey_can_sign(sk))
        .collect();

    // Key-ID membership gate: the claimed key ID must name the primary key or
    // one of its subkeys. This is an early rejection for inputs whose key ID is
    // absent from the certificate; the binding security property is enforced at
    // verification below, where the key that verifies must be the claimed one.
    let any_subkey_matches = pub_key
        .public_subkeys
        .iter()
        .any(|sk| fingerprint_to_key_id(&sk.fingerprint()) == expected_key_id);
    if primary_id != expected_key_id && !any_subkey_matches {
        return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
            "public key and key id do not match".into(),
        ));
    }

    // Parse detached signature — reject empty or multi-object streams (TEAO1-172).
    let sig: DetachedSignature = match parse_single(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "invalid signature".into(),
            ));
        }
    };

    // Reject everything but Binary (TEAO1-166 / TEAO1-148) — see `is_accepted_sig_type`.
    if !is_accepted_sig_type(sig.signature.typ()) {
        return PrecompileResult::Ok(PrecompileOutput::new(gas_cost, failure_result()));
    }

    // Verify, binding the verifying key to the claimed key ID (TEAO1-144): the
    // signature only counts if the key whose ID the caller claimed is the key
    // that actually verifies it — the primary key, or an eligible signing
    // subkey carrying that ID. A signature from a sibling key (different ID in
    // the same cert) no longer satisfies a claim about another key.
    let verified = (primary_id == expected_key_id && sig.verify(&pub_key, &message).is_ok())
        || eligible_subkeys.iter().any(|sk| {
            fingerprint_to_key_id(&sk.fingerprint()) == expected_key_id
                && sig.verify(sk, &message).is_ok()
        });

    if verified {
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, success_result()))
    } else {
        // Invalid signature is not an error — return 0
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, failure_result()))
    }
}

#[cfg(test)]
mod tests {
    //! Tests ported from tea-geth commit 46ec0efe:
    //!   - `core/vm/contracts_test.go` — GPG verify precompile tests
    //!   - `params/protocol_params.go` — gas constants (base=23500, per_byte=16, kink=3264)
    //!
    //! Test data (hex files) extracted verbatim from the Go test vectors.
    //! Each test below documents the original Go function it was ported from.

    use super::*;

    // Test data loaded from hex files extracted from tea-geth test suite.
    const ED25519_INPUT: &str = include_str!("testdata_gpg_verify_ed25519.hex");
    const RSA_INPUT: &str = include_str!("testdata_gpg_verify_rsa.hex");
    const LONG_INPUT: &str = include_str!("testdata_gpg_verify_long_input.hex");

    const SUCCESS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn hex_decode(s: &str) -> Vec<u8> {
        alloy_primitives::hex::decode(s).expect("valid hex")
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

    // === Gas calculation tests (from params/protocol_params.go lines 199-201) ===

    #[test]
    fn test_gas_calculation_base() {
        assert_eq!(required_gas(&vec![0u8; GPG_VERIFY_INPUT_LENGTH_KINK]), GPG_VERIFY_BASE_GAS);
        assert_eq!(required_gas(&[0u8; 100]), GPG_VERIFY_BASE_GAS);
    }

    #[test]
    fn test_gas_calculation_above_kink() {
        // 9504 bytes: 23500 + (9504 - 3264) * 16 = 123340
        assert_eq!(required_gas(&vec![0u8; 9504]), 123_340);
    }

    #[test]
    fn test_gas_calculation_just_above_kink() {
        assert_eq!(
            required_gas(&vec![0u8; GPG_VERIFY_INPUT_LENGTH_KINK + 1]),
            GPG_VERIFY_BASE_GAS + GPG_VERIFY_GAS_PER_BYTE
        );
    }

    // === ABI decoding tests (validates decodegpgVerifyInput from contracts.go:1828) ===

    #[test]
    fn test_decode_ed25519_input() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        assert_eq!(decoded.message.len(), 32);
        assert_eq!(decoded.key_id.len(), 8);
        assert!(!decoded.public_key.is_empty());
        assert!(!decoded.signature.is_empty());
    }

    #[test]
    fn test_decode_rsa_input() {
        let input = hex_decode(RSA_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        assert_eq!(decoded.message.len(), 32);
        assert_eq!(decoded.key_id.len(), 8);
        assert!(!decoded.public_key.is_empty());
        assert!(!decoded.signature.is_empty());
    }

    // === Full verification tests (ported from contracts_test.go) ===

    /// Ported from: `TestPrecompiledGPGVerify_ED25519` (contracts_test.go:580)
    /// Input: ed25519 key+sig, gas=23500, expected=0x01 (valid)
    #[test]
    fn test_gpg_verify_ed25519() {
        let input = hex_decode(ED25519_INPUT);
        let result = gpg_verify_run(&input, 23_500);
        assert_precompile_ok(&result, 23_500, SUCCESS_HEX);
    }

    /// Ported from: `TestPrecompiledGPGVerify_RSA` (contracts_test.go:590)
    /// Input: RSA key+sig, gas=23500, expected=0x01 (valid)
    #[test]
    fn test_gpg_verify_rsa() {
        let input = hex_decode(RSA_INPUT);
        let result = gpg_verify_run(&input, 23_500);
        assert_precompile_ok(&result, 23_500, SUCCESS_HEX);
    }

    /// Ported from: `TestPrecompiledGPGVerify_OOG` (contracts_test.go:600)
    /// Same ed25519 input but gas=23499 (1 below required) → OutOfGas
    #[test]
    fn test_gpg_verify_oog() {
        let input = hex_decode(ED25519_INPUT);
        let result = gpg_verify_run(&input, 23_499);
        assert_precompile_oog(&result);
    }

    /// Ported from: `TestPrecompiledGPGVerify_LongInput` (contracts_test.go:609)
    /// 9504-byte input (RSA, large key), expected=0x01 (valid).
    ///
    /// This fixture is signed by a signing **subkey**, not the primary key. The
    /// original tea-geth vector declared the *primary* key ID and still accepted
    /// it, but that is exactly the loose behavior TEAO1-144 closes: the precompile
    /// now requires the claimed key ID to name the key that actually signed. So we
    /// declare the truthful issuer (the signing subkey's ID) and assert success —
    /// proving a correctly-attributed subkey signature still verifies. (The
    /// rejection of the primary-ID claim is covered by
    /// `test_gpg_verify_subkey_signed_cannot_claim_primary_id`.)
    #[test]
    fn test_gpg_verify_long_input() {
        let input = hex_decode(LONG_INPUT);
        assert_eq!(input.len(), 9504);
        let decoded = decode_input(&input).expect("decode ok");
        let pub_key =
            SignedPublicKey::from_bytes(Cursor::new(&decoded.public_key)).expect("valid key");
        let sig =
            DetachedSignature::from_bytes(Cursor::new(&decoded.signature)).expect("valid sig");

        // Identify the subkey that actually produced the signature (the issuer).
        let signer_id = pub_key
            .public_subkeys
            .iter()
            .find(|sk| sig.verify(sk, &decoded.message).is_ok())
            .map(|sk| fingerprint_to_key_id(&sk.fingerprint()))
            .expect("a signing subkey verifies the long-input signature");

        let truthful =
            encode_gpg_verify_input(&decoded.message, &signer_id, &decoded.public_key, &decoded.signature);
        let gas = required_gas(&truthful);
        let result = gpg_verify_run(&truthful, gas);
        assert_precompile_ok(&result, gas, SUCCESS_HEX);
    }

    /// TEAO1-144 regression: the long-input fixture is signed by a subkey. A
    /// caller must not be able to claim the **primary** key's ID (a sibling of
    /// the actual signer in the same certificate) for that signature. The
    /// original fixture bytes declare exactly the primary ID, so they are a real
    /// vector for this attack and must now return `bytes32(0)`.
    #[test]
    fn test_gpg_verify_subkey_signed_cannot_claim_primary_id() {
        let input = hex_decode(LONG_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        let pub_key =
            SignedPublicKey::from_bytes(Cursor::new(&decoded.public_key)).expect("valid key");
        let primary_id = fingerprint_to_key_id(&pub_key.fingerprint());
        assert_eq!(decoded.key_id, primary_id, "fixture declares the primary key ID");

        let gas = required_gas(&input);
        let result = gpg_verify_run(&input, gas);
        let output = result.as_ref().expect("Ok result");
        assert!(
            output.bytes.iter().all(|&b| b == 0),
            "a subkey-signed signature must not verify under the primary key ID"
        );
    }

    /// Ported from: `TestPrecompiledGPGVerify_LongInputOOG` (contracts_test.go:619)
    /// Same long input but gas=123339 (1 below required) → OutOfGas
    #[test]
    fn test_gpg_verify_long_input_oog() {
        let input = hex_decode(LONG_INPUT);
        let result = gpg_verify_run(&input, 123_339);
        assert_precompile_oog(&result);
    }

    // === Additional tests from PR #5 review feedback ===

    // --- Gas calculation edge cases ---

    /// Gas for empty input should equal base gas (23,500).
    #[test]
    fn test_gas_zero_length_input() {
        assert_eq!(required_gas(&[]), GPG_VERIFY_BASE_GAS);
    }

    /// Gas across the kink boundary: kink-1 and kink both equal base gas;
    /// kink+1 (first byte in per-byte tier) equals base gas + GPG_VERIFY_GAS_PER_BYTE.
    #[test]
    fn test_gas_kink_boundary() {
        assert_eq!(required_gas(&vec![0u8; GPG_VERIFY_INPUT_LENGTH_KINK - 1]), GPG_VERIFY_BASE_GAS);
        assert_eq!(required_gas(&vec![0u8; GPG_VERIFY_INPUT_LENGTH_KINK]), GPG_VERIFY_BASE_GAS);
        assert_eq!(
            required_gas(&vec![0u8; GPG_VERIFY_INPUT_LENGTH_KINK + 1]),
            GPG_VERIFY_BASE_GAS + GPG_VERIFY_GAS_PER_BYTE,
        );
    }

    // --- Error & edge case tests ---

    /// F-1 regression: a crafted ABI offset must decode-error cleanly, never
    /// panic. Pre-hardening, `pub_key_offset = u64::MAX` wrapped past the bounds
    /// check and `&input[offset..offset + 32]` panicked (`start > end`) — a
    /// consensus halt inside the precompile.
    #[test]
    fn test_gpg_verify_crafted_offset_no_panic() {
        let mut input = vec![0u8; 128];
        // pub_key_offset slot [64..96]; low 8 bytes = u64::MAX → usize::MAX.
        input[88..96].copy_from_slice(&u64::MAX.to_be_bytes());
        let result = gpg_verify_run(&input, required_gas(&input));
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "crafted offset must decode-error, got: {result:?}"
        );
    }

    /// F-1 regression: an offset with any non-zero byte in its upper 24 bytes is
    /// beyond any real input length and must be rejected at decode.
    #[test]
    fn test_gpg_verify_offset_upper_bytes_rejected() {
        let mut input = vec![0u8; 128];
        input[64] = 0x01; // first byte of pub_key_offset slot → non-zero upper-24
        let result = gpg_verify_run(&input, required_gas(&input));
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "upper-byte offset must be rejected, got: {result:?}"
        );
    }

    /// Empty input should return decode error, not panic.
    #[test]
    fn test_gpg_verify_empty_input() {
        let result = gpg_verify_run(&[], 23_500);
        assert!(
            matches!(
                result,
                PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))
            ),
            "expected decode error for empty input, got: {result:?}"
        );
    }

    /// Input shorter than 128 bytes (minimum ABI header) should return decode error.
    #[test]
    fn test_gpg_verify_truncated_input() {
        let input = vec![0u8; 127];
        let result = gpg_verify_run(&input, 23_500);
        assert!(
            matches!(
                result,
                PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))
            ),
            "expected decode error for truncated input, got: {result:?}"
        );
    }

    /// Valid ABI encoding but garbage bytes for the public key.
    #[test]
    fn test_gpg_verify_corrupt_public_key() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        // Re-encode with garbage public key bytes
        let garbage_key = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let corrupt_input =
            encode_gpg_verify_input(&decoded.message, &decoded.key_id, &garbage_key, &decoded.signature);

        let result = gpg_verify_run(&corrupt_input, 23_500);
        assert!(
            matches!(
                result,
                PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))
            ),
            "expected 'invalid public key' error, got: {result:?}"
        );
    }

    /// Valid key + valid message but garbage signature bytes.
    #[test]
    fn test_gpg_verify_corrupt_signature() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        // Re-encode with garbage signature
        let garbage_sig = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let corrupt_input =
            encode_gpg_verify_input(&decoded.message, &decoded.key_id, &decoded.public_key, &garbage_sig);

        let result = gpg_verify_run(&corrupt_input, 23_500);
        assert!(
            matches!(
                result,
                PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))
            ),
            "expected 'invalid signature' error, got: {result:?}"
        );
    }

    /// Valid key + valid sig but different message hash → bytes32(0).
    /// Direct unit test (complements the EVM integration test).
    #[test]
    fn test_gpg_verify_wrong_message() {
        let mut input = hex_decode(ED25519_INPUT);
        // Corrupt the first byte of the message hash
        input[0] ^= 0xFF;
        let result = gpg_verify_run(&input, 23_500);
        let output = result.as_ref().expect("expected Ok result");
        assert_eq!(output.gas_used, 23_500);
        assert!(output.bytes.iter().all(|&b| b == 0), "should return bytes32(0) for wrong message");
    }

    /// Gas = 0 should return OutOfGas.
    #[test]
    fn test_gpg_verify_zero_gas() {
        let input = hex_decode(ED25519_INPUT);
        let result = gpg_verify_run(&input, 0);
        assert_precompile_oog(&result);
    }

    /// Key ID that doesn't match primary key or any subkey should error.
    #[test]
    fn test_gpg_verify_wrong_key_id() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        // Use a completely wrong key ID
        let wrong_key_id: [u8; 8] = [0xFF; 8];
        let bad_input =
            encode_gpg_verify_input(&decoded.message, &wrong_key_id, &decoded.public_key, &decoded.signature);

        let result = gpg_verify_run(&bad_input, 23_500);
        assert!(
            matches!(
                result,
                PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))
            ),
            "expected 'key id do not match' error, got: {result:?}"
        );
    }

    // --- Subkey handling tests ---

    /// Verify that we can extract subkey IDs from existing test keys and that
    /// subkey matching logic works correctly.
    #[test]
    fn test_gpg_verify_subkey_id_matching() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        // Parse the public key
        let pub_key =
            SignedPublicKey::from_bytes(Cursor::new(&decoded.public_key)).expect("valid key");

        // Get the primary key ID
        let primary_id = fingerprint_to_key_id(&pub_key.fingerprint());
        assert_eq!(primary_id, decoded.key_id, "ed25519 test vector uses primary key ID");

        // If the key has subkeys, verify they DON'T match the primary key ID
        for sk in &pub_key.public_subkeys {
            let sk_id = fingerprint_to_key_id(&sk.fingerprint());
            assert_ne!(sk_id, primary_id, "subkey ID should differ from primary");
        }
    }

    /// If the key has subkeys, using a subkey ID should pass the key ID check.
    #[test]
    fn test_gpg_verify_with_subkey_id_passes_id_check() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        let pub_key =
            SignedPublicKey::from_bytes(Cursor::new(&decoded.public_key)).expect("valid key");

        if pub_key.public_subkeys.is_empty() {
            // Skip if no subkeys — the test is only meaningful with subkeys
            return;
        }

        // Use the first subkey's ID
        let sk_id = fingerprint_to_key_id(&pub_key.public_subkeys[0].fingerprint());

        // Re-encode with the subkey ID. The key ID check should pass because
        // we check both primary and subkeys. The signature verification may fail
        // (since the sig was made by the primary key, not the subkey), so we just
        // verify we get past the key ID check (no "key id do not match" error).
        let subkey_input =
            encode_gpg_verify_input(&decoded.message, &sk_id, &decoded.public_key, &decoded.signature);

        let result = gpg_verify_run(&subkey_input, 23_500);
        // Should NOT be a "key id do not match" error
        match &result {
            PrecompileResult::Err(revm::precompile::PrecompileError::Other(msg)) => {
                assert!(
                    !msg.contains("key id do not match"),
                    "subkey ID should pass the key ID check"
                );
            }
            _ => {
                // Ok or other error — both acceptable as long as it's not key ID mismatch
            }
        }
    }

    /// RSA key subkey check — verify RSA test vector also handles subkeys correctly.
    #[test]
    fn test_gpg_verify_rsa_subkey_id_matching() {
        let input = hex_decode(RSA_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        let pub_key =
            SignedPublicKey::from_bytes(Cursor::new(&decoded.public_key)).expect("valid key");

        let primary_id = fingerprint_to_key_id(&pub_key.fingerprint());
        assert_eq!(primary_id, decoded.key_id, "RSA test vector uses primary key ID");

        // Verify subkey IDs are distinct from primary
        for sk in &pub_key.public_subkeys {
            let sk_id = fingerprint_to_key_id(&sk.fingerprint());
            assert_ne!(sk_id, primary_id, "RSA subkey ID should differ from primary");
        }
    }

    // --- Security-fix tests (Cantina §0x0696) ---

    /// Generate a fresh, deterministic ed25519 key, optionally with a signing
    /// subkey. Used to build negative test vectors in-process (no gpg CLI).
    fn gen_ed25519(seed: u8, signing_subkey: bool) -> pgp::composed::SignedSecretKey {
        use pgp::composed::{KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
        use rand_08::SeedableRng;
        let mut rng = rand_08::rngs::StdRng::from_seed([seed; 32]);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Test <test@example.com>".into());
        if signing_subkey {
            params.subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Ed25519)
                    .can_sign(true)
                    .build()
                    .expect("subkey params"),
            );
        }
        params.build().expect("key params").generate(&mut rng).expect("generate key")
    }

    /// TEAO1-172: appending a second OpenPGP object to the publicKey blob must be
    /// rejected (the single-object guard), even though the first object is valid.
    #[test]
    fn test_gpg_verify_rejects_concatenated_public_key() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        // Baseline: the single, unmodified object verifies.
        let base = encode_gpg_verify_input(
            &decoded.message,
            &decoded.key_id,
            &decoded.public_key,
            &decoded.signature,
        );
        let base_res = gpg_verify_run(&base, required_gas(&base));
        assert_precompile_ok(&base_res, required_gas(&base), SUCCESS_HEX);

        // Two concatenated public-key objects must be rejected.
        let doubled: Vec<u8> = [decoded.public_key.clone(), decoded.public_key.clone()].concat();
        let attack =
            encode_gpg_verify_input(&decoded.message, &decoded.key_id, &doubled, &decoded.signature);
        let result = gpg_verify_run(&attack, required_gas(&attack));
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "concatenated public-key objects must be rejected, got: {result:?}"
        );
    }

    /// TEAO1-172: appending a second object to the signature blob must be rejected.
    #[test]
    fn test_gpg_verify_rejects_concatenated_signature() {
        let input = hex_decode(ED25519_INPUT);
        let decoded = decode_input(&input).expect("decode ok");

        let doubled: Vec<u8> = [decoded.signature.clone(), decoded.signature.clone()].concat();
        let attack =
            encode_gpg_verify_input(&decoded.message, &decoded.key_id, &decoded.public_key, &doubled);
        let result = gpg_verify_run(&attack, required_gas(&attack));
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "concatenated signature objects must be rejected, got: {result:?}"
        );
    }

    /// TEAO1-160: the signing-eligibility filter must discriminate between
    /// signing and non-signing subkeys. The long-input certificate contains
    /// both, so `subkey_can_sign` must return both true and false across it —
    /// proving the filter has teeth on a real certificate.
    #[test]
    fn test_eligibility_filters_non_signing_subkeys() {
        let input = hex_decode(LONG_INPUT);
        let decoded = decode_input(&input).expect("decode ok");
        let pub_key =
            SignedPublicKey::from_bytes(Cursor::new(&decoded.public_key)).expect("valid key");
        assert!(
            pub_key.public_subkeys.iter().any(|sk| !subkey_can_sign(sk)),
            "fixture should contain a non-signing subkey (filtered out)"
        );
        assert!(
            pub_key.public_subkeys.iter().any(subkey_can_sign),
            "fixture should contain a signing subkey (retained)"
        );
    }

    /// Build a valid **non-signing** `SubkeyBinding` self-signature for `ssk`'s
    /// first subkey, stamped at `created_secs`. The empty `KeyFlags` clears the
    /// sign capability, so no embedded primary-key-binding back-signature is
    /// required and `verify_bindings` still accepts it.
    fn non_signing_binding_at(
        ssk: &pgp::composed::SignedSecretKey,
        created_secs: u32,
    ) -> Signature {
        use pgp::packet::{KeyFlags, SignatureConfig, Subpacket, SubpacketData};
        use pgp::types::{KeyVersion, Password, Timestamp};
        use rand_08::SeedableRng;

        let mut rng = rand_08::rngs::StdRng::from_seed([0x55; 32]);
        let mut config =
            SignatureConfig::from_key(&mut rng, &ssk.primary_key, SignatureType::SubkeyBinding)
                .expect("binding config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                created_secs,
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::KeyFlags(KeyFlags::default())).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(ssk.primary_key.fingerprint()))
                .unwrap(),
        ];
        if ssk.primary_key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                ssk.primary_key.legacy_key_id(),
            ))
            .unwrap()];
        }
        config
            .sign_subkey_binding(
                &ssk.primary_key,
                ssk.primary_key.public_key(),
                &Password::empty(),
                ssk.secret_subkeys[0].key.public_key(),
            )
            .expect("sign non-signing binding")
    }

    /// TEAO1-193: subkey eligibility must honor the **effective** (latest)
    /// binding, not union `sign()` across every retained binding. A subkey that
    /// carries a stale signing-capable binding alongside a later valid
    /// non-signing re-binding must be ineligible; only when the signing binding
    /// is itself the latest may the subkey verify.
    #[test]
    fn test_subkey_effective_binding_overrides_stale_signing() {
        use pgp::crypto::hash::HashAlgorithm;
        use pgp::ser::Serialize;
        use pgp::types::Password;
        use rand_08::SeedableRng;

        // A key whose only subkey carries a genuine signing binding (with the
        // embedded back-signature that `verify_bindings` requires).
        let ssk = gen_ed25519(7, true);
        let full_pub = ssk.to_public_key();
        assert_eq!(full_pub.public_subkeys.len(), 1, "expected one signing subkey");
        let subkey = full_pub.public_subkeys[0].clone();
        let signing_binding = subkey.signatures[0].clone();
        assert!(signing_binding.key_flags().sign(), "control: original binding advertises signing");
        let signing_created = signing_binding.created().expect("binding has a creation time");

        // The same subkey material signs the message we will verify.
        let message = [0x42u8; 32];
        let mut rng = rand_08::rngs::StdRng::from_seed([0x11; 32]);
        let sig = DetachedSignature::sign_binary_data(
            &mut rng,
            &ssk.secret_subkeys[0].key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &message[..],
        )
        .expect("subkey signs message");
        let subkey_id = fingerprint_to_key_id(&subkey.fingerprint());
        let sig_bytes = sig.to_bytes().expect("sig bytes");

        // Run the precompile against a certificate carrying exactly `sub`.
        let run = |sub: SignedPublicSubKey| -> Vec<u8> {
            let pubkey = SignedPublicKey::new(
                full_pub.primary_key.clone(),
                full_pub.details.clone(),
                vec![sub],
            );
            let input = encode_gpg_verify_input(
                &message,
                &subkey_id,
                &pubkey.to_bytes().expect("pub bytes"),
                &sig_bytes,
            );
            let gas = required_gas(&input);
            gpg_verify_run(&input, gas).as_ref().expect("Ok result").bytes.to_vec()
        };

        // Effective binding is the LATER non-signing one — ineligible, even
        // though a valid older signing binding is retained.
        let later_non_signing = non_signing_binding_at(&ssk, signing_created.as_secs() + 1);
        assert!(!later_non_signing.key_flags().sign(), "control: later binding clears the sign flag");
        let mixed = SignedPublicSubKey::new(
            subkey.key.clone(),
            vec![signing_binding.clone(), later_non_signing.clone()],
        );
        assert!(
            mixed.verify_bindings(&full_pub.primary_key).is_ok(),
            "control: both retained bindings are individually valid",
        );
        assert!(
            run(mixed).iter().all(|&b| b == 0),
            "a stale signing binding must not re-enable a re-bound non-signing subkey (TEAO1-193)",
        );

        // Only the later non-signing binding retained — also ineligible.
        let current_only =
            SignedPublicSubKey::new(subkey.key.clone(), vec![later_non_signing.clone()]);
        assert!(
            run(current_only).iter().all(|&b| b == 0),
            "the effective non-signing binding is ineligible",
        );

        // Positive control: when the signing binding is the EFFECTIVE (latest)
        // one, the subkey verifies — the fix honors recency, it is not a blanket
        // rejection of multi-binding subkeys.
        let earlier_non_signing = non_signing_binding_at(&ssk, signing_created.as_secs() - 1);
        let signing_latest = SignedPublicSubKey::new(
            subkey.key.clone(),
            vec![earlier_non_signing, signing_binding.clone()],
        );
        assert_eq!(
            alloy_primitives::hex::encode(run(signing_latest)),
            SUCCESS_HEX,
            "a subkey whose effective (latest) binding advertises signing must verify",
        );
    }

    /// TEAO1-166 / TEAO1-148: only Binary-class signatures bind the exact 32-byte
    /// message. A Text-class detached signature over the same key/message must be
    /// rejected by the binary-only gate (the same gate rejects Timestamp and
    /// Standalone, which bind no message data).
    #[test]
    fn test_gpg_verify_rejects_text_signature() {
        use pgp::crypto::hash::HashAlgorithm;
        use pgp::ser::Serialize;
        use pgp::types::Password;
        use rand_08::SeedableRng;

        let ssk = gen_ed25519(9, false);
        let spk = ssk.to_public_key();
        let message = [0x42u8; 32];
        let mut rng = rand_08::rngs::StdRng::from_seed([42u8; 32]);
        let text_sig = DetachedSignature::sign_text_data(
            &mut rng,
            &*ssk,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &message[..],
        )
        .expect("text sign");
        assert_ne!(
            text_sig.signature.typ(),
            Some(SignatureType::Binary),
            "control: this is a non-Binary signature"
        );

        let key_id = fingerprint_to_key_id(&spk.fingerprint());
        let input = encode_gpg_verify_input(
            &message,
            &key_id,
            &spk.to_bytes().expect("pub bytes"),
            &text_sig.to_bytes().expect("sig bytes"),
        );
        let gas = required_gas(&input);
        let output = gpg_verify_run(&input, gas).as_ref().expect("Ok").bytes.clone();
        assert!(
            output.iter().all(|&b| b == 0),
            "text-mode signature must be rejected by the binary-only gate"
        );
    }

    /// Control for the binary gate: a freshly generated Binary detached signature
    /// over the exact 32-byte message, declared under the truthful primary key
    /// ID, must verify. Guards against the gate over-rejecting valid signatures.
    #[test]
    fn test_gpg_verify_binary_signature_verifies() {
        use pgp::crypto::hash::HashAlgorithm;
        use pgp::ser::Serialize;
        use pgp::types::Password;
        use rand_08::SeedableRng;

        let ssk = gen_ed25519(11, false);
        let spk = ssk.to_public_key();
        let message = [0x37u8; 32];
        let mut rng = rand_08::rngs::StdRng::from_seed([12u8; 32]);
        let sig = DetachedSignature::sign_binary_data(
            &mut rng,
            &*ssk,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &message[..],
        )
        .expect("binary sign");

        let key_id = fingerprint_to_key_id(&spk.fingerprint());
        let input = encode_gpg_verify_input(
            &message,
            &key_id,
            &spk.to_bytes().expect("pub bytes"),
            &sig.to_bytes().expect("sig bytes"),
        );
        let gas = required_gas(&input);
        let result = gpg_verify_run(&input, gas);
        assert_precompile_ok(&result, gas, SUCCESS_HEX);
    }

    /// TEAO1-148 (explicit): the binary-only gate rejects Timestamp and
    /// Standalone signature classes (which bind no message data) and Text
    /// (TEAO1-166), accepting only Binary. Deterministic coverage of the gate
    /// predicate across the classes the high-level signing API can't forge.
    #[test]
    fn only_binary_sig_type_accepted() {
        assert!(is_accepted_sig_type(Some(SignatureType::Binary)));
        for typ in [SignatureType::Text, SignatureType::Standalone, SignatureType::Timestamp] {
            assert!(!is_accepted_sig_type(Some(typ)), "{typ:?} must be rejected");
        }
        assert!(!is_accepted_sig_type(None));
    }

    /// TEAO1-141: a subkey grafted from a different certificate has no valid
    /// binding signature to the victim's primary key, so it must fail the
    /// binding check and never be treated as an eligible signing authority.
    #[test]
    fn test_grafted_subkey_fails_binding_check() {
        let victim = gen_ed25519(1, false); // primary only
        let attacker = gen_ed25519(2, true); // primary + signing subkey
        let victim_pub = victim.to_public_key();
        let attacker_pub = attacker.to_public_key();
        assert!(!attacker_pub.public_subkeys.is_empty(), "attacker has a signing subkey");

        // Graft the attacker's signing subkey onto the victim's primary identity.
        let grafted = SignedPublicKey {
            primary_key: victim_pub.primary_key.clone(),
            details: victim_pub.details.clone(),
            public_subkeys: attacker_pub.public_subkeys.clone(),
        };
        for sk in &grafted.public_subkeys {
            assert!(
                sk.verify_bindings(&grafted.primary_key).is_err(),
                "grafted subkey must fail binding to the victim primary (TEAO1-141)"
            );
        }
        // Control: in its own certificate the same subkey binds correctly.
        for sk in &attacker_pub.public_subkeys {
            assert!(
                sk.verify_bindings(&attacker_pub.primary_key).is_ok(),
                "legitimately-bound subkey must pass its own binding check"
            );
        }
    }

    // --- Helper: ABI-encode GPG verify input ---

    /// Encodes a GPG verify input in the same ABI format the precompile expects.
    fn encode_gpg_verify_input(
        message: &[u8; 32],
        key_id: &[u8; 8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        // [0..32] bytes32 message
        buf.extend_from_slice(message);

        // [32..64] bytes8 keyId (left-aligned, right-padded to 32 bytes)
        buf.extend_from_slice(key_id);
        buf.extend_from_slice(&[0u8; 24]);

        // [64..96] offset to publicKey = 128 (4 * 32 bytes of header)
        buf.extend_from_slice(&u256_bytes(128));

        // [96..128] offset to signature (128 + 32 + padded_len(publicKey))
        let pub_key_padded_len = public_key.len().div_ceil(32) * 32;
        let sig_offset = 128 + 32 + pub_key_padded_len;
        buf.extend_from_slice(&u256_bytes(sig_offset));

        // publicKey: length + data (padded to 32 bytes)
        buf.extend_from_slice(&u256_bytes(public_key.len()));
        buf.extend_from_slice(public_key);
        let pub_key_padding = pub_key_padded_len - public_key.len();
        buf.extend_from_slice(&vec![0u8; pub_key_padding]);

        // signature: length + data (padded to 32 bytes)
        buf.extend_from_slice(&u256_bytes(signature.len()));
        buf.extend_from_slice(signature);
        let sig_padded_len = signature.len().div_ceil(32) * 32;
        let sig_padding = sig_padded_len - signature.len();
        buf.extend_from_slice(&vec![0u8; sig_padding]);

        buf
    }

    /// Encode a usize as a big-endian 32-byte uint256.
    fn u256_bytes(val: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&(val as u64).to_be_bytes());
        out
    }
}
