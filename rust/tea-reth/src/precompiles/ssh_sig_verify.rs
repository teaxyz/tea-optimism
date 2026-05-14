//! SSHSIG signature verification precompile.
//!
//! Verifies OpenSSH SSHSIG (PROTOCOL.sshsig) signatures on-chain — the format
//! produced by `ssh-keygen -Y sign` and used by `git tag -s` / `git commit -S`
//! when the user's signing key is an SSH key. Registered at address `0x0698`.
//!
//! # Why a separate precompile from `0x0697`
//!
//! `0x0697` verifies the SSH cryptographic primitive (ed25519 / rsa-sha2-N)
//! against a raw 32-byte message slot. SSHSIG instead signs an envelope built
//! over the user's payload:
//!
//! ```text
//! "SSHSIG" || string(namespace) || string(reserved) || string(hash_algorithm) || string(H(payload))
//! ```
//!
//! For SHA-512 (the default — used by both `ssh-keygen -Y sign` and `git tag
//! -s`), `H(payload)` is 64 bytes and the envelope is ~96 bytes total. Neither
//! fits in `0x0697`'s `bytes32 message` slot. This precompile takes the raw
//! payload, computes SHA-512 internally, reconstructs the envelope per the
//! SSHSIG spec, and runs the same SSH primitive against the envelope.
//!
//! # Input format
//!
//! `abi.encode(bytes payload, bytes namespace, bytes publicKey, bytes signature)`
//!
//! - `payload`: raw bytes that `ssh-keygen -Y sign` consumed (e.g., git tag
//!   content). Length capped at [`MAX_PAYLOAD_BYTES`].
//! - `namespace`: SSHSIG namespace string (e.g., `b"git"` for git-signed tags
//!   and commits, `b"file"` for ad-hoc `ssh-keygen -Y sign` invocations).
//!   Length capped at [`MAX_NAMESPACE_BYTES`].
//! - `publicKey`: SSH wire format (RFC 4253) public key bytes.
//! - `signature`: SSH wire format signature (`string algorithm, string sig_blob`).
//!
//! # Hardcoded SSHSIG fields
//!
//! - `hash_algorithm = "sha512"` — matches `ssh-keygen -Y sign` default and git.
//!   Callers wanting `sha256` must use a future variant; SHA-512 is locked in
//!   here to keep the ABI tight and the audit surface small.
//! - `reserved = ""` — per the SSHSIG spec, always empty in version 1.
//!
//! # Output
//!
//! Returns `bytes32(1)` for valid signatures, `bytes32(0)` for invalid.
//!
//! # Supported algorithms
//!
//! - `ssh-ed25519`: Ed25519 signatures (64-byte sig, 32-byte pubkey).
//! - `rsa-sha2-256`: RSA with SHA-256 (PKCS#1 v1.5), max 4096-bit key.
//! - `rsa-sha2-512`: RSA with SHA-512 (PKCS#1 v1.5), max 4096-bit key.
//!
//! Deprecated `ssh-rsa` (SHA-1) signatures are rejected.

use alloy_primitives::{Address, Bytes, address};
use revm::precompile::{Precompile, PrecompileId, PrecompileOutput, PrecompileResult};

/// SSHSIG verify precompile address.
pub const SSHSIG_VERIFY_ADDRESS: Address =
    address!("0x0000000000000000000000000000000000000698");

/// Base gas cost for SSHSIG verification.
///
/// Slightly above `0x0697`'s 23,500 to cover the additional SHA-512 over the
/// payload plus the ~100-byte envelope reconstruction.
pub const SSHSIG_VERIFY_BASE_GAS: u64 = 25_000;

/// Per-byte gas cost above the kink point.
///
/// Mirrors `0x0697`. Covers the linear cost of SHA-512 (payload) and the
/// inner SSH primitive's own hash pass over the envelope.
pub const SSHSIG_VERIFY_GAS_PER_BYTE: u64 = 16;

/// Input length kink point — below this, only base gas is charged.
pub const SSHSIG_VERIFY_INPUT_LENGTH_KINK: usize = 3264;

/// Maximum payload size in bytes (16 KiB).
///
/// Generous for git tags and commits, which top out in the low KB range.
/// Bump if larger SSHSIG payloads ever need to be verified on-chain.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

/// Maximum namespace size in bytes.
///
/// SSHSIG namespaces are short identifiers (`"git"`, `"file"`, etc.). 256
/// bytes is far above any reasonable use.
pub const MAX_NAMESPACE_BYTES: usize = 256;

/// Maximum SSH wire-format public key blob size in bytes.
///
/// Covers an `ssh-rsa` 4096-bit key (~540 bytes including all wire-format
/// framing) with comfortable headroom.
pub const MAX_PUBKEY_BYTES: usize = 1024;

/// Maximum SSH wire-format signature blob size in bytes.
///
/// Covers an `ssh-rsa` 4096-bit signature (~530 bytes including framing).
pub const MAX_SIGNATURE_BYTES: usize = 1024;

/// Maximum RSA modulus size in bytes (4096-bit = 512 bytes).
/// Bump this and release a new tea-reth if 8192-bit keys are ever needed.
pub const MAX_RSA_MODULUS_BYTES: usize = 512;

/// Hardcoded SSHSIG hash algorithm field. SHA-512 matches `ssh-keygen -Y sign`
/// default and what git uses for SSH-signed tags/commits.
const SSHSIG_HASH_ALGORITHM: &[u8] = b"sha512";

/// SSHSIG magic preamble per PROTOCOL.sshsig.
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// Returns the SSHSIG verify precompile for registration.
pub fn precompile() -> Precompile {
    Precompile::new(
        PrecompileId::custom("sshsig_verify"),
        SSHSIG_VERIFY_ADDRESS,
        sshsig_verify_run,
    )
}

/// Calculates the gas required for SSHSIG verification.
pub fn required_gas(input: &[u8]) -> u64 {
    if input.len() <= SSHSIG_VERIFY_INPUT_LENGTH_KINK {
        return SSHSIG_VERIFY_BASE_GAS;
    }
    let additional_bytes = input.len() - SSHSIG_VERIFY_INPUT_LENGTH_KINK;
    SSHSIG_VERIFY_BASE_GAS + SSHSIG_VERIFY_GAS_PER_BYTE * additional_bytes as u64
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

/// Read a length-prefixed string from SSH wire format.
///
/// SSH wire format uses a `uint32` big-endian length prefix followed by raw
/// bytes. Returns the string data and advances the offset.
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

/// Append a length-prefixed SSH wire-format string to `out`.
fn write_ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

// ─────────────────────────────────────────── ABI decoding

/// Decoded SSHSIG verify precompile input.
struct SshSigVerifyInput {
    payload: Vec<u8>,
    namespace: Vec<u8>,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

/// ABI-decode the SSHSIG verify input.
///
/// Expected layout:
/// ```text
/// [0..32]   offset to payload   (dynamic)
/// [32..64]  offset to namespace (dynamic)
/// [64..96]  offset to publicKey (dynamic)
/// [96..128] offset to signature (dynamic)
/// ```
fn decode_input(input: &[u8]) -> Result<SshSigVerifyInput, &'static str> {
    if input.len() < 128 {
        return Err("input too short");
    }

    let payload_offset = u256_to_usize(&input[0..32])?;
    let namespace_offset = u256_to_usize(&input[32..64])?;
    let pub_key_offset = u256_to_usize(&input[64..96])?;
    let sig_offset = u256_to_usize(&input[96..128])?;

    let payload = read_dynamic_bytes(input, payload_offset, MAX_PAYLOAD_BYTES)?;
    let namespace = read_dynamic_bytes(input, namespace_offset, MAX_NAMESPACE_BYTES)?;
    let public_key = read_dynamic_bytes(input, pub_key_offset, MAX_PUBKEY_BYTES)?;
    let signature = read_dynamic_bytes(input, sig_offset, MAX_SIGNATURE_BYTES)?;

    Ok(SshSigVerifyInput { payload, namespace, public_key, signature })
}

/// Read a uint256 as usize (for ABI offsets).
fn u256_to_usize(data: &[u8]) -> Result<usize, &'static str> {
    if data.len() != 32 {
        return Err("invalid uint256 length");
    }
    // Reject offsets that don't fit in usize — anything in the upper 24 bytes
    // is definitionally beyond our input length.
    if data[0..24].iter().any(|&b| b != 0) {
        return Err("offset too large");
    }
    let val = u64::from_be_bytes(data[24..32].try_into().map_err(|_| "conversion error")?);
    Ok(val as usize)
}

/// Read ABI-encoded dynamic bytes from a given offset, enforcing a max length.
///
/// Uses `checked_add` throughout so adversarial `offset` / `length` values
/// near `usize::MAX` can never wrap around into a valid slice index.
fn read_dynamic_bytes(input: &[u8], offset: usize, max_len: usize) -> Result<Vec<u8>, &'static str> {
    let header_end = offset.checked_add(32).ok_or("offset overflow")?;
    if header_end > input.len() {
        return Err("offset out of bounds");
    }
    let length = u256_to_usize(&input[offset..header_end])?;
    if length > max_len {
        return Err("dynamic field exceeds max length");
    }
    let data_end = header_end.checked_add(length).ok_or("length overflow")?;
    if data_end > input.len() {
        return Err("data out of bounds");
    }
    Ok(input[header_end..data_end].to_vec())
}

// ─────────────────────────────────────────── Envelope reconstruction

/// Build the SSHSIG signed-data envelope per PROTOCOL.sshsig:
///
/// ```text
/// "SSHSIG" || string(namespace) || string("") || string("sha512") || string(SHA-512(payload))
/// ```
fn build_sshsig_envelope(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let payload_hash = sha2::Sha512::digest(payload);

    // 6 (magic) + 4+ns + 4 (empty reserved) + 4+6 ("sha512") + 4+64 (hash)
    let mut envelope = Vec::with_capacity(SSHSIG_MAGIC.len() + namespace.len() + 86);
    envelope.extend_from_slice(SSHSIG_MAGIC);
    write_ssh_string(&mut envelope, namespace);
    write_ssh_string(&mut envelope, b"");
    write_ssh_string(&mut envelope, SSHSIG_HASH_ALGORITHM);
    write_ssh_string(&mut envelope, payload_hash.as_slice());
    envelope
}

// ─────────────────────────────────────────── Verification dispatch

/// SSHSIG verify precompile entry point.
fn sshsig_verify_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_cost = required_gas(input);
    if gas_limit < gas_cost {
        return PrecompileResult::Err(revm::precompile::PrecompileError::OutOfGas);
    }

    let SshSigVerifyInput { payload, namespace, public_key, signature } =
        match decode_input(input) {
            Ok(decoded) => decoded,
            Err(_) => {
                return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                    "failed to decode sshsig verify input".into(),
                ));
            }
        };

    // Build the SSHSIG envelope the user's `ssh-keygen -Y sign` actually
    // signed. This is the message the SSH primitive verifies against.
    let envelope = build_sshsig_envelope(&payload, &namespace);

    // Parse SSH public key wire format to get key type.
    let mut key_offset = 0usize;
    let key_type = match read_ssh_string(&public_key, &mut key_offset) {
        Ok(t) => t,
        Err(_) => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "invalid ssh public key".into(),
            ));
        }
    };

    // Parse SSH signature wire format to get algorithm and blob.
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

    // Dispatch verification based on key type.
    let verified = match key_type {
        b"ssh-ed25519" => verify_ed25519(&public_key, key_offset, &envelope, sig_algo, sig_blob),
        b"ssh-rsa" => verify_rsa(&public_key, key_offset, &envelope, sig_algo, sig_blob),
        _ => {
            return PrecompileResult::Err(revm::precompile::PrecompileError::Other(
                "unsupported ssh key type".into(),
            ));
        }
    };

    if verified {
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, success_result()))
    } else {
        // Invalid signature is not an error — return 0.
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, failure_result()))
    }
}

/// Verify an ed25519 SSHSIG signature against the reconstructed envelope.
fn verify_ed25519(
    pub_key_data: &[u8],
    offset: usize,
    envelope: &[u8],
    sig_algo: &[u8],
    sig_blob: &[u8],
) -> bool {
    // Verify algorithm consistency: key type and sig algo must both be ssh-ed25519.
    if sig_algo != b"ssh-ed25519" {
        return false;
    }

    // Extract 32-byte ed25519 public key from SSH wire format.
    let mut key_offset = offset;
    let key_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(k) if k.len() == 32 => k,
        _ => return false,
    };

    // ed25519 signature must be exactly 64 bytes.
    if sig_blob.len() != 64 {
        return false;
    }

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(
        key_bytes.try_into().unwrap_or(&[0u8; 32]),
    ) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let signature = ed25519_dalek::Signature::from_bytes(
        sig_blob.try_into().unwrap_or(&[0u8; 64]),
    );

    use ed25519_dalek::Verifier;
    verifying_key.verify(envelope, &signature).is_ok()
}

/// Verify an RSA SSHSIG signature (rsa-sha2-256 or rsa-sha2-512) against the
/// reconstructed envelope.
fn verify_rsa(
    pub_key_data: &[u8],
    offset: usize,
    envelope: &[u8],
    sig_algo: &[u8],
    sig_blob: &[u8],
) -> bool {
    // Parse RSA public key: mpint e, mpint n.
    let mut key_offset = offset;
    let e_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let n_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Reject RSA keys larger than 4096-bit. Bump MAX_RSA_MODULUS_BYTES and
    // release a new tea-reth binary if larger keys are ever needed.
    if n_bytes.len() > MAX_RSA_MODULUS_BYTES {
        return false;
    }

    let e = rsa::BigUint::from_bytes_be(e_bytes);
    let n = rsa::BigUint::from_bytes_be(n_bytes);
    let pub_key = match rsa::RsaPublicKey::new(n, e) {
        Ok(k) => k,
        Err(_) => return false,
    };

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
            verifying_key.verify(envelope, &sig).is_ok()
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
            verifying_key.verify(envelope, &sig).is_ok()
        }
        // Reject deprecated ssh-rsa (SHA-1) — insecure.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the SSHSIG verification precompile.
    //!
    //! Each round-trip test signs a payload at runtime with a deterministic
    //! key, wire-format encodes the result the same way `ssh-keygen -Y sign`
    //! does, and runs it through the precompile end-to-end. This proves the
    //! precompile accepts the exact byte shape OpenSSH produces.

    use super::*;
    use ed25519_dalek::Signer;

    const SUCCESS_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const FAILURE_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// Real `ssh-keygen -Y sign` output for an ed25519 key signing
    /// b"hello sshsig precompile" with namespace="file". Generated via
    /// real OpenSSH binary and parsed back to ABI-encoded precompile input.
    /// This proves the precompile accepts bytes OpenSSH actually produces —
    /// not just bytes our own helpers re-synthesize.
    const FIXTURE_ED25519: &str = include_str!("testdata_sshsig_verify_ed25519.hex");
    const FIXTURE_RSA: &str = include_str!("testdata_sshsig_verify_rsa.hex");

    fn hex_decode(s: &str) -> Vec<u8> {
        alloy_primitives::hex::decode(s.trim()).expect("valid hex")
    }

    fn assert_precompile_ok(result: &PrecompileResult, expected_output: &str) {
        let output = result.as_ref().expect("expected Ok result");
        assert_eq!(
            alloy_primitives::hex::encode(&output.bytes),
            expected_output,
            "unexpected precompile output"
        );
    }

    fn assert_precompile_err(result: &PrecompileResult) {
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::Other(_))),
            "expected decode error, got: {result:?}"
        );
    }

    fn assert_precompile_oog(result: &PrecompileResult) {
        assert!(
            matches!(result, PrecompileResult::Err(revm::precompile::PrecompileError::OutOfGas)),
            "expected OutOfGas, got: {result:?}"
        );
    }

    // ─────────────────────── Helpers: build wire-format inputs

    fn ssh_string(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    /// Build a wire-format ed25519 pubkey blob: `string("ssh-ed25519") + string(32-byte-key)`.
    fn build_ed25519_pubkey_blob(key_bytes: &[u8; 32]) -> Vec<u8> {
        [ssh_string(b"ssh-ed25519"), ssh_string(key_bytes)].concat()
    }

    /// Build a wire-format signature blob: `string(algorithm) + string(sig_bytes)`.
    fn build_signature_blob(algorithm: &[u8], sig_bytes: &[u8]) -> Vec<u8> {
        [ssh_string(algorithm), ssh_string(sig_bytes)].concat()
    }

    /// Encodes an mpint per RFC 4251 §5: prepends 0x00 if the high bit is set.
    fn ssh_mpint(value: &[u8]) -> Vec<u8> {
        let mut start = 0;
        while start < value.len().saturating_sub(1) && value[start] == 0 {
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

    fn build_rsa_pubkey_blob(pub_key: &rsa::RsaPublicKey) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        let mut out = Vec::new();
        out.extend_from_slice(&ssh_string(b"ssh-rsa"));
        out.extend_from_slice(&ssh_mpint(&pub_key.e().to_bytes_be()));
        out.extend_from_slice(&ssh_mpint(&pub_key.n().to_bytes_be()));
        out
    }

    /// ABI-encode `(bytes payload, bytes namespace, bytes pubkey, bytes signature)`.
    fn encode_input(
        payload: &[u8],
        namespace: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        let pad32 = |n: usize| (n + 31) / 32 * 32;
        let payload_off = 128;
        let namespace_off = payload_off + 32 + pad32(payload.len());
        let pubkey_off = namespace_off + 32 + pad32(namespace.len());
        let sig_off = pubkey_off + 32 + pad32(public_key.len());

        let mut buf = Vec::new();
        buf.extend_from_slice(&u256(payload_off));
        buf.extend_from_slice(&u256(namespace_off));
        buf.extend_from_slice(&u256(pubkey_off));
        buf.extend_from_slice(&u256(sig_off));
        push_dynamic_bytes(&mut buf, payload);
        push_dynamic_bytes(&mut buf, namespace);
        push_dynamic_bytes(&mut buf, public_key);
        push_dynamic_bytes(&mut buf, signature);
        buf
    }

    fn push_dynamic_bytes(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&u256(data.len()));
        buf.extend_from_slice(data);
        let pad = (32 - data.len() % 32) % 32;
        buf.extend_from_slice(&vec![0u8; pad]);
    }

    fn u256(val: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&(val as u64).to_be_bytes());
        out
    }

    // ─────────────────────── Helpers: sign a payload at runtime

    /// Deterministic ed25519 seed — RFC 8032 test vector 2 seed.
    const ED25519_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    /// Sign `payload` as `ssh-keygen -Y sign` would, with a fixed ed25519 key
    /// and the given namespace. Returns `(precompile_input, envelope_bytes)`.
    fn sign_sshsig_ed25519(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let verifying_key = signing_key.verifying_key();

        let envelope = build_sshsig_envelope(payload, namespace);
        let sig = signing_key.sign(&envelope);

        let pub_key_blob = build_ed25519_pubkey_blob(verifying_key.as_bytes());
        let sig_blob = build_signature_blob(b"ssh-ed25519", &sig.to_bytes());

        encode_input(payload, namespace, &pub_key_blob, &sig_blob)
    }

    fn sign_sshsig_rsa_sha256(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
        use rand_08::SeedableRng;
        use rsa::pkcs1v15::SigningKey;
        use sha2::Sha256;
        use signature::{SignatureEncoding, Signer};

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa-2048 keygen");
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let envelope = build_sshsig_envelope(payload, namespace);
        let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
        let sig = signing_key.sign(&envelope);

        let pub_key_blob = build_rsa_pubkey_blob(&public_key);
        let sig_blob = build_signature_blob(b"rsa-sha2-256", &sig.to_bytes());
        encode_input(payload, namespace, &pub_key_blob, &sig_blob)
    }

    fn sign_sshsig_rsa_sha512(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
        use rand_08::SeedableRng;
        use rsa::pkcs1v15::SigningKey;
        use sha2::Sha512;
        use signature::{SignatureEncoding, Signer};

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa-2048 keygen");
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let envelope = build_sshsig_envelope(payload, namespace);
        let signing_key: SigningKey<Sha512> = SigningKey::new(private_key);
        let sig = signing_key.sign(&envelope);

        let pub_key_blob = build_rsa_pubkey_blob(&public_key);
        let sig_blob = build_signature_blob(b"rsa-sha2-512", &sig.to_bytes());
        encode_input(payload, namespace, &pub_key_blob, &sig_blob)
    }

    fn run(input: &[u8]) -> PrecompileResult {
        let gas = required_gas(input);
        sshsig_verify_run(input, gas)
    }

    // ─────────────────────── Gas tests

    #[test]
    fn gas_below_kink_is_base() {
        assert_eq!(required_gas(&vec![0u8; 100]), SSHSIG_VERIFY_BASE_GAS);
        assert_eq!(required_gas(&[]), SSHSIG_VERIFY_BASE_GAS);
        assert_eq!(
            required_gas(&vec![0u8; SSHSIG_VERIFY_INPUT_LENGTH_KINK]),
            SSHSIG_VERIFY_BASE_GAS
        );
    }

    #[test]
    fn gas_above_kink_charges_per_byte() {
        assert_eq!(
            required_gas(&vec![0u8; SSHSIG_VERIFY_INPUT_LENGTH_KINK + 1]),
            SSHSIG_VERIFY_BASE_GAS + SSHSIG_VERIFY_GAS_PER_BYTE,
        );
        assert_eq!(
            required_gas(&vec![0u8; SSHSIG_VERIFY_INPUT_LENGTH_KINK + 100]),
            SSHSIG_VERIFY_BASE_GAS + SSHSIG_VERIFY_GAS_PER_BYTE * 100,
        );
    }

    // ─────────────────────── Envelope / SSHSIG round-trip tests

    #[test]
    fn envelope_layout_matches_spec() {
        // Spot-check the envelope bytes for a known payload + namespace.
        // Layout per PROTOCOL.sshsig:
        //   "SSHSIG" || string(namespace) || string("") || string("sha512") || string(SHA-512(payload))
        let payload = b"hello world";
        let envelope = build_sshsig_envelope(payload, b"file");
        assert_eq!(&envelope[0..6], b"SSHSIG");
        // namespace: length 4, "file"
        assert_eq!(&envelope[6..14], &[0, 0, 0, 4, b'f', b'i', b'l', b'e']);
        // reserved: empty
        assert_eq!(&envelope[14..18], &[0, 0, 0, 0]);
        // hash_alg: length 6, "sha512"
        assert_eq!(&envelope[18..28], &[0, 0, 0, 6, b's', b'h', b'a', b'5', b'1', b'2']);
        // payload-hash: length 64, then SHA-512(payload)
        assert_eq!(&envelope[28..32], &[0, 0, 0, 64]);
        let expected_hash = {
            use sha2::Digest;
            sha2::Sha512::digest(payload).to_vec()
        };
        assert_eq!(&envelope[32..96], expected_hash.as_slice());
        assert_eq!(envelope.len(), 96);
    }

    // ─────────────────────── Real `ssh-keygen -Y sign` fixtures
    //
    // These are the load-bearing tests: they consume bytes produced by the
    // actual OpenSSH binary, not bytes we re-synthesize from `ed25519-dalek`
    // / `rsa` crate output. A bug in our wire-format helpers can hide in the
    // round-trip tests below (sign with our helper → verify our envelope)
    // but will show up here as a failed fixture verify.

    #[test]
    fn fixture_real_ssh_keygen_ed25519_verifies() {
        let input = hex_decode(FIXTURE_ED25519);
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn fixture_real_ssh_keygen_rsa_verifies() {
        let input = hex_decode(FIXTURE_RSA);
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn fixture_real_ssh_keygen_ed25519_tampered_payload_rejects() {
        let mut input = hex_decode(FIXTURE_ED25519);
        // Flip a byte inside the payload region. Offset 160 lands inside
        // the first dynamic field (payload) per the ABI layout.
        input[160] ^= 0xFF;
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn fixture_real_ssh_keygen_rsa_tampered_payload_rejects() {
        let mut input = hex_decode(FIXTURE_RSA);
        input[160] ^= 0xFF;
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    // ─────────────────────── Self-consistent round-trip tests

    #[test]
    fn ed25519_round_trip_short_payload() {
        let input = sign_sshsig_ed25519(b"hello world", b"file");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn ed25519_round_trip_git_namespace() {
        // Mimics what `git tag -s` produces — namespace="git", larger payload.
        let payload = b"object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
            type commit\ntag v1.0.0\n\
            tagger David <david@example.com> 1700000000 +0000\n\n\
            release notes go here\n";
        let input = sign_sshsig_ed25519(payload, b"git");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn ed25519_round_trip_empty_payload() {
        // Edge case: SSHSIG envelope is well-formed even with empty payload
        // (SHA-512 of empty is a fixed 64-byte value).
        let input = sign_sshsig_ed25519(b"", b"file");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn ed25519_round_trip_8kb_payload() {
        // Under the 16 KiB cap, well above the gas kink.
        let payload = vec![0xABu8; 8 * 1024];
        let input = sign_sshsig_ed25519(&payload, b"git");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn rsa_sha2_256_round_trip() {
        let input = sign_sshsig_rsa_sha256(b"signed by rsa-256", b"file");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn rsa_sha2_512_round_trip() {
        let input = sign_sshsig_rsa_sha512(b"signed by rsa-512", b"git");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    // ─────────────────────── Tampered-input tests

    #[test]
    fn ed25519_tampered_payload_returns_zero() {
        let mut input = sign_sshsig_ed25519(b"original payload", b"file");
        // Flip a byte inside the payload data region. Layout: 128 bytes of
        // offsets + 32 bytes payload length-prefix + payload bytes. So
        // index 128+32 = 160 is the first payload byte.
        input[160] ^= 0xFF;
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn ed25519_tampered_namespace_returns_zero() {
        let input_good = sign_sshsig_ed25519(b"payload", b"file");
        // Re-encode with a different namespace but the same signature —
        // the envelope reconstruction inside the precompile will differ.
        let envelope = build_sshsig_envelope(b"payload", b"file");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let sig = signing_key.sign(&envelope);
        let pub_key_blob =
            build_ed25519_pubkey_blob(signing_key.verifying_key().as_bytes());
        let sig_blob = build_signature_blob(b"ssh-ed25519", &sig.to_bytes());

        // Pass the same sig+pubkey but claim namespace was "git".
        let input_bad = encode_input(b"payload", b"git", &pub_key_blob, &sig_blob);
        assert_ne!(input_good, input_bad, "namespaces should differ in encoded bytes");
        assert_precompile_ok(&run(&input_bad), FAILURE_HEX);
    }

    #[test]
    fn rsa_sha2_512_tampered_payload_returns_zero() {
        let mut input = sign_sshsig_rsa_sha512(b"original", b"file");
        input[160] ^= 0xFF;
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn rsa_sha2_512_signature_with_sha256_algo_label_fails() {
        // Defends against future refactors that accidentally merge the
        // rsa-sha2-256 and rsa-sha2-512 dispatch arms.
        let mut input = sign_sshsig_rsa_sha512(b"payload", b"file");
        let needle = b"rsa-sha2-512";
        let replacement = b"rsa-sha2-256";
        let pos = input.windows(needle.len()).position(|w| w == needle).expect("algo present");
        input[pos..pos + needle.len()].copy_from_slice(replacement);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    // ─────────────────────── Length-cap tests

    #[test]
    fn payload_at_max_length_accepted() {
        // Exactly at the cap should still verify.
        let payload = vec![0x42u8; MAX_PAYLOAD_BYTES];
        let input = sign_sshsig_ed25519(&payload, b"file");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn payload_over_max_length_rejected_at_decode() {
        // Construct an input that claims a payload longer than the cap.
        // We don't need a valid sig — decode should fail before crypto.
        let mut buf = Vec::new();
        buf.extend_from_slice(&u256(128)); // payload offset
        buf.extend_from_slice(&u256(128 + 32 + 32)); // namespace offset (stub)
        buf.extend_from_slice(&u256(128 + 32 + 64)); // pubkey offset (stub)
        buf.extend_from_slice(&u256(128 + 32 + 96)); // sig offset (stub)
        buf.extend_from_slice(&u256(MAX_PAYLOAD_BYTES + 1));
        buf.extend_from_slice(&vec![0u8; 32]); // pretend data
        assert_precompile_err(&run(&buf));
    }

    #[test]
    fn namespace_over_max_length_rejected() {
        let oversized_ns = vec![b'x'; MAX_NAMESPACE_BYTES + 1];
        // Build a minimally-valid envelope with the oversized namespace
        // declared. Sig content irrelevant — we fail at decode.
        let input = sign_sshsig_ed25519(b"x", &oversized_ns);
        assert_precompile_err(&run(&input));
    }

    #[test]
    fn rsa_modulus_over_max_rejected_with_failure() {
        // Forge an RSA pubkey with a 1024-byte modulus (8192-bit). The size
        // check inside verify_rsa returns false → bytes32(0), no error.
        let oversized_n = vec![0x01u8; MAX_RSA_MODULUS_BYTES + 1];
        let pubkey = [
            ssh_string(b"ssh-rsa"),
            ssh_string(&[0x01, 0x00, 0x01]), // e = 65537
            ssh_string(&oversized_n),
        ]
        .concat();
        // Fake sig — doesn't matter, we reject before verifying crypto.
        let sig = build_signature_blob(b"rsa-sha2-256", &vec![0xAAu8; 256]);
        let input = encode_input(b"payload", b"file", &pubkey, &sig);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    // ─────────────────────── Error-path tests

    #[test]
    fn empty_input_errors() {
        assert_precompile_err(&run(&[]));
    }

    #[test]
    fn truncated_offset_header_errors() {
        // 127 bytes — one short of the four 32-byte offset slots.
        assert_precompile_err(&run(&vec![0u8; 127]));
    }

    #[test]
    fn out_of_gas() {
        let input = sign_sshsig_ed25519(b"payload", b"file");
        assert_precompile_oog(&sshsig_verify_run(&input, SSHSIG_VERIFY_BASE_GAS - 1));
    }

    #[test]
    fn corrupt_pubkey_errors() {
        let envelope = build_sshsig_envelope(b"payload", b"file");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let sig = signing_key.sign(&envelope);
        let garbage_key = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let sig_blob = build_signature_blob(b"ssh-ed25519", &sig.to_bytes());
        let input = encode_input(b"payload", b"file", &garbage_key, &sig_blob);
        assert_precompile_err(&run(&input));
    }

    #[test]
    fn unsupported_key_algo_errors() {
        // Build a pubkey claiming to be ssh-dss (unsupported).
        let fake_key = [ssh_string(b"ssh-dss"), ssh_string(&[0u8; 32])].concat();
        let fake_sig = build_signature_blob(b"ssh-dss", &[0u8; 64]);
        let input = encode_input(b"payload", b"file", &fake_key, &fake_sig);
        assert_precompile_err(&run(&input));
    }

    #[test]
    fn ed25519_key_rsa_sig_algo_returns_failure() {
        // ed25519 pubkey but signature claims rsa-sha2-256 → algo mismatch.
        // verify_ed25519 returns false (not Err) → bytes32(0).
        let envelope = build_sshsig_envelope(b"payload", b"file");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let sig = signing_key.sign(&envelope);
        let pub_key_blob =
            build_ed25519_pubkey_blob(signing_key.verifying_key().as_bytes());
        let sig_blob = build_signature_blob(b"rsa-sha2-256", &sig.to_bytes());
        let input = encode_input(b"payload", b"file", &pub_key_blob, &sig_blob);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn wrong_ed25519_pubkey_returns_failure() {
        // Sign with seed A, verify with seed B → bytes32(0).
        let envelope = build_sshsig_envelope(b"payload", b"file");
        let signer_a = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let sig = signer_a.sign(&envelope);

        let other_seed = [0x11u8; 32];
        let signer_b = ed25519_dalek::SigningKey::from_bytes(&other_seed);
        let wrong_pub_blob =
            build_ed25519_pubkey_blob(signer_b.verifying_key().as_bytes());
        let sig_blob = build_signature_blob(b"ssh-ed25519", &sig.to_bytes());
        let input = encode_input(b"payload", b"file", &wrong_pub_blob, &sig_blob);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn ed25519_short_signature_returns_failure() {
        let envelope = build_sshsig_envelope(b"payload", b"file");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let _ = envelope; // ed25519 sig is exactly 64 bytes — use a 32-byte stub.
        let pub_key_blob =
            build_ed25519_pubkey_blob(signing_key.verifying_key().as_bytes());
        let short_sig = build_signature_blob(b"ssh-ed25519", &[0u8; 32]);
        let input = encode_input(b"payload", b"file", &pub_key_blob, &short_sig);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    // ─────────────────────── ssh_string parsing micro-tests

    #[test]
    fn read_ssh_string_basic() {
        let data = [0u8, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'];
        let mut offset = 0;
        let result = read_ssh_string(&data, &mut offset).unwrap();
        assert_eq!(result, b"hello");
        assert_eq!(offset, 9);
    }

    #[test]
    fn read_ssh_string_truncated_length() {
        let data = [0u8, 0, 0];
        let mut offset = 0;
        assert!(read_ssh_string(&data, &mut offset).is_err());
    }

    #[test]
    fn read_ssh_string_truncated_data() {
        let data = [0u8, 0, 0, 10, b'h', b'i'];
        let mut offset = 0;
        assert!(read_ssh_string(&data, &mut offset).is_err());
    }
}
