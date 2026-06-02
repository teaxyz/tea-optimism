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
//! # SSHSIG hash algorithm handling
//!
//! `ssh-keygen -Y sign` defaults to SHA-512, and git uses SHA-512 for SSH-
//! signed tags/commits, so the primary verification path tries SHA-512 first.
//! On failure the precompile retries with a SHA-256 envelope to cover signers
//! invoked with `ssh-keygen -Y sign -O hashalg=sha256`. Both envelopes route
//! through the same `verify_ssh_ed25519` / `verify_ssh_rsa` /
//! `verify_ssh_ecdsa` paths — only the envelope hash differs.
//!
//! Gas note: precompile gas is pre-computed from input size before any
//! verification work runs, so callers are billed identically whether the
//! signature happened to be SHA-512 or SHA-256. The retry adds a few µs of
//! CPU on the SHA-512-fails-then-SHA-256-succeeds path; it does not change
//! observed gas cost.
//!
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
//! - `ecdsa-sha2-nistp256`: ECDSA on P-256 with SHA-256 (RFC 5656).
//! - `ecdsa-sha2-nistp384`: ECDSA on P-384 with SHA-384 (RFC 5656).
//! - `ecdsa-sha2-nistp521`: ECDSA on P-521 with SHA-512 (RFC 5656).
//!
//! Deprecated `ssh-rsa` (SHA-1) signatures are rejected. ECDSA signatures are
//! low-S-only (high-S form is rejected to prevent malleability — see
//! `ssh_common::verify_ssh_ecdsa`).

use alloy_primitives::{Address, Bytes, address};
use revm::precompile::{Precompile, PrecompileId, PrecompileOutput, PrecompileResult};

use super::ssh_common::{read_ssh_string, verify_ssh_ecdsa, verify_ssh_ed25519, verify_ssh_rsa};

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
///
/// Saturating arithmetic mirrors `ssh_verify::required_gas`.
pub fn required_gas(input: &[u8]) -> u64 {
    if input.len() <= SSHSIG_VERIFY_INPUT_LENGTH_KINK {
        return SSHSIG_VERIFY_BASE_GAS;
    }
    let additional_bytes = input.len() - SSHSIG_VERIFY_INPUT_LENGTH_KINK;
    SSHSIG_VERIFY_BASE_GAS
        .saturating_add(SSHSIG_VERIFY_GAS_PER_BYTE.saturating_mul(additional_bytes as u64))
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

/// Append a length-prefixed SSH wire-format string to `out`. Used when
/// reconstructing the SSHSIG envelope locally; the inverse parser
/// [`read_ssh_string`] lives in [`super::ssh_common`].
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
///
/// Rejects offsets whose upper 24 bytes are non-zero and uses `usize::try_from`
/// so a u64 value larger than `usize::MAX` on a 32-bit target is an error
/// rather than a silent truncation.
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

/// Build the SSHSIG signed-data envelope per PROTOCOL.sshsig using SHA-512.
///
/// ```text
/// "SSHSIG" || string(namespace) || string("") || string("sha512") || string(SHA-512(payload))
/// ```
///
/// SHA-512 is the `ssh-keygen -Y sign` default and what `git commit -S` /
/// `git tag -s` produce for SSH-signed objects, so this is the primary
/// verification path. The SHA-256 fallback lives in
/// [`build_sshsig_envelope_with_hash`].
///
/// `cfg(test)`-only: production code reuses
/// [`build_sshsig_envelope_with_hash`] directly in `run_verification` to
/// avoid double-hashing the payload (it needs both SHA-512 and SHA-256
/// envelopes in one place). The test helpers keep using this convenience
/// wrapper because it matches what the original `sign_sshsig_*` helpers
/// expect.
#[cfg(test)]
fn build_sshsig_envelope(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let payload_hash = sha2::Sha512::digest(payload);
    build_sshsig_envelope_with_hash(namespace, b"sha512", payload_hash.as_slice())
}

/// Build the SSHSIG envelope from a pre-computed payload hash. Factored out
/// of [`build_sshsig_envelope`] so the SHA-256 retry path (`ssh-keygen -Y
/// sign -O hashalg=sha256`) reuses the same wire-format reconstruction.
///
/// `hash_algo_name` is the wire-format string that appears inside the
/// envelope (currently `b"sha512"` or `b"sha256"`); `hash_bytes` is the
/// caller-computed digest of the payload using that algorithm.
fn build_sshsig_envelope_with_hash(
    namespace: &[u8],
    hash_algo_name: &[u8],
    hash_bytes: &[u8],
) -> Vec<u8> {
    // Capacity hint: 6 magic + (4 + ns) + 4 empty reserved + (4 + algo_name) +
    // (4 + hash_len). Slight overshoot is fine — Vec only reallocates if
    // exceeded.
    let mut envelope = Vec::with_capacity(
        SSHSIG_MAGIC.len() + 4 + namespace.len() + 4 + 4 + hash_algo_name.len() + 4 + hash_bytes.len(),
    );
    envelope.extend_from_slice(SSHSIG_MAGIC);
    write_ssh_string(&mut envelope, namespace);
    write_ssh_string(&mut envelope, b"");
    write_ssh_string(&mut envelope, hash_algo_name);
    write_ssh_string(&mut envelope, hash_bytes);
    envelope
}

// ─────────────────────────────────────────── Verification dispatch

/// SSHSIG verify precompile entry point.
///
/// Follows the `ecrecover` convention: only out-of-gas returns `Err`. Any
/// parsed-but-unverifiable input — malformed ABI, corrupt SSH wire format,
/// unsupported key type, empty namespace — returns `bytes32(0)`.
fn sshsig_verify_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_cost = required_gas(input);
    if gas_limit < gas_cost {
        return PrecompileResult::Err(revm::precompile::PrecompileError::OutOfGas);
    }

    let verified = decode_input(input).is_ok_and(|decoded| run_verification(&decoded));

    if verified {
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, success_result()))
    } else {
        PrecompileResult::Ok(PrecompileOutput::new(gas_cost, failure_result()))
    }
}

/// Verify a decoded SSHSIG input. Returns `false` for any parse failure,
/// unsupported algorithm, empty namespace, or invalid signature.
fn run_verification(decoded: &SshSigVerifyInput) -> bool {
    // PROTOCOL.sshsig: "The namespace value MUST NOT be the empty string."
    // OpenSSH's own `ssh-keygen -Y verify` enforces this. Reject empty
    // namespace so a signer can't strip it and reuse the signature across
    // domains the calling contract didn't authorize.
    if decoded.namespace.is_empty() {
        return false;
    }

    let mut key_offset = 0usize;
    let key_type = match read_ssh_string(&decoded.public_key, &mut key_offset) {
        Ok(t) => t,
        Err(_) => return false,
    };

    let mut sig_parse_offset = 0usize;
    let sig_algo = match read_ssh_string(&decoded.signature, &mut sig_parse_offset) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_blob = match read_ssh_string(&decoded.signature, &mut sig_parse_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Reject trailing bytes in the SSH wire-format signature blob — same
    // encoding-malleability rationale as the trailing-byte check on the
    // pubkey blob in ssh_common::verify_ssh_*.
    if sig_parse_offset != decoded.signature.len() {
        return false;
    }

    // Try SHA-512 envelope first (the `ssh-keygen -Y sign` default and what
    // git uses for SSH-signed tags/commits — the common case). If verification
    // fails, fall back to SHA-256 to cover `ssh-keygen -Y sign -O hashalg=sha256`
    // signers. Precompile gas is pre-computed from input size before any work
    // runs, so the caller pays the same regardless of which envelope succeeded;
    // the retry only adds a few µs of CPU on the SHA-256 path.
    {
        use sha2::Digest;
        let sha512_hash = sha2::Sha512::digest(&decoded.payload);
        let envelope_sha512 = build_sshsig_envelope_with_hash(
            &decoded.namespace,
            b"sha512",
            sha512_hash.as_slice(),
        );
        if verify_with_envelope(
            key_type,
            &decoded.public_key,
            key_offset,
            &envelope_sha512,
            sig_algo,
            sig_blob,
        ) {
            return true;
        }

        let sha256_hash = sha2::Sha256::digest(&decoded.payload);
        let envelope_sha256 = build_sshsig_envelope_with_hash(
            &decoded.namespace,
            b"sha256",
            sha256_hash.as_slice(),
        );
        verify_with_envelope(
            key_type,
            &decoded.public_key,
            key_offset,
            &envelope_sha256,
            sig_algo,
            sig_blob,
        )
    }
}

/// Dispatch verification over a pre-built envelope by SSH key type. Factored
/// out of `run_verification` so the SHA-512 / SHA-256 envelope-retry path
/// doesn't duplicate the dispatch table (any future key-type addition lands
/// in one place and applies to both envelopes automatically).
fn verify_with_envelope(
    key_type: &[u8],
    public_key: &[u8],
    key_offset: usize,
    envelope: &[u8],
    sig_algo: &[u8],
    sig_blob: &[u8],
) -> bool {
    match key_type {
        b"ssh-ed25519" => {
            verify_ssh_ed25519(public_key, key_offset, envelope, sig_algo, sig_blob)
        }
        b"ssh-rsa" => verify_ssh_rsa(public_key, key_offset, envelope, sig_algo, sig_blob),
        // ECDSA dispatch — see ssh_verify.rs for the same arms. The inner
        // `verify_ssh_ecdsa` cross-gates sig_algo against key_type and
        // against the embedded curve_name; we accept any of the three
        // here and let the inner gate decide.
        b"ecdsa-sha2-nistp256"
        | b"ecdsa-sha2-nistp384"
        | b"ecdsa-sha2-nistp521" => {
            verify_ssh_ecdsa(key_type, public_key, key_offset, envelope, sig_algo, sig_blob)
        }
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
    /// Real `git commit -S` output (gpg.format=ssh) — the SSHSIG armor from a
    /// signed commit's `gpgsig` field, parsed to (payload, namespace="git",
    /// pubkey, signature). Payload is the commit content with the gpgsig
    /// block stripped (matches what `git verify-commit` checks).
    /// Verified end-to-end with `ssh-keygen -Y verify` before embedding.
    const FIXTURE_GIT_COMMIT: &str =
        include_str!("testdata_sshsig_git_commit_ed25519.hex");

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

    fn build_ecdsa_pubkey_blob(key_type: &[u8], curve_name: &[u8], q: &[u8]) -> Vec<u8> {
        [ssh_string(key_type), ssh_string(curve_name), ssh_string(q)].concat()
    }

    /// RFC 5656 §3.1.2: the ECDSA sig_blob is itself SSH-encoded as
    /// `mpint(r) || mpint(s)`.
    fn build_ecdsa_sig_inner(r: &[u8], s: &[u8]) -> Vec<u8> {
        [ssh_mpint(r), ssh_mpint(s)].concat()
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

    /// Encoding-malleability guard (sibling of the GPG truncated-tail finding):
    /// the SSHSIG wire-format parsers must consume the *entire* pubkey and
    /// signature blobs. Appending any trailing byte to an otherwise-valid blob
    /// must flip the result to failure — there is no lenient filter (as `pgp`
    /// has) that could silently drop the tail. `verify_ssh_*` enforces full
    /// consumption of the pubkey blob and `run_verification` enforces it on the
    /// signature blob.
    #[test]
    fn rejects_trailing_bytes_on_blobs() {
        let payload = b"hello sshsig precompile";
        let namespace = b"file";
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let verifying_key = signing_key.verifying_key();
        let envelope = build_sshsig_envelope(payload, namespace);
        let sig = signing_key.sign(&envelope);

        let pub_key_blob = build_ed25519_pubkey_blob(verifying_key.as_bytes());
        let sig_blob = build_signature_blob(b"ssh-ed25519", &sig.to_bytes());

        // Baseline: the unmodified blobs verify.
        assert_precompile_ok(&run(&encode_input(payload, namespace, &pub_key_blob, &sig_blob)), SUCCESS_HEX);

        // One trailing byte on the pubkey blob must be rejected.
        let mut pk_tail = pub_key_blob.clone();
        pk_tail.push(0x00);
        assert_precompile_ok(&run(&encode_input(payload, namespace, &pk_tail, &sig_blob)), FAILURE_HEX);

        // One trailing byte on the signature blob must be rejected.
        let mut sig_tail = sig_blob.clone();
        sig_tail.push(0x00);
        assert_precompile_ok(&run(&encode_input(payload, namespace, &pub_key_blob, &sig_tail)), FAILURE_HEX);
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

    /// Real `git commit -S` fixture (namespace="git"). End-to-end proof that
    /// the precompile accepts the exact bytes git emits for SSH-signed
    /// commits, not just synthetic test vectors. Counterpart to the
    /// `ssh-keygen -Y sign` fixtures above — git's signing path is the
    /// primary on-chain use case for this precompile.
    #[test]
    fn fixture_real_git_commit_signed_verifies() {
        let input = hex_decode(FIXTURE_GIT_COMMIT);
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    /// Tampering the commit payload (e.g., changing the tree/author/message)
    /// must reject. Offset 160 lands inside the first dynamic field (the
    /// commit body) per the ABI layout.
    #[test]
    fn fixture_real_git_commit_tampered_payload_rejects() {
        let mut input = hex_decode(FIXTURE_GIT_COMMIT);
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

    // ─────────────────────── ECDSA SSHSIG round-trip tests
    //
    // Cover the new dispatch arms in `run_verification` for each of the
    // three NIST curves. The cross-gate / low-S / canonical-encoding
    // primitives are tested in `ssh_common.rs`; this layer just proves
    // the SSHSIG envelope path correctly hands off to `verify_ssh_ecdsa`.

    fn sign_sshsig_ecdsa_nistp256(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
        use rand_08::SeedableRng;
        use signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let q_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let envelope = build_sshsig_envelope(payload, namespace);
        let sig: Signature = signing_key.sign(&envelope);
        let sig = sig.normalize_s().unwrap_or(sig);
        let (r, s) = sig.split_bytes();

        let pub_blob = build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp256", b"nistp256", &q_bytes);
        let sig_inner = build_ecdsa_sig_inner(&r, &s);
        let sig_blob = build_signature_blob(b"ecdsa-sha2-nistp256", &sig_inner);
        encode_input(payload, namespace, &pub_blob, &sig_blob)
    }

    fn sign_sshsig_ecdsa_nistp384(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
        use rand_08::SeedableRng;
        use signature::Signer;
        use p384::ecdsa::{Signature, SigningKey};
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let q_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let envelope = build_sshsig_envelope(payload, namespace);
        let sig: Signature = signing_key.sign(&envelope);
        let sig = sig.normalize_s().unwrap_or(sig);
        let (r, s) = sig.split_bytes();

        let pub_blob = build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp384", b"nistp384", &q_bytes);
        let sig_inner = build_ecdsa_sig_inner(&r, &s);
        let sig_blob = build_signature_blob(b"ecdsa-sha2-nistp384", &sig_inner);
        encode_input(payload, namespace, &pub_blob, &sig_blob)
    }

    fn sign_sshsig_ecdsa_nistp521(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
        use rand_08::SeedableRng;
        use signature::Signer;
        use p521::ecdsa::{Signature, SigningKey, VerifyingKey};
        use p521::elliptic_curve::sec1::ToEncodedPoint;

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let q_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let envelope = build_sshsig_envelope(payload, namespace);
        let sig: Signature = signing_key.sign(&envelope);
        let sig = sig.normalize_s().unwrap_or(sig);
        let (r, s) = sig.split_bytes();

        let pub_blob = build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp521", b"nistp521", &q_bytes);
        let sig_inner = build_ecdsa_sig_inner(&r, &s);
        let sig_blob = build_signature_blob(b"ecdsa-sha2-nistp521", &sig_inner);
        encode_input(payload, namespace, &pub_blob, &sig_blob)
    }

    #[test]
    fn ecdsa_nistp256_round_trip() {
        let input = sign_sshsig_ecdsa_nistp256(b"signed by ecdsa-256", b"git");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn ecdsa_nistp384_round_trip() {
        let input = sign_sshsig_ecdsa_nistp384(b"signed by ecdsa-384", b"git");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn ecdsa_nistp521_round_trip() {
        let input = sign_sshsig_ecdsa_nistp521(b"signed by ecdsa-521", b"git");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn ecdsa_nistp256_tampered_payload_rejects() {
        let mut input = sign_sshsig_ecdsa_nistp256(b"original payload", b"file");
        input[160] ^= 0xFF; // first byte of payload data region
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    // ─────────────────────── SHA-256 envelope-hash retry path tests
    //
    // `ssh-keygen -Y sign -O hashalg=sha256` produces signatures over a
    // SHA-256-flavored SSHSIG envelope. The default `ssh-keygen -Y sign`
    // and `git commit -S` produce SHA-512. The precompile tries SHA-512
    // first and falls back to SHA-256 — both verify, neither requires the
    // caller to know which the signer used.

    /// Build an SSHSIG envelope using SHA-256 — the form `ssh-keygen -Y sign
    /// -O hashalg=sha256` produces. Mirrors `build_sshsig_envelope` (SHA-512)
    /// but with a SHA-256 digest and `"sha256"` algorithm string in the
    /// envelope.
    fn build_sshsig_envelope_sha256(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        let payload_hash = sha2::Sha256::digest(payload);
        build_sshsig_envelope_with_hash(namespace, b"sha256", payload_hash.as_slice())
    }

    /// Sign `payload` with the fixed ed25519 key but produce a SHA-256
    /// envelope (the `hashalg=sha256` variant). Mirrors `sign_sshsig_ed25519`.
    fn sign_sshsig_ed25519_sha256(payload: &[u8], namespace: &[u8]) -> Vec<u8> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let verifying_key = signing_key.verifying_key();

        let envelope = build_sshsig_envelope_sha256(payload, namespace);
        let sig = signing_key.sign(&envelope);

        let pub_key_blob = build_ed25519_pubkey_blob(verifying_key.as_bytes());
        let sig_blob = build_signature_blob(b"ssh-ed25519", &sig.to_bytes());

        encode_input(payload, namespace, &pub_key_blob, &sig_blob)
    }

    #[test]
    fn envelope_sha256_layout_matches_spec() {
        // Verifies the SHA-256 envelope is well-formed and the helper
        // produces exactly the bytes `ssh-keygen -Y sign -O hashalg=sha256`
        // would feed to the signing key.
        //   "SSHSIG" || string(namespace) || string("") || string("sha256") || string(SHA-256(payload))
        let payload = b"hello world";
        let envelope = build_sshsig_envelope_sha256(payload, b"file");
        assert_eq!(&envelope[0..6], b"SSHSIG");
        assert_eq!(&envelope[6..14], &[0, 0, 0, 4, b'f', b'i', b'l', b'e']);
        assert_eq!(&envelope[14..18], &[0, 0, 0, 0]); // reserved
        assert_eq!(&envelope[18..28], &[0, 0, 0, 6, b's', b'h', b'a', b'2', b'5', b'6']);
        assert_eq!(&envelope[28..32], &[0, 0, 0, 32]); // SHA-256 = 32 bytes
        let expected = {
            use sha2::Digest;
            sha2::Sha256::digest(payload).to_vec()
        };
        assert_eq!(&envelope[32..64], expected.as_slice());
        assert_eq!(envelope.len(), 64);
    }

    #[test]
    fn ed25519_sshsig_sha256_envelope_verifies() {
        // The load-bearing test: a signer using `hashalg=sha256` now
        // verifies. Before the fallback was added, this returned bytes32(0).
        let input = sign_sshsig_ed25519_sha256(b"hello hashalg=sha256", b"file");
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
    }

    #[test]
    fn ed25519_sshsig_both_envelopes_verify_for_same_signer() {
        // Same key + same payload + same namespace, signed once over the
        // SHA-512 envelope and once over the SHA-256 envelope — both
        // verify. Proves the retry path is transparent to callers; they
        // don't need to know which `hashalg` the signer chose.
        let payload = b"deterministic across envelopes";
        let namespace = b"file";
        let input_sha512 = sign_sshsig_ed25519(payload, namespace);
        let input_sha256 = sign_sshsig_ed25519_sha256(payload, namespace);
        assert_ne!(
            input_sha512, input_sha256,
            "the two inputs must differ — the signature is over different envelopes"
        );
        assert_precompile_ok(&run(&input_sha512), SUCCESS_HEX);
        assert_precompile_ok(&run(&input_sha256), SUCCESS_HEX);
    }

    #[test]
    fn ed25519_sshsig_sha256_tampered_payload_rejects() {
        // Even with the SHA-256 envelope path, tampering still rejects.
        let mut input = sign_sshsig_ed25519_sha256(b"original payload", b"file");
        input[160] ^= 0xFF;
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn rsa_sshsig_sha256_envelope_verifies() {
        // RSA over SHA-256 envelope — same retry path, RSA key type.
        use rand_08::SeedableRng;
        use rsa::pkcs1v15::SigningKey;
        use sha2::Sha256;
        use signature::{SignatureEncoding, Signer};

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa-2048 keygen");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        let envelope = build_sshsig_envelope_sha256(b"rsa sha256 envelope", b"file");
        let signing_key: SigningKey<Sha256> = SigningKey::new(priv_key);
        let sig = signing_key.sign(&envelope);

        let pub_key_blob = build_rsa_pubkey_blob(&pub_key);
        let sig_blob = build_signature_blob(b"rsa-sha2-256", &sig.to_bytes());
        let input = encode_input(b"rsa sha256 envelope", b"file", &pub_key_blob, &sig_blob);
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
    fn payload_over_max_length_rejected() {
        // Input claims a payload longer than the cap → decode fails →
        // normalized to bytes32(0).
        let mut buf = Vec::new();
        buf.extend_from_slice(&u256(128));
        buf.extend_from_slice(&u256(128 + 32 + 32));
        buf.extend_from_slice(&u256(128 + 32 + 64));
        buf.extend_from_slice(&u256(128 + 32 + 96));
        buf.extend_from_slice(&u256(MAX_PAYLOAD_BYTES + 1));
        buf.extend_from_slice(&vec![0u8; 32]);
        assert_precompile_ok(&run(&buf), FAILURE_HEX);
    }

    #[test]
    fn namespace_over_max_length_rejected() {
        let oversized_ns = vec![b'x'; MAX_NAMESPACE_BYTES + 1];
        let input = sign_sshsig_ed25519(b"x", &oversized_ns);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn rsa_modulus_over_max_rejected() {
        // Canonical-encoded ~4104-bit RSA modulus: mpint payload = [0x00, 0xFF; 513]
        // → strip removes one 0x00 → 513 bytes > MAX_RSA_MODULUS_BYTES (512) → reject.
        // (Pre-fix, the gate ran on the 514-byte raw mpint payload, so this was
        // also rejected — but for the wrong reason. Post-strip, this exercises
        // the actual size cap.)
        let mut n_bytes: Vec<u8> = vec![0x00];
        n_bytes.extend(std::iter::repeat(0xFFu8).take(513));
        let pubkey = [
            ssh_string(b"ssh-rsa"),
            ssh_string(&[0x01, 0x00, 0x01]), // e = 65537
            ssh_string(&n_bytes),
        ]
        .concat();
        let sig = build_signature_blob(b"rsa-sha2-256", &vec![0xAAu8; 513]);
        let input = encode_input(b"payload", b"file", &pubkey, &sig);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn rsa_modulus_below_min_rejected() {
        // Forge a 1024-bit RSA pubkey (128-byte modulus) — below 2048-bit floor.
        let n_raw = {
            let mut v = vec![0xC0u8];
            v.extend(std::iter::repeat(0xFFu8).take(127));
            v
        };
        let mut pubkey = ssh_string(b"ssh-rsa");
        pubkey.extend_from_slice(&ssh_string(&[0x01, 0x00, 0x01]));
        pubkey.extend_from_slice(&ssh_mpint(&n_raw));
        let sig = build_signature_blob(b"rsa-sha2-256", &vec![0xAAu8; 128]);
        let input = encode_input(b"payload", b"file", &pubkey, &sig);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    // ─────────────────────── Error-path tests (all normalized to bytes32(0))
    //
    // Per the ecrecover convention, only out-of-gas returns `Err`. Any other
    // parsed-but-unverifiable input — empty, truncated, corrupt, unsupported
    // algorithm, empty namespace — must return `bytes32(0)` so callers cannot
    // accidentally revert on "the signature didn't verify."

    #[test]
    fn empty_input_returns_failure() {
        assert_precompile_ok(&run(&[]), FAILURE_HEX);
    }

    #[test]
    fn truncated_offset_header_returns_failure() {
        assert_precompile_ok(&run(&vec![0u8; 127]), FAILURE_HEX);
    }

    #[test]
    fn out_of_gas() {
        let input = sign_sshsig_ed25519(b"payload", b"file");
        assert_precompile_oog(&sshsig_verify_run(&input, SSHSIG_VERIFY_BASE_GAS - 1));
    }

    #[test]
    fn corrupt_pubkey_returns_failure() {
        let envelope = build_sshsig_envelope(b"payload", b"file");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
        let sig = signing_key.sign(&envelope);
        let garbage_key = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let sig_blob = build_signature_blob(b"ssh-ed25519", &sig.to_bytes());
        let input = encode_input(b"payload", b"file", &garbage_key, &sig_blob);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn unsupported_key_algo_returns_failure() {
        let fake_key = [ssh_string(b"ssh-dss"), ssh_string(&[0u8; 32])].concat();
        let fake_sig = build_signature_blob(b"ssh-dss", &[0u8; 64]);
        let input = encode_input(b"payload", b"file", &fake_key, &fake_sig);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn empty_namespace_rejected() {
        // PROTOCOL.sshsig: "The namespace value MUST NOT be the empty string."
        // OpenSSH's own `ssh-keygen -Y verify` rejects empty-namespace SSHSIGs.
        // Without this gate, a signer could strip the namespace and replay
        // across calling-contract domains.
        let input = sign_sshsig_ed25519(b"payload", b"");
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn ssh_rsa_sha1_sig_algo_rejected() {
        // Legacy `ssh-rsa` (SHA-1) is RFC-8332-deprecated. The dispatch arm
        // in verify_ssh_rsa rejects it explicitly. Relabel a valid rsa-sha2-256
        // signature as `ssh-rsa` to exercise that arm without keygen cost.
        use rand_08::SeedableRng;
        use rsa::pkcs1v15::SigningKey;
        use sha2::Sha256;
        use signature::{SignatureEncoding, Signer};

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
            .expect("RSA-2048 keygen");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        let envelope = build_sshsig_envelope(b"payload", b"file");
        let signing_key: SigningKey<Sha256> = SigningKey::new(priv_key);
        let sig_bytes = signing_key.sign(&envelope).to_bytes();

        let pub_blob = build_rsa_pubkey_blob(&pub_key);
        let sig_blob = build_signature_blob(b"ssh-rsa", &sig_bytes); // wrong label
        let input = encode_input(b"payload", b"file", &pub_blob, &sig_blob);
        assert_precompile_ok(&run(&input), FAILURE_HEX);
    }

    #[test]
    fn rsa4096_round_trip_via_sshsig() {
        // The critical test: real RSA-4096 keypair (modulus mpint-encodes to
        // 513 bytes due to the RFC 4251 §5 high-bit pad) signs an SSHSIG
        // envelope and verifies end-to-end. Before strip_mpint_pad was
        // applied to the size gate, this returned bytes32(0). Asserts
        // SUCCESS_HEX, so it locks in the strip behavior for 0x0698 too.
        use rand_08::SeedableRng;
        use rsa::pkcs1v15::SigningKey;
        use sha2::Sha512;
        use signature::{SignatureEncoding, Signer};

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 4096)
            .expect("RSA-4096 keygen");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        let envelope = build_sshsig_envelope(b"hello rsa4096", b"file");
        let signing_key: SigningKey<Sha512> = SigningKey::new(priv_key);
        let sig_bytes = signing_key.sign(&envelope).to_bytes();

        let pub_blob = build_rsa_pubkey_blob(&pub_key);
        let sig_blob = build_signature_blob(b"rsa-sha2-512", &sig_bytes);
        let input = encode_input(b"hello rsa4096", b"file", &pub_blob, &sig_blob);
        assert_precompile_ok(&run(&input), SUCCESS_HEX);
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

    // (SSH wire-format parser tests live in ssh_common.rs alongside the
    // shared implementation, so they're not duplicated here.)
}
