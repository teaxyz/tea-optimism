//! Shared SSH wire-format and signature-verification helpers used by both
//! `0x0697` (ssh_verify) and `0x0698` (ssh_sig_verify).
//!
//! Centralising this here prevents the class of bug that motivated this module:
//! `0x0697` shipped without `strip_mpint_pad`, was fixed in PR #14, and the
//! same bug then went straight to production in `0x0698` via PR #13 because the
//! parser was copy-pasted. With both precompiles routing through the same
//! verify functions, RFC-compliance fixes land in one place and cannot drift.

use rsa::pkcs1v15::{Signature as RsaPkcs1Signature, VerifyingKey as RsaPkcs1VerifyingKey};
use sha2::{Sha256, Sha512};
use signature::Verifier as SignatureVerifier;

/// Maximum RSA modulus size in bytes — 4096-bit. Bump and re-release if larger
/// keys are ever needed. Compared against the *unpadded* mpint via
/// [`strip_mpint_pad`].
pub const MAX_RSA_MODULUS_BYTES: usize = 512;

/// Minimum RSA modulus size in bytes — 2048-bit. RFC 8332 retired `ssh-rsa`
/// (SHA-1) over RSA-1024 weakness; matching that spirit, we reject moduli
/// below 2048-bit at the gate so a caller that uses a recovered pubkey as
/// "is this signed at all" can't be fooled by a trivially-factorable key.
pub const MIN_RSA_MODULUS_BYTES: usize = 256;

// ─────────────────────────────────────────── SSH wire-format helpers

/// Strip the leading 0x00 disambiguation byte from an SSH mpint payload,
/// rejecting non-canonical encodings.
///
/// RFC 4251 §5: a positive-integer mpint has at most one leading `0x00`, and
/// only when the next byte's high bit is set. Any other leading-zero pattern
/// is non-canonical and rejected. This matters for the lower-bound check on
/// the RSA modulus: a lenient single-strip would let an attacker encode a
/// 1024-bit modulus as `[0x00] + [0x00; 128] + [128 bytes of actual modulus]`
/// (257 bytes), strip to 256, pass `MIN_RSA_MODULUS_BYTES`, and have
/// `BigUint::from_bytes_be` silently absorb the remaining zeros — defeating
/// the 2048-bit floor entirely.
pub fn strip_mpint_pad(bytes: &[u8]) -> Result<&[u8], &'static str> {
    if bytes.len() >= 2 && bytes[0] == 0x00 {
        if bytes[1] & 0x80 == 0 {
            return Err("non-canonical mpint pad");
        }
        return Ok(&bytes[1..]);
    }
    // RFC 4251 §5: a positive mpint whose most-significant byte has the high
    // bit set MUST carry the leading `0x00` sign pad. A signless high-bit value
    // is non-canonical — reject it, otherwise `0x00||x` and `x` decode to the
    // same RSA modulus / ECDSA scalar, aliasing one key or signature across two
    // distinct publicKey / sig_blob byte strings (TEAO1-168 / TEAO1-183).
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        return Err("missing mpint sign pad");
    }
    Ok(bytes)
}

/// Read a length-prefixed string from SSH wire format.
///
/// SSH wire format uses a `uint32` big-endian length prefix followed by raw
/// bytes. Returns the string data and advances the offset. Uses `checked_add`
/// throughout so an adversarial `offset` near `usize::MAX` cannot wrap into a
/// valid slice index — important on 32-bit targets even though tea-reth runs
/// on 64-bit.
pub fn read_ssh_string<'a>(
    data: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], &'static str> {
    let len_end = offset.checked_add(4).ok_or("offset overflow")?;
    if len_end > data.len() {
        return Err("truncated string length");
    }
    let len = u32::from_be_bytes(
        data[*offset..len_end]
            .try_into()
            .map_err(|_| "length conversion error")?,
    ) as usize;
    let data_end = len_end.checked_add(len).ok_or("length overflow")?;
    if data_end > data.len() {
        return Err("truncated string data");
    }
    let result = &data[len_end..data_end];
    *offset = data_end;
    Ok(result)
}

// ─────────────────────────────────────────── Signature verification

/// Verify an SSH ed25519 signature against `message`.
///
/// `pub_key_data` is the full SSH wire-format public key blob; `offset` is the
/// position immediately after the `key_type` string (i.e. where the 32-byte
/// `ssh-string`-wrapped pubkey begins). `sig_algo` and `sig_blob` are the two
/// strings parsed from the SSH signature wire format.
///
/// Uses [`ed25519_dalek::VerifyingKey::verify_strict`], which rejects
/// non-canonical S and small-subgroup R variants — closes the signature-
/// malleability footgun where a single `(pubkey, message)` pair admits
/// multiple valid signatures.
pub fn verify_ssh_ed25519(
    pub_key_data: &[u8],
    offset: usize,
    message: &[u8],
    sig_algo: &[u8],
    sig_blob: &[u8],
) -> bool {
    // Algorithm cross-gate: ed25519 key requires ed25519 sig.
    if sig_algo != b"ssh-ed25519" {
        return false;
    }

    let mut key_offset = offset;
    let key_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(k) if k.len() == 32 => k,
        _ => return false,
    };

    // Reject trailing bytes in the SSH wire-format pubkey blob. The
    // canonical encoding is `string("ssh-ed25519") + string(32-byte-key)`
    // with nothing after. Trailing-byte tolerance would let two distinct
    // `publicKey` ABI inputs verify the same signature, which is harmless
    // for the primitive but a footgun for any caller that hashes the
    // pubkey bytes off-chain to derive an identity.
    if key_offset != pub_key_data.len() {
        return false;
    }

    if sig_blob.len() != 64 {
        return false;
    }

    // Explicit early-return instead of `unwrap_or(&[0u8; 32])` so that a
    // future refactor loosening the length gate can't silently switch
    // verification to a hard-coded all-zero pubkey.
    let key_array: &[u8; 32] = match key_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_array: &[u8; 64] = match sig_blob.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(key_array) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let signature = ed25519_dalek::Signature::from_bytes(sig_array);

    verifying_key.verify_strict(message, &signature).is_ok()
}

/// Verify an SSH RSA signature (rsa-sha2-256 or rsa-sha2-512) against `message`.
///
/// Parses `mpint e, mpint n` from `pub_key_data[offset..]`, strips the SSH
/// mpint pad on `n`, enforces both the upper ([`MAX_RSA_MODULUS_BYTES`]) and
/// lower ([`MIN_RSA_MODULUS_BYTES`]) bounds on the modulus, and dispatches by
/// `sig_algo`. Deprecated `ssh-rsa` (SHA-1) is rejected by an explicit arm,
/// not by falling through to the wildcard.
pub fn verify_ssh_rsa(
    pub_key_data: &[u8],
    offset: usize,
    message: &[u8],
    sig_algo: &[u8],
    sig_blob: &[u8],
) -> bool {
    let mut key_offset = offset;
    let e_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let n_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Reject trailing bytes in the SSH wire-format pubkey blob — same
    // rationale as in verify_ssh_ed25519 above.
    if key_offset != pub_key_data.len() {
        return false;
    }

    // Strict canonical mpint strip on both e and n. Without canonicalising
    // e, an attacker could pad it with extraneous leading zeros to produce
    // distinct `publicKey` byte sequences that map to the same (n, e) RSA
    // key — same caller-side identity-derivation footgun as trailing bytes.
    let e_unpadded = match strip_mpint_pad(e_bytes) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let n_unpadded = match strip_mpint_pad(n_bytes) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Fast pre-filter on the byte length of the canonical encoding.
    if n_unpadded.len() > MAX_RSA_MODULUS_BYTES
        || n_unpadded.len() < MIN_RSA_MODULUS_BYTES
    {
        return false;
    }

    let e = rsa::BigUint::from_bytes_be(e_unpadded);
    let n = rsa::BigUint::from_bytes_be(n_unpadded);
    let pub_key = match rsa::RsaPublicKey::new(n, e) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // Precise post-construction bit-length check. Byte length is in
    // [bits/8, (bits+7)/8] so the fast filter can admit a 2041-bit modulus
    // through the 256-byte floor; this clamps to the exact constants.
    use rsa::traits::PublicKeyParts;
    let n_bits = pub_key.n().bits();
    if !(MIN_RSA_MODULUS_BYTES * 8..=MAX_RSA_MODULUS_BYTES * 8).contains(&n_bits) {
        return false;
    }

    match sig_algo {
        b"rsa-sha2-256" => {
            let verifying_key = RsaPkcs1VerifyingKey::<Sha256>::new(pub_key);
            let sig = match RsaPkcs1Signature::try_from(sig_blob) {
                Ok(s) => s,
                Err(_) => return false,
            };
            SignatureVerifier::verify(&verifying_key, message, &sig).is_ok()
        }
        b"rsa-sha2-512" => {
            let verifying_key = RsaPkcs1VerifyingKey::<Sha512>::new(pub_key);
            let sig = match RsaPkcs1Signature::try_from(sig_blob) {
                Ok(s) => s,
                Err(_) => return false,
            };
            SignatureVerifier::verify(&verifying_key, message, &sig).is_ok()
        }
        // Explicit rejection of SHA-1 `ssh-rsa` (RFC 8332 deprecated) so it
        // cannot silently fall through if another arm is added in the future.
        b"ssh-rsa" => false,
        _ => false,
    }
}

/// Verify an SSH ECDSA signature against `message`, per RFC 5656.
///
/// `pub_key_data` is the full SSH wire-format public key blob; `offset` is the
/// position immediately after the `key_type` string (same convention as
/// [`verify_ssh_rsa`]). `sig_algo` and `sig_blob` are the two strings parsed
/// from the SSH signature wire format.
///
/// # Wire formats (RFC 5656)
///
/// Public key (after the consumed `key_type`):
/// ```text
///   string("nistpXXX")           ← embedded curve name; cross-gated below
///   string(Q)                    ← uncompressed SEC1 point: 0x04 || X || Y
/// ```
///
/// Signature blob (RFC 5656 §3.1.2): the blob is itself SSH-wire-encoded:
/// ```text
///   mpint(r) mpint(s)
/// ```
///
/// # Security gates
///
/// - **Algorithm cross-gate**: `sig_algo` must match `key_type` exactly — an
///   ecdsa-sha2-nistp256 key cannot verify an ecdsa-sha2-nistp384 signature
///   even if the embedded SEC1 point happens to decode under both curves.
/// - **Curve-name cross-gate**: the second string in the pubkey blob is the
///   embedded curve name ("nistp256" / "nistp384" / "nistp521") and must
///   agree with the algorithm suffix. RFC 5656 §3.1 mandates this; without
///   the check, a pubkey with `key_type=ecdsa-sha2-nistp256` but
///   `curve_name=nistp384` could pass.
/// - **Trailing-byte rejection** on the pubkey blob — same
///   identity-derivation footgun rationale as [`verify_ssh_ed25519`] /
///   [`verify_ssh_rsa`].
/// - **Strict canonical mpint** on both `r` and `s` via [`strip_mpint_pad`].
/// - **Low-S enforcement** (BIP-62 style): reject any signature where
///   `S > n/2`. ECDSA admits two valid `s` values for each `(r, message)`
///   pair (`s` and `n - s`), so accepting both forms is a signature-
///   malleability footgun — we reject the non-canonical high-S form rather
///   than silently normalising it, so callers that hash signature bytes to
///   derive identity cannot be tricked into seeing two distinct "valid"
///   signatures for the same `(pubkey, message)`.
pub fn verify_ssh_ecdsa(
    key_type: &[u8],
    pub_key_data: &[u8],
    offset: usize,
    message: &[u8],
    sig_algo: &[u8],
    sig_blob: &[u8],
) -> bool {
    // Outer key_type cross-gate (TEAO1-163): the SSH key_type string that
    // precedes the pubkey blob must equal the signature algorithm. Without it,
    // a blob advertising `ecdsa-sha2-nistp256` could verify an
    // `ecdsa-sha2-nistp384` signature as long as the embedded curve_name agreed
    // with sig_algo — aliasing one key across multiple advertised identities.
    // This makes the function's documented "sig_algo must match key_type"
    // guarantee real rather than aspirational.
    if key_type != sig_algo {
        return false;
    }

    // Algorithm cross-gate + curve-name dispatch in one match. Each arm
    // pins the expected curve_name suffix and the SEC1 uncompressed-point
    // length so a sig_algo + key_type match cannot also accept a Q from a
    // different curve.
    let mut key_offset = offset;
    let curve_name = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let q_bytes = match read_ssh_string(pub_key_data, &mut key_offset) {
        Ok(q) => q,
        Err(_) => return false,
    };

    // Reject trailing bytes in the SSH wire-format pubkey blob — same
    // rationale as in verify_ssh_ed25519 / verify_ssh_rsa above.
    if key_offset != pub_key_data.len() {
        return false;
    }

    // Parse mpint(r), mpint(s) from the inner signature blob and reject any
    // trailing bytes there as well — the SSHSIG / SSH primitive wire format
    // gives the sig_blob string an exact length, so a well-formed signer
    // never produces trailing bytes.
    let mut sig_offset = 0usize;
    let r_bytes = match read_ssh_string(sig_blob, &mut sig_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let s_bytes = match read_ssh_string(sig_blob, &mut sig_offset) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if sig_offset != sig_blob.len() {
        return false;
    }
    let r_unpadded = match strip_mpint_pad(r_bytes) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let s_unpadded = match strip_mpint_pad(s_bytes) {
        Ok(b) => b,
        Err(_) => return false,
    };

    match sig_algo {
        b"ecdsa-sha2-nistp256" => {
            if curve_name != b"nistp256" {
                return false;
            }
            verify_ecdsa_p256(q_bytes, message, r_unpadded, s_unpadded)
        }
        b"ecdsa-sha2-nistp384" => {
            if curve_name != b"nistp384" {
                return false;
            }
            verify_ecdsa_p384(q_bytes, message, r_unpadded, s_unpadded)
        }
        b"ecdsa-sha2-nistp521" => {
            if curve_name != b"nistp521" {
                return false;
            }
            verify_ecdsa_p521(q_bytes, message, r_unpadded, s_unpadded)
        }
        _ => false,
    }
}

/// Pack `r_unpadded` / `s_unpadded` into a fixed-width big-endian buffer of
/// `field_bytes` per scalar, left-padding with zeros. ECDSA `Signature::from_scalars`
/// expects exactly `field_bytes`-wide inputs; mpint stripping leaves a value
/// whose byte length is in `[0, field_bytes]`. Returns `None` if either scalar
/// exceeds the field width (which would mean a non-canonical input — the SSH
/// mpint should have been the minimal canonical encoding).
fn pad_scalars(
    r_unpadded: &[u8],
    s_unpadded: &[u8],
    field_bytes: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if r_unpadded.len() > field_bytes || s_unpadded.len() > field_bytes {
        return None;
    }
    let mut r_padded = vec![0u8; field_bytes];
    let mut s_padded = vec![0u8; field_bytes];
    r_padded[field_bytes - r_unpadded.len()..].copy_from_slice(r_unpadded);
    s_padded[field_bytes - s_unpadded.len()..].copy_from_slice(s_unpadded);
    Some((r_padded, s_padded))
}

/// RFC 5656 §3.1 mandates the *uncompressed* SEC1 point (`0x04 ‖ X ‖ Y`).
/// `VerifyingKey::from_sec1_bytes` would otherwise also accept compressed
/// (`0x02`/`0x03`) encodings, letting two distinct `publicKey` blobs map to the
/// same key — which breaks callers that hash the blob to derive an on-chain
/// identity. `field_bytes` is the curve coordinate width (32/48/66).
fn is_uncompressed_sec1(q_bytes: &[u8], field_bytes: usize) -> bool {
    q_bytes.first() == Some(&0x04) && q_bytes.len() == 1 + 2 * field_bytes
}

/// Verify ECDSA on P-256 with SHA-256.
fn verify_ecdsa_p256(q_bytes: &[u8], message: &[u8], r: &[u8], s: &[u8]) -> bool {
    use p256::ecdsa::{Signature, VerifyingKey};
    if !is_uncompressed_sec1(q_bytes, 32) {
        return false;
    }
    let verifying_key = match VerifyingKey::from_sec1_bytes(q_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let (r_padded, s_padded) = match pad_scalars(r, s, 32) {
        Some(pair) => pair,
        None => return false,
    };
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_padded);
    sig_bytes[32..].copy_from_slice(&s_padded);
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Low-S enforcement: reject non-canonical high-S sigs rather than
    // silently normalising — see the function-level doc above for why.
    if signature.normalize_s().is_some() {
        return false;
    }
    // `Verifier::verify` on a `VerifyingKey<NistP256>` takes the raw
    // message and hashes with SHA-256 internally (per RFC 6979 / RFC 5656).
    SignatureVerifier::verify(&verifying_key, message, &signature).is_ok()
}

/// Verify ECDSA on P-384 with SHA-384.
fn verify_ecdsa_p384(q_bytes: &[u8], message: &[u8], r: &[u8], s: &[u8]) -> bool {
    use p384::ecdsa::{Signature, VerifyingKey};
    if !is_uncompressed_sec1(q_bytes, 48) {
        return false;
    }
    let verifying_key = match VerifyingKey::from_sec1_bytes(q_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let (r_padded, s_padded) = match pad_scalars(r, s, 48) {
        Some(pair) => pair,
        None => return false,
    };
    let mut sig_bytes = [0u8; 96];
    sig_bytes[..48].copy_from_slice(&r_padded);
    sig_bytes[48..].copy_from_slice(&s_padded);
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if signature.normalize_s().is_some() {
        return false;
    }
    SignatureVerifier::verify(&verifying_key, message, &signature).is_ok()
}

/// Verify ECDSA on P-521 with SHA-512.
///
/// Note P-521's field is 521 bits, so each scalar is 66 bytes (the high byte
/// has only 1 bit used). A canonical mpint of `r` or `s` therefore lands in
/// `[0, 66]` bytes — `pad_scalars` handles the left-pad to exactly 66.
fn verify_ecdsa_p521(q_bytes: &[u8], message: &[u8], r: &[u8], s: &[u8]) -> bool {
    use p521::ecdsa::{Signature, VerifyingKey};
    if !is_uncompressed_sec1(q_bytes, 66) {
        return false;
    }
    let verifying_key = match VerifyingKey::from_sec1_bytes(q_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let (r_padded, s_padded) = match pad_scalars(r, s, 66) {
        Some(pair) => pair,
        None => return false,
    };
    let mut sig_bytes = [0u8; 132];
    sig_bytes[..66].copy_from_slice(&r_padded);
    sig_bytes[66..].copy_from_slice(&s_padded);
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if signature.normalize_s().is_some() {
        return false;
    }
    SignatureVerifier::verify(&verifying_key, message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────── strip_mpint_pad

    #[test]
    fn strip_mpint_pad_removes_canonical_high_bit_pad() {
        assert_eq!(strip_mpint_pad(&[0x00, 0x80, 0x01]).unwrap(), &[0x80, 0x01]);
        assert_eq!(strip_mpint_pad(&[0x00, 0xFF]).unwrap(), &[0xFF]);
    }

    #[test]
    fn strip_mpint_pad_noop_when_no_leading_zero() {
        // High bit unset → no sign pad required → returned unchanged.
        assert_eq!(
            strip_mpint_pad(&[0x7F, 0xFF, 0x01]).unwrap(),
            &[0x7F, 0xFF, 0x01]
        );
    }

    /// TEAO1-168 / TEAO1-183: a high-bit-set value with no leading `0x00` sign
    /// pad is a non-canonical (signless) mpint and must be rejected, so that
    /// `0x00||x` and `x` cannot alias the same integer.
    #[test]
    fn strip_mpint_pad_rejects_missing_sign_pad() {
        assert!(strip_mpint_pad(&[0x80, 0xFF]).is_err());
        assert!(strip_mpint_pad(&[0xFF]).is_err());
        assert!(strip_mpint_pad(&[0x80]).is_err());
    }

    #[test]
    fn strip_mpint_pad_rejects_non_canonical_multi_zero() {
        // Two leading 0x00s is never canonical — the inner 0x00 has high bit
        // unset, so the pad isn't needed. Must reject.
        assert!(strip_mpint_pad(&[0x00, 0x00, 0x80]).is_err());
        assert!(strip_mpint_pad(&[0x00, 0x00, 0x00, 0xFF]).is_err());
    }

    #[test]
    fn strip_mpint_pad_rejects_unneeded_pad() {
        // Leading 0x00 followed by a byte with high bit unset → the pad
        // isn't needed → non-canonical → reject.
        assert!(strip_mpint_pad(&[0x00, 0x7F, 0xFF]).is_err());
    }

    #[test]
    fn strip_mpint_pad_empty_input() {
        assert_eq!(strip_mpint_pad(&[]).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn strip_mpint_pad_lone_zero() {
        // Single 0x00 is the RFC 4251 §5 encoding of zero — valid, not stripped.
        assert_eq!(strip_mpint_pad(&[0x00]).unwrap(), &[0x00]);
    }

    // ─────────────────────────────────────────── read_ssh_string

    #[test]
    fn read_ssh_string_valid() {
        let data = [0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'];
        let mut offset = 0;
        assert_eq!(read_ssh_string(&data, &mut offset).unwrap(), b"hello");
        assert_eq!(offset, 9);
    }

    #[test]
    fn read_ssh_string_truncated_length() {
        let data = [0, 0, 0];
        let mut offset = 0;
        assert!(read_ssh_string(&data, &mut offset).is_err());
    }

    #[test]
    fn read_ssh_string_truncated_data() {
        let data = [0, 0, 0, 10, b'h', b'i'];
        let mut offset = 0;
        assert!(read_ssh_string(&data, &mut offset).is_err());
    }

    #[test]
    fn read_ssh_string_offset_overflow() {
        // Adversarial: offset near usize::MAX must not wrap.
        let data = [0u8; 100];
        let mut offset = usize::MAX - 2;
        assert!(read_ssh_string(&data, &mut offset).is_err());
    }

    // ─────────────────────────────────────────── verify_ssh_rsa

    /// Build an SSH wire-format public key blob for `ssh-rsa`.
    fn build_rsa_pubkey_blob(pubkey: &rsa::RsaPublicKey) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        let mut out = Vec::new();
        write_ssh_string(&mut out, b"ssh-rsa");
        write_ssh_mpint(&mut out, &pubkey.e().to_bytes_be());
        write_ssh_mpint(&mut out, &pubkey.n().to_bytes_be());
        out
    }

    fn write_ssh_string(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
    }

    fn write_ssh_mpint(out: &mut Vec<u8>, value: &[u8]) {
        // Canonical SSH mpint: trim extraneous leading zeros, then pad with
        // 0x00 if the high bit is set.
        let mut start = 0;
        while start < value.len().saturating_sub(1) && value[start] == 0 {
            start += 1;
        }
        let trimmed = &value[start..];
        let needs_pad = trimmed.first().is_some_and(|b| *b & 0x80 != 0);
        let total = trimmed.len() + needs_pad as usize;
        out.extend_from_slice(&(total as u32).to_be_bytes());
        if needs_pad {
            out.push(0u8);
        }
        out.extend_from_slice(trimmed);
    }

    /// Sign `message` with a freshly-generated RSA key of `key_size_bits` using
    /// PKCS#1 v1.5 + SHA-256, returning `(pubkey_blob, sig_algo, sig_blob)`.
    fn sign_rsa_sha256(
        message: &[u8],
        key_size_bits: usize,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use rand_08::SeedableRng;
        use rsa::pkcs1v15::SigningKey;
        use signature::{SignatureEncoding, Signer};

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, key_size_bits)
            .expect("RSA keygen succeeds");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        let signing_key: SigningKey<Sha256> = SigningKey::new(priv_key);
        let sig_bytes = signing_key.sign(message).to_bytes();

        (
            build_rsa_pubkey_blob(&pub_key),
            b"rsa-sha2-256".to_vec(),
            sig_bytes.to_vec(),
        )
    }

    #[test]
    fn verify_ssh_rsa_rsa2048_round_trip() {
        let message = [0x42u8; 32];
        let (pub_blob, algo, sig) = sign_rsa_sha256(&message, 2048);
        let mut o = 0usize;
        let _key_type = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(verify_ssh_rsa(&pub_blob, o, &message, &algo, &sig));
    }

    #[test]
    fn verify_ssh_rsa_rsa4096_round_trip() {
        // The critical test: RSA-N produces a modulus with bit_length == N,
        // so RSA-4096's SSH mpint encoding is 513 bytes. Without
        // strip_mpint_pad before the size gate, this returns false.
        let message = [0x42u8; 32];
        let (pub_blob, algo, sig) = sign_rsa_sha256(&message, 4096);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(verify_ssh_rsa(&pub_blob, o, &message, &algo, &sig));
    }

    #[test]
    fn verify_ssh_rsa_rejects_tampered_message() {
        let message = [0x42u8; 32];
        let (pub_blob, algo, sig) = sign_rsa_sha256(&message, 2048);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        let mut bad = message;
        bad[0] ^= 0xFF;
        assert!(!verify_ssh_rsa(&pub_blob, o, &bad, &algo, &sig));
    }

    #[test]
    fn verify_ssh_rsa_rejects_sha1_ssh_rsa() {
        // Sign with rsa-sha2-256, then relabel sig_algo as the legacy
        // SHA-1-based "ssh-rsa". The explicit arm must reject.
        let message = [0x42u8; 32];
        let (pub_blob, _algo, sig) = sign_rsa_sha256(&message, 2048);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_rsa(&pub_blob, o, &message, b"ssh-rsa", &sig));
    }

    #[test]
    fn verify_ssh_rsa_rejects_unknown_algo() {
        let message = [0x42u8; 32];
        let (pub_blob, _algo, sig) = sign_rsa_sha256(&message, 2048);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_rsa(&pub_blob, o, &message, b"rsa-sha2-384", &sig));
    }

    #[test]
    fn verify_ssh_rsa_rejects_modulus_above_max() {
        // Fake key: canonical mpint encoding of a 4104-bit modulus
        // (513 bytes pad-stripped). Must fail the upper bound.
        let mut pub_blob = Vec::new();
        write_ssh_string(&mut pub_blob, b"ssh-rsa");
        write_ssh_string(&mut pub_blob, &[0x01, 0x00, 0x01]); // e = 65537
        // n: u32 length = 514, bytes = [0x00, 0xFF; 513] — strip → 513.
        let mut n_blob: Vec<u8> = vec![0x00];
        n_blob.extend(std::iter::repeat_n(0xFFu8, 513));
        pub_blob.extend_from_slice(&(n_blob.len() as u32).to_be_bytes());
        pub_blob.extend_from_slice(&n_blob);

        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_rsa(
            &pub_blob,
            o,
            &[0u8; 32],
            b"rsa-sha2-256",
            &vec![0xAAu8; 513],
        ));
    }

    #[test]
    fn verify_ssh_rsa_rejects_modulus_below_min() {
        // Fake 1024-bit key (128-byte modulus) — below MIN_RSA_MODULUS_BYTES.
        let mut pub_blob = Vec::new();
        write_ssh_string(&mut pub_blob, b"ssh-rsa");
        write_ssh_string(&mut pub_blob, &[0x01, 0x00, 0x01]);
        // n: 128 bytes with high bit set → mpint pad → 129 bytes; strip → 128.
        let mut n_raw = vec![0xC0u8];
        n_raw.extend(std::iter::repeat_n(0xFFu8, 127));
        write_ssh_mpint(&mut pub_blob, &n_raw);

        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_rsa(
            &pub_blob,
            o,
            &[0u8; 32],
            b"rsa-sha2-256",
            &[0xAAu8; 128],
        ));
    }

    #[test]
    fn verify_ssh_rsa_rejects_padded_modulus_min_bypass() {
        // The bypass that motivated strict mpint canonicalisation. A 1024-bit
        // modulus is encoded as:
        //   [0x00]             ← single canonical-looking pad
        //   [0x00 × 128]       ← 128 extraneous zeros (non-canonical)
        //   [128 actual bytes] ← underlying 1024-bit modulus
        // Total mpint payload = 257 bytes. A lenient single-strip would leave
        // 256 bytes, sneak past `MIN_RSA_MODULUS_BYTES`, and then
        // `BigUint::from_bytes_be` would silently swallow the 128 leading
        // zeros — yielding a 1024-bit modulus that "passes" the 2048-bit floor.
        // Strict strip rejects the non-canonical multi-zero prefix.
        let mut mpint_payload: Vec<u8> = vec![0x00; 129]; // 1 pad + 128 extra
        mpint_payload.push(0x80);
        mpint_payload.extend(std::iter::repeat_n(0xFFu8, 127));
        // Wrap in SSH string framing (4-byte length prefix).
        let mut pub_blob = Vec::new();
        write_ssh_string(&mut pub_blob, b"ssh-rsa");
        write_ssh_string(&mut pub_blob, &[0x01, 0x00, 0x01]);
        pub_blob.extend_from_slice(&(mpint_payload.len() as u32).to_be_bytes());
        pub_blob.extend_from_slice(&mpint_payload);

        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(
            !verify_ssh_rsa(&pub_blob, o, &[0u8; 32], b"rsa-sha2-256", &[0xAAu8; 128]),
            "padded 1024-bit modulus must NOT pass — would bypass 2048-bit floor"
        );
    }

    /// End-to-end version of the bypass: a *real* RSA-1024 keypair signs a
    /// real message, then the modulus is wire-encoded as a non-canonical
    /// 257-byte mpint. On the pre-fix code (lenient single strip + byte-only
    /// min check), the signature verifies because the underlying integer
    /// matches the embedded key and PKCS#1 v1.5 + SHA-256 happily accepts.
    /// On the post-fix code, the strict strip + `bits()` check reject before
    /// any crypto runs. The fake-key variant above proves the strip layer
    /// catches it; this version proves the precompile result is also `false`
    /// when the attacker has full control of a matching keypair.
    #[test]
    fn verify_ssh_rsa_rejects_padded_modulus_with_real_keypair() {
        use rand_08::SeedableRng;
        use rsa::pkcs1v15::SigningKey;
        use rsa::traits::PublicKeyParts;
        use signature::{SignatureEncoding, Signer};

        let mut rng = rand_08::rngs::StdRng::from_seed([7u8; 32]);
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 1024)
            .expect("RSA-1024 keygen");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let n_raw = pub_key.n().to_bytes_be();
        assert_eq!(n_raw.len(), 128);

        let message = b"e2e padded-mpint bypass demo".as_slice();
        let signing_key: SigningKey<Sha256> = SigningKey::new(priv_key);
        let sig_bytes = signing_key.sign(message).to_bytes();
        assert_eq!(sig_bytes.len(), 128);

        // Non-canonical mpint: [0x00] + [0x00 × 128] + [128 real bytes] = 257.
        let mut malicious_mpint: Vec<u8> = vec![0x00; 129];
        malicious_mpint.extend_from_slice(&n_raw);
        assert_eq!(malicious_mpint.len(), 257);

        let mut pub_blob = Vec::new();
        write_ssh_string(&mut pub_blob, b"ssh-rsa");
        write_ssh_mpint(&mut pub_blob, &pub_key.e().to_bytes_be());
        // Inject the malicious mpint as a raw SSH-string framing (4 + 257 bytes).
        pub_blob.extend_from_slice(&(malicious_mpint.len() as u32).to_be_bytes());
        pub_blob.extend_from_slice(&malicious_mpint);

        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();

        let accepted =
            verify_ssh_rsa(&pub_blob, o, message, b"rsa-sha2-256", &sig_bytes);
        assert!(
            !accepted,
            "VULN: real 1024-bit signature accepted via non-canonical mpint — \
             2048-bit floor is bypassable"
        );
    }

    // ─────────────────────────────────────────── verify_ssh_ed25519

    fn sign_ed25519(message: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer as DalekSigner;
        // RFC 8032 test vector 2 seed for reproducibility.
        let seed: [u8; 32] = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46,
            0xec, 0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
            0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
        ];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pub_key = signing_key.verifying_key();
        let sig = signing_key.sign(message);

        let mut pub_blob = Vec::new();
        write_ssh_string(&mut pub_blob, b"ssh-ed25519");
        write_ssh_string(&mut pub_blob, pub_key.as_bytes());

        (pub_blob, b"ssh-ed25519".to_vec(), sig.to_bytes().to_vec())
    }

    #[test]
    fn verify_ssh_ed25519_round_trip() {
        let message = b"some message";
        let (pub_blob, algo, sig) = sign_ed25519(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(verify_ssh_ed25519(&pub_blob, o, message, &algo, &sig));
    }

    #[test]
    fn verify_ssh_ed25519_rejects_tampered_message() {
        let message = b"some message";
        let (pub_blob, algo, sig) = sign_ed25519(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_ed25519(&pub_blob, o, b"some tampered message", &algo, &sig));
    }

    #[test]
    fn verify_ssh_ed25519_rejects_wrong_algo() {
        let message = b"some message";
        let (pub_blob, _, sig) = sign_ed25519(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_ed25519(&pub_blob, o, message, b"rsa-sha2-256", &sig));
    }

    #[test]
    fn verify_ssh_ed25519_rejects_wrong_sig_length() {
        let message = b"some message";
        let (pub_blob, algo, _) = sign_ed25519(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        let short_sig = vec![0u8; 63];
        assert!(!verify_ssh_ed25519(&pub_blob, o, message, &algo, &short_sig));
    }

    #[test]
    fn verify_ssh_ed25519_rejects_non_canonical_s() {
        // Construct a signature with S = L (the curve order) — non-canonical.
        // verify_strict rejects it; the lenient verify would accept the
        // equivalent S = 0 (mod L). This test would FAIL under verify().
        let message = b"some message";
        let (pub_blob, algo, mut sig) = sign_ed25519(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();

        // ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
        // little-endian bytes:
        let curve_order_le: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ];
        // Overwrite the S half (bytes 32..64). The original sig's R stays.
        sig[32..64].copy_from_slice(&curve_order_le);
        assert!(!verify_ssh_ed25519(&pub_blob, o, message, &algo, &sig));
    }

    // ─────────────────────────────────────────── verify_ssh_ecdsa

    /// Build an SSH wire-format ECDSA public key blob:
    ///   string(key_type) + string(curve_name) + string(Q)
    fn build_ecdsa_pubkey_blob(key_type: &[u8], curve_name: &[u8], q: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_ssh_string(&mut out, key_type);
        write_ssh_string(&mut out, curve_name);
        write_ssh_string(&mut out, q);
        out
    }

    /// Build an SSH wire-format ECDSA signature blob:
    ///   mpint(r) || mpint(s)
    /// (RFC 5656 §3.1.2 — the blob is itself an SSH-encoded stream.)
    fn build_ecdsa_sig_blob(r_be: &[u8], s_be: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_ssh_mpint(&mut out, r_be);
        write_ssh_mpint(&mut out, s_be);
        out
    }

    /// Sign `message` with a freshly-generated P-256 keypair, returning
    /// `(pubkey_blob, sig_algo, sig_blob)` in the same shape as the other
    /// `sign_*` helpers. The blobs are exactly what a real `ssh-keygen` /
    /// OpenSSH would emit for this curve.
    fn sign_ecdsa_nistp256(message: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use signature::Signer as EcdsaSigner;
        use p256::ecdsa::{Signature, SigningKey};

        let mut rng = rand_08::rngs::StdRng::from_seed_helper();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let q_point = verifying_key.to_encoded_point(false); // uncompressed
        let q_bytes = q_point.as_bytes().to_vec();

        let signature: Signature = signing_key.sign(message);
        // Normalise to low-S to ensure verify accepts (sign() can emit either form).
        let signature = signature.normalize_s().unwrap_or(signature);
        let (r, s) = signature.split_bytes();

        let pub_blob =
            build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp256", b"nistp256", &q_bytes);
        let sig_blob = build_ecdsa_sig_blob(&r, &s);
        (pub_blob, b"ecdsa-sha2-nistp256".to_vec(), sig_blob)
    }

    #[test]
    fn is_uncompressed_sec1_gate() {
        // F-2: only `0x04 ‖ X ‖ Y` of the exact curve width is accepted.
        assert!(!is_uncompressed_sec1(&[0x02; 33], 32)); // compressed p256
        assert!(!is_uncompressed_sec1(&[0x03; 33], 32));
        assert!(!is_uncompressed_sec1(&[0x04; 64], 32)); // wrong length
        assert!(is_uncompressed_sec1(&[0x04; 65], 32)); // valid p256
        assert!(!is_uncompressed_sec1(&[0x04; 65], 48)); // p384 width mismatch
        assert!(is_uncompressed_sec1(&[0x04; 97], 48)); // valid p384
        assert!(is_uncompressed_sec1(&[0x04; 133], 66)); // valid p521
    }

    #[test]
    fn verify_ecdsa_p256_rejects_compressed_pubkey() {
        // F-2 regression: the *compressed* encoding of a key whose uncompressed
        // form verifies a signature must itself be rejected (RFC 5656 §3.1), so
        // two distinct `publicKey` blobs cannot alias onto the same key.
        use p256::ecdsa::{Signature, SigningKey};
        use signature::Signer as EcdsaSigner;

        let mut rng = rand_08::rngs::StdRng::from_seed_helper();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let message = b"f-2 regression message";
        let signature: Signature = signing_key.sign(message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let (r, s) = signature.split_bytes();

        let q_uncompressed = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        let q_compressed = verifying_key.to_encoded_point(true).as_bytes().to_vec();

        assert!(
            verify_ecdsa_p256(&q_uncompressed, message, &r, &s),
            "uncompressed key must still verify"
        );
        assert!(
            !verify_ecdsa_p256(&q_compressed, message, &r, &s),
            "compressed key must be rejected (F-2)"
        );
    }

    fn sign_ecdsa_nistp384(message: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use signature::Signer as EcdsaSigner;
        use p384::ecdsa::{Signature, SigningKey};

        let mut rng = rand_08::rngs::StdRng::from_seed_helper();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let q_point = verifying_key.to_encoded_point(false);
        let q_bytes = q_point.as_bytes().to_vec();

        let signature: Signature = signing_key.sign(message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let (r, s) = signature.split_bytes();

        let pub_blob =
            build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp384", b"nistp384", &q_bytes);
        let sig_blob = build_ecdsa_sig_blob(&r, &s);
        (pub_blob, b"ecdsa-sha2-nistp384".to_vec(), sig_blob)
    }

    fn sign_ecdsa_nistp521(message: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use signature::Signer as EcdsaSigner;
        use p521::ecdsa::{Signature, SigningKey, VerifyingKey};

        let mut rng = rand_08::rngs::StdRng::from_seed_helper();
        let signing_key = SigningKey::random(&mut rng);
        // p521 0.13.3 gates `SigningKey::verifying_key` behind a non-existent
        // `verifying` feature — work around by going through the From impl.
        let verifying_key = VerifyingKey::from(&signing_key);
        let q_point = verifying_key.to_encoded_point(false);
        let q_bytes = q_point.as_bytes().to_vec();

        let signature: Signature = signing_key.sign(message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let (r, s) = signature.split_bytes();

        let pub_blob =
            build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp521", b"nistp521", &q_bytes);
        let sig_blob = build_ecdsa_sig_blob(&r, &s);
        (pub_blob, b"ecdsa-sha2-nistp521".to_vec(), sig_blob)
    }

    /// Shim for the deterministic seed used across all sign_* helpers, so
    /// CI runs are reproducible. Mirrors the `[7u8; 32]` pattern.
    trait FromSeedHelper {
        fn from_seed_helper() -> rand_08::rngs::StdRng;
    }
    impl FromSeedHelper for rand_08::rngs::StdRng {
        fn from_seed_helper() -> rand_08::rngs::StdRng {
            use rand_08::SeedableRng;
            rand_08::rngs::StdRng::from_seed([7u8; 32])
        }
    }

    #[test]
    fn verify_ssh_ecdsa_p256_round_trip() {
        let message = b"hello p256";
        let (pub_blob, algo, sig) = sign_ecdsa_nistp256(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(verify_ssh_ecdsa(&algo, &pub_blob, o, message, &algo, &sig));
    }

    #[test]
    fn verify_ssh_ecdsa_p384_round_trip() {
        let message = b"hello p384";
        let (pub_blob, algo, sig) = sign_ecdsa_nistp384(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(verify_ssh_ecdsa(&algo, &pub_blob, o, message, &algo, &sig));
    }

    #[test]
    fn verify_ssh_ecdsa_p521_round_trip() {
        let message = b"hello p521";
        let (pub_blob, algo, sig) = sign_ecdsa_nistp521(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(verify_ssh_ecdsa(&algo, &pub_blob, o, message, &algo, &sig));
    }

    #[test]
    fn verify_ssh_ecdsa_p256_rejects_tampered_message() {
        let message = b"hello p256";
        let (pub_blob, algo, sig) = sign_ecdsa_nistp256(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        let mut bad = message.to_vec();
        bad[0] ^= 0xFF;
        assert!(!verify_ssh_ecdsa(&algo, &pub_blob, o, &bad, &algo, &sig));
    }

    #[test]
    fn verify_ssh_ecdsa_p384_rejects_tampered_message() {
        let message = b"hello p384";
        let (pub_blob, algo, sig) = sign_ecdsa_nistp384(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        let mut bad = message.to_vec();
        bad[0] ^= 0xFF;
        assert!(!verify_ssh_ecdsa(&algo, &pub_blob, o, &bad, &algo, &sig));
    }

    #[test]
    fn verify_ssh_ecdsa_p521_rejects_tampered_message() {
        let message = b"hello p521";
        let (pub_blob, algo, sig) = sign_ecdsa_nistp521(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        let mut bad = message.to_vec();
        bad[0] ^= 0xFF;
        assert!(!verify_ssh_ecdsa(&algo, &pub_blob, o, &bad, &algo, &sig));
    }

    #[test]
    fn verify_ssh_ecdsa_rejects_algo_mismatch_with_rsa() {
        // P-256 key, sig_algo labelled rsa-sha2-256 → key_type cross-gate rejects.
        let message = b"hello p256";
        let (pub_blob, _algo, sig) = sign_ecdsa_nistp256(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_ecdsa(
            b"ecdsa-sha2-nistp256",
            &pub_blob,
            o,
            message,
            b"rsa-sha2-256",
            &sig
        ));
    }

    #[test]
    fn verify_ssh_ecdsa_rejects_cross_curve_algo() {
        // P-256 key, sig_algo claims ecdsa-sha2-nistp384 → curve-name
        // cross-gate inside verify_ssh_ecdsa rejects (the embedded
        // curve_name "nistp256" doesn't match the sig_algo's "nistp384"
        // suffix).
        let message = b"hello p256";
        let (pub_blob, _algo, sig) = sign_ecdsa_nistp256(message);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_ecdsa(
            b"ecdsa-sha2-nistp256",
            &pub_blob,
            o,
            message,
            b"ecdsa-sha2-nistp384",
            &sig,
        ));
    }

    #[test]
    fn verify_ssh_ecdsa_rejects_mismatched_embedded_curve_name() {
        // Forge a pubkey blob whose key_type says ecdsa-sha2-nistp256 but
        // whose embedded curve_name says "nistp384" — curve-name cross-gate
        // must reject.
        use signature::Signer as EcdsaSigner;
        use p256::ecdsa::{Signature, SigningKey};

        let mut rng = rand_08::rngs::StdRng::from_seed_helper();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let q_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let message = b"forge curve_name";
        let signature: Signature = signing_key.sign(message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let (r, s) = signature.split_bytes();

        // key_type = nistp256, but curve_name = "nistp384" (lie).
        let pub_blob =
            build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp256", b"nistp384", &q_bytes);
        let sig_blob = build_ecdsa_sig_blob(&r, &s);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_ecdsa(
            b"ecdsa-sha2-nistp256",
            &pub_blob,
            o,
            message,
            b"ecdsa-sha2-nistp256",
            &sig_blob,
        ));
    }

    #[test]
    fn verify_ssh_ecdsa_rejects_trailing_pubkey_bytes() {
        // Append a stray byte after the canonical pubkey blob — the
        // trailing-byte gate in verify_ssh_ecdsa must reject.
        let message = b"hello p256";
        let (mut pub_blob, algo, sig) = sign_ecdsa_nistp256(message);
        pub_blob.push(0xAB);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_ecdsa(&algo, &pub_blob, o, message, &algo, &sig));
    }

    #[test]
    fn verify_ssh_ecdsa_rejects_trailing_sig_blob_bytes() {
        // Append a stray byte after the canonical mpint(r)||mpint(s) — the
        // trailing-byte gate inside the inner sig_blob parse must reject.
        let message = b"hello p256";
        let (pub_blob, algo, mut sig) = sign_ecdsa_nistp256(message);
        sig.push(0xAB);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_ecdsa(&algo, &pub_blob, o, message, &algo, &sig));
    }

    #[test]
    fn verify_ssh_ecdsa_p256_rejects_high_s_form() {
        // Construct the high-S variant of a valid low-S signature. ECDSA
        // admits two valid `s` for every `(r, message)` pair (`s` and
        // `n - s`); we reject the non-canonical high-S form to prevent
        // signature malleability — accepting both would let a caller that
        // hashes signature bytes off-chain to derive identity see two
        // distinct "valid" sigs for the same `(pubkey, message)`.
        use signature::Signer as EcdsaSigner;
        use p256::ecdsa::{Signature, SigningKey};

        let mut rng = rand_08::rngs::StdRng::from_seed_helper();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let q_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let message = b"high-s malleability";
        let low_s_sig: Signature = signing_key.sign(message);
        let low_s_sig = low_s_sig.normalize_s().unwrap_or(low_s_sig);
        // Flip to high-S by negating the scalar: high-S = -low_s_sig.
        // `Signature::normalize_s` returns None when already low; calling
        // `normalize_s` on the high-S form gives back the low-S, so the
        // pair (sig, sig_minus_s) is exactly {low, high}.
        let (r_scalar, s_scalar) = low_s_sig.split_scalars();
        let high_s_scalar = -*s_scalar;
        let high_s_sig = Signature::from_scalars(r_scalar.to_bytes(), high_s_scalar.to_bytes())
            .expect("from_scalars constructs a valid high-S signature");
        assert!(
            high_s_sig.normalize_s().is_some(),
            "constructed signature must be the high-S form"
        );

        // Sanity check: the high-S signature is mathematically valid (the
        // bare ECDSA algorithm accepts both forms; only our strict-mode
        // wrapper rejects it).
        use signature::Verifier as EcdsaVerifier;
        assert!(verifying_key.verify(message, &high_s_sig).is_ok());

        let (r, s) = high_s_sig.split_bytes();
        let pub_blob =
            build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp256", b"nistp256", &q_bytes);
        let sig_blob = build_ecdsa_sig_blob(&r, &s);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(
            !verify_ssh_ecdsa(
                b"ecdsa-sha2-nistp256",
                &pub_blob,
                o,
                message,
                b"ecdsa-sha2-nistp256",
                &sig_blob,
            ),
            "high-S signature must be rejected to prevent malleability"
        );
    }

    /// TEAO1-163: the outer SSH `key_type` must equal the signature algorithm.
    /// Here the blob's key_type lies as `ecdsa-sha2-nistp256` while the embedded
    /// curve_name and sig_algo are both a self-consistent `ecdsa-sha2-nistp384`.
    /// Pre-fix this verified (the curve_name agreed with sig_algo and key_type
    /// was never consulted); the outer key_type gate must now reject it.
    #[test]
    fn verify_ssh_ecdsa_rejects_mismatched_outer_key_type() {
        use p384::ecdsa::{Signature, SigningKey};
        use signature::Signer as EcdsaSigner;

        let mut rng = rand_08::rngs::StdRng::from_seed_helper();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let q_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let message = b"mislabeled outer key_type";
        let sig: Signature = signing_key.sign(message);
        let sig = sig.normalize_s().unwrap_or(sig);
        let (r, s) = sig.split_bytes();

        // Outer key_type lies as nistp256; embedded curve + sig_algo are nistp384
        // and mutually consistent, so only the key_type gate can catch this.
        let pub_blob = build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp256", b"nistp384", &q_bytes);
        let sig_blob = build_ecdsa_sig_blob(&r, &s);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(
            !verify_ssh_ecdsa(
                b"ecdsa-sha2-nistp256", // outer key_type (the lie)
                &pub_blob,
                o,
                message,
                b"ecdsa-sha2-nistp384", // sig_algo, matches embedded curve_name
                &sig_blob,
            ),
            "mismatched outer key_type must be rejected (TEAO1-163)"
        );

        // Control: a truthful key_type==sig_algo==nistp384 blob still verifies.
        let good_blob = build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp384", b"nistp384", &q_bytes);
        let mut og = 0usize;
        let _ = read_ssh_string(&good_blob, &mut og).unwrap();
        assert!(verify_ssh_ecdsa(
            b"ecdsa-sha2-nistp384",
            &good_blob,
            og,
            message,
            b"ecdsa-sha2-nistp384",
            &sig_blob,
        ));
    }

    /// TEAO1-183: a signless high-bit `r` scalar (raw, without the mandatory
    /// `0x00` sign pad) must be rejected, so it cannot alias the canonically
    /// padded form. Control: the canonical signature still verifies.
    #[test]
    fn verify_ssh_ecdsa_rejects_signless_r_scalar() {
        use p256::ecdsa::{Signature, SigningKey};
        use signature::Signer as EcdsaSigner;

        let mut rng = rand_08::rngs::StdRng::from_seed_helper();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let q_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // Find a message whose signature's r has the high bit set (needs a pad).
        let mut message = Vec::new();
        let (r, s) = loop {
            let sig: Signature = signing_key.sign(&message);
            let sig = sig.normalize_s().unwrap_or(sig);
            let (r, s) = sig.split_bytes();
            if r[0] & 0x80 != 0 {
                break (r, s);
            }
            message.push(0u8);
        };

        let pub_blob = build_ecdsa_pubkey_blob(b"ecdsa-sha2-nistp256", b"nistp256", &q_bytes);

        // Canonical control: build_ecdsa_sig_blob writes mpint(r) with the 0x00 pad.
        let canonical = build_ecdsa_sig_blob(&r, &s);
        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(verify_ssh_ecdsa(
            b"ecdsa-sha2-nistp256",
            &pub_blob,
            o,
            &message,
            b"ecdsa-sha2-nistp256",
            &canonical
        ));

        // Alias: write r as a raw SSH string (high bit set, no 0x00 pad).
        let mut signless = Vec::new();
        write_ssh_string(&mut signless, &r);
        write_ssh_mpint(&mut signless, &s);
        let mut o2 = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o2).unwrap();
        assert!(
            !verify_ssh_ecdsa(
                b"ecdsa-sha2-nistp256",
                &pub_blob,
                o2,
                &message,
                b"ecdsa-sha2-nistp256",
                &signless
            ),
            "signless high-bit r scalar must be rejected (TEAO1-183)"
        );
    }
}
