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

/// Strip the leading 0x00 disambiguation byte from an SSH mpint payload.
///
/// RFC 4251 §5 prepends `0x00` to positive integers whose high bit is set so
/// they don't decode as negative. Canonical mpints have at most one leading
/// `0x00`. This strip is lenient — it removes one if present and leaves the
/// rest to `BigUint::from_bytes_be` (which ignores leading zeros). Multiple-
/// leading-zero non-canonical encodings of the same number get a slightly
/// larger post-strip length and may trip the [`MAX_RSA_MODULUS_BYTES`] gate;
/// that's safe (never tighter than canonical), just not byte-canonicalised.
pub fn strip_mpint_pad(bytes: &[u8]) -> &[u8] {
    if bytes.first() == Some(&0u8) {
        &bytes[1..]
    } else {
        bytes
    }
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

    // Strip the RFC 4251 §5 high-bit pad. RSA-N keygen always produces a
    // modulus with bit_length == N, so real RSA-4096 keys mpint-encode to
    // 513 bytes — the gate must run against the stripped 512.
    let n_unpadded = strip_mpint_pad(n_bytes);

    if n_unpadded.len() > MAX_RSA_MODULUS_BYTES {
        return false;
    }
    if n_unpadded.len() < MIN_RSA_MODULUS_BYTES {
        return false;
    }

    let e = rsa::BigUint::from_bytes_be(e_bytes);
    let n = rsa::BigUint::from_bytes_be(n_unpadded);
    let pub_key = match rsa::RsaPublicKey::new(n, e) {
        Ok(k) => k,
        Err(_) => return false,
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────── strip_mpint_pad

    #[test]
    fn strip_mpint_pad_removes_single_leading_zero() {
        assert_eq!(strip_mpint_pad(&[0x00, 0x80, 0x01]), &[0x80, 0x01]);
    }

    #[test]
    fn strip_mpint_pad_noop_when_no_leading_zero() {
        assert_eq!(strip_mpint_pad(&[0x7F, 0xFF, 0x01]), &[0x7F, 0xFF, 0x01]);
        assert_eq!(strip_mpint_pad(&[0x80, 0xFF]), &[0x80, 0xFF]);
    }

    #[test]
    fn strip_mpint_pad_strips_only_one_zero() {
        // Non-canonical multi-zero input: we leave the rest to BigUint, which
        // ignores leading zeros. The post-strip length is still trustworthy
        // for the size gate (never tighter than canonical).
        assert_eq!(strip_mpint_pad(&[0x00, 0x00, 0x80]), &[0x00, 0x80]);
    }

    #[test]
    fn strip_mpint_pad_empty_input() {
        assert_eq!(strip_mpint_pad(&[]), &[] as &[u8]);
    }

    #[test]
    fn strip_mpint_pad_lone_zero() {
        assert_eq!(strip_mpint_pad(&[0x00]), &[] as &[u8]);
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
        while start < value.len() - 1 && value[start] == 0 {
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
        n_blob.extend(std::iter::repeat(0xFFu8).take(513));
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
        n_raw.extend(std::iter::repeat(0xFFu8).take(127));
        write_ssh_mpint(&mut pub_blob, &n_raw);

        let mut o = 0usize;
        let _ = read_ssh_string(&pub_blob, &mut o).unwrap();
        assert!(!verify_ssh_rsa(
            &pub_blob,
            o,
            &[0u8; 32],
            b"rsa-sha2-256",
            &vec![0xAAu8; 128],
        ));
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
}
