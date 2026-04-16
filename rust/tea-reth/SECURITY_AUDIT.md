# Security Audit: Tea-Reth Precompiles

**Audit date:** 2026-04-15  
**Scope:** `gpg_verify.rs` (0x0696), `ssh_verify.rs` (0x0697), `factory.rs`  
**Auditor:** Claude Opus 4.6 (automated)

---

## Executive Summary

Both precompiles are well-structured with consistent patterns. The GPG precompile
is ported from a Go implementation with existing test vectors. The SSH precompile
is new and follows the same architecture. This audit identifies **3 medium**, **4 low**,
and **2 informational** findings.

---

## 1. GPG Precompile (`gpg_verify.rs` — 0x0696)

### 1.1 Input Validation

| Check | Status | Notes |
|-------|--------|-------|
| Minimum input length | **PASS** | Rejects < 128 bytes |
| ABI offset bounds checking | **PASS** | `read_dynamic_bytes` checks offset + length |
| Integer overflow in offsets | **PASS** | Uses `u64::from_be_bytes` on last 8 bytes |
| Empty pubkey/signature | **PASS** | rpgp rejects with parse errors |

### 1.2 Cryptographic Safety

**[M-01] No algorithm restriction on GPG keys**

The precompile accepts any key algorithm that rpgp supports, including:
- RSA (any key size, including weak 1024-bit)
- DSA
- ElGamal
- ECDSA (any curve)
- EdDSA (Curve25519)

**Risk:** A user could register a deliberately weak GPG key (e.g., RSA-512) and
claim it's secure. The precompile would happily verify signatures from such keys.

**Recommendation:** Consider rejecting keys below a minimum strength (e.g.,
RSA < 2048 bits). However, this changes the precompile semantics and may break
compatibility with tea-geth. Alternatively, enforce minimum key strength at the
IdentiTEA contract level.

**[L-01] Key ID is bytes8, not the full fingerprint**

The precompile matches `bytes8 keyId` against the last 8 bytes of the key
fingerprint. Key ID collisions are theoretically possible (birthday bound ~2^32
for 64-bit IDs). However, the full public key is also provided and verified,
so a collision would require forging a valid signature — this is a non-exploitable
weakness.

### 1.3 Gas Model

**[I-01] Flat base gas regardless of algorithm**

Base gas is 23,500 for both ed25519 (~100μs) and RSA-4096 (~2ms). RSA verification
is ~20x more expensive computationally. The per-byte charge above 3264 bytes
partially compensates (RSA keys are larger), but the gas model could be gamed
with large RSA keys at the kink boundary.

**Impact:** Low. The base gas of 23,500 is generous enough to cover RSA-4096
without making ed25519 prohibitively expensive. The kink at 3264 bytes plus
16 gas/byte above that provides reasonable protection against oversized inputs.

### 1.4 Error Handling

**[L-02] Parse errors return `PrecompileError::Other`, not `bytes32(0)`**

Invalid keys and signatures return errors (which revert the calling transaction)
rather than `bytes32(0)`. This is consistent with the Go implementation but means
a contract calling the precompile must handle reverts, not just check the return
value.

A wrong-message or wrong-key-for-valid-sig returns `bytes32(0)` (non-reverting).
This asymmetry is intentional (matching Go behavior) but should be documented.

### 1.5 DoS Vectors

**[M-02] Unbounded key parsing via rpgp**

The `SignedPublicKey::from_bytes()` call parses an arbitrary-length OpenPGP
packet stream. While gas limits cap execution time, a maliciously crafted
public key with many subkeys, user IDs, or signatures could cause excessive
memory allocation within the gas budget.

**Mitigation:** The per-byte gas charge above 3264 bytes provides some protection.
A 100KB input would cost 23,500 + (100,000 - 3,264) × 16 = 1,571,260 gas.
This is expensive but not prohibitive. Consider adding a hard input size cap
(e.g., 64KB) as defense-in-depth.

---

## 2. SSH Precompile (`ssh_verify.rs` — 0x0697)

### 2.1 Input Validation

| Check | Status | Notes |
|-------|--------|-------|
| Minimum input length | **PASS** | Rejects < 96 bytes |
| ABI offset bounds checking | **PASS** | Same pattern as GPG |
| SSH string length validation | **PASS** | `read_ssh_string` checks bounds |
| Ed25519 key size check | **PASS** | Requires exactly 32 bytes |
| Ed25519 sig size check | **PASS** | Requires exactly 64 bytes |
| RSA mpint parsing | **PASS** | Delegated to `BigUint::from_bytes_be` |

### 2.2 Cryptographic Safety

**[M-03] No minimum RSA key size enforcement**

Same issue as GPG precompile — any RSA key size accepted, including insecure
sizes like 512 or 1024 bits.

**Recommendation:** Reject RSA keys with modulus < 2048 bits (256 bytes). This
is a simple check: `if n_bytes.len() < 256 { return false; }`

**[L-03] ssh-rsa (SHA-1) correctly rejected**

The precompile only accepts `rsa-sha2-256` and `rsa-sha2-512` signature algorithms.
The deprecated `ssh-rsa` (which uses SHA-1) is rejected. This is correct — SHA-1
is broken for collision resistance. **PASS.**

### 2.3 Algorithm Consistency

**[PASS] Key type / signature algorithm cross-check**

The precompile dispatches on `key_type` (from the public key) and then checks
that `sig_algo` (from the signature) is consistent:
- `ssh-ed25519` key requires `ssh-ed25519` signature
- `ssh-rsa` key requires `rsa-sha2-256` or `rsa-sha2-512` signature

Mismatches return `bytes32(0)` (for ed25519) or `false` (for RSA), preventing
cross-algorithm confusion attacks.

### 2.4 Simpler than GPG — Smaller Attack Surface

The SSH precompile has a significantly smaller attack surface than GPG:
- No subkey concept (no key ID matching complexity)
- Simple wire format (uint32 length-prefixed strings) vs OpenPGP packets
- Only 3 algorithms (ed25519, rsa-sha2-256, rsa-sha2-512) vs GPG's open-ended set
- No rpgp dependency (uses ed25519-dalek + rsa directly)

### 2.5 DoS Vectors

**[L-04] RSA key construction cost**

`RsaPublicKey::new(n, e)` performs primality and validity checks internally.
With a very large modulus (e.g., 16384-bit), this could be expensive. However,
the per-byte gas charge provides proportional protection:
- 16384-bit key ≈ 2048 bytes of modulus
- Total input ≈ 2100+ bytes → well within kink, only base gas charged

**Recommendation:** Add a maximum modulus size check (e.g., 8192 bits / 1024 bytes)
to prevent abuse with unreasonably large keys.

---

## 3. Integration Audit (Both Precompiles as EVM Components)

### 3.1 Address Space

| Address | Precompile | Collision Risk |
|---------|-----------|----------------|
| 0x0696 | GPG verify | None — well above standard precompile range (0x01-0x0a) |
| 0x0697 | SSH verify | None — adjacent to GPG, no conflict |

Both addresses are in the "custom precompile" range and don't conflict with
any standard Ethereum or OP Stack precompiles.

### 3.2 Factory Registration

**[I-02] `OnceLock` caches precompiles for the first spec seen**

The `TeaPrecompiles::precompiles()` function uses `OnceLock`, which means the
precompile set is initialized once for the first `OpSpecId` and then reused for
all subsequent calls — even if the spec changes (e.g., during a hardfork).

This is the same pattern as the original code and is acceptable because:
1. Tea's custom precompiles don't change behavior across specs
2. The standard OP precompiles are also captured at this point

However, if a future hardfork adds or removes standard precompiles, the
`OnceLock` would need to be replaced with a per-spec cache.

### 3.3 Error Semantics Consistency

Both precompiles follow the same error pattern:
- Parse/validation errors → `PrecompileError::Other` (reverts calling tx)
- Valid input but failed verification → `bytes32(0)` (non-reverting)
- Valid input and valid signature → `bytes32(1)` (non-reverting)

This is consistent across both precompiles and matches the tea-geth behavior.

### 3.4 Gas Model Consistency

Both precompiles use identical gas parameters:
- Base: 23,500
- Per-byte above 3264: 16
- Kink: 3264 bytes

This consistency simplifies gas estimation for callers.

### 3.5 Cross-Precompile Attacks

**No cross-precompile attack vectors identified.** The precompiles:
- Don't share state
- Don't call each other
- Use different parsing libraries (rpgp vs ed25519-dalek/rsa)
- Accept different key formats (OpenPGP vs SSH wire format)
- A valid GPG signature cannot be replayed against the SSH precompile and vice versa

### 3.6 Side-Channel Resistance

**ed25519-dalek:** Uses constant-time operations by default. **PASS.**

**rsa crate (0.9):** Uses variable-time modular exponentiation via `num-bigint-dig`.
This is standard for RSA verification (not a secret operation — the public key is
public). **PASS.**

**rpgp:** Similar — verification is a public operation, timing doesn't leak secrets.
**PASS.**

---

## 4. Findings Summary

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| M-01 | Medium | No algorithm restriction on GPG keys | Open — enforce at IdentiTEA level |
| M-02 | Medium | Unbounded key parsing via rpgp | Open — consider input size cap |
| M-03 | Medium | No minimum RSA key size in SSH precompile | Open — add modulus length check |
| L-01 | Low | Key ID is bytes8, not full fingerprint | Accepted — non-exploitable |
| L-02 | Low | Parse errors revert, verification failures return 0 | Accepted — matches Go behavior |
| L-03 | Low | ssh-rsa (SHA-1) correctly rejected | PASS |
| L-04 | Low | RSA key construction cost | Open — consider max modulus size |
| I-01 | Info | Flat base gas regardless of algorithm | Accepted |
| I-02 | Info | OnceLock caches for first spec only | Accepted — matches original |

---

## 5. EIP Compatibility Notes

### EIP-7932 (Secondary Signature Algorithms)

EIP-7932 introduces a framework for alternative signature algorithms for Ethereum
*transactions* — it adds an algorithm registry and a SIGRECOVER precompile. It is
**not directly applicable** to Tea's precompiles, which verify signatures over
arbitrary 32-byte messages (not transaction payloads). However, if EIP-7932 is
adopted on mainnet, Tea could register its GPG and SSH algorithms in the registry
for interoperability.

### EIP-8051 (ML-DSA / Dilithium)

EIP-8051 adds post-quantum (ML-DSA) signature verification as a precompile. This
is orthogonal to Tea's precompiles. If post-quantum signing becomes relevant for
git commits (e.g., via GPG's post-quantum extensions), a separate precompile
following EIP-8051's pattern could be added.

Neither EIP is implemented in tea-optimism.

---

## 6. Recommendations

1. **Short-term:** Add a comment documenting the error semantics (revert vs bytes32(0))
   in both precompile source files, so Solidity callers know to use `try/catch` or
   low-level `staticcall`.

2. **Medium-term:** Consider adding minimum RSA key size checks to both GPG and SSH
   precompiles (2048-bit minimum). This can be a simple length check on the modulus.

3. **Long-term:** If the precompile set needs to change per-hardfork, replace the
   `OnceLock` in `TeaPrecompiles` with a `HashMap<OpSpecId, Precompiles>` or similar.
