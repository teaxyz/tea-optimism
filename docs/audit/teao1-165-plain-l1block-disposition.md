# TEAO1-165 — "Plain L1Block leaves Tea's cached price slot permanently unwritable" — Disposition

**Severity:** Low · **Status:** Remediated (resolved-by-design); Apex per-PR scan flags a false positive.

## The finding

On Tea's `GasPriceOracle`, the cached price slot (`CUSTOM_GAS_TOKEN_PRICE_SLOT`) is written only by
`updateGasTokenPriceRatio()`, which is gated to `Predeploys.L1_BLOCK_ATTRIBUTES`. If a chain deploys the
**plain (upstream) `L1Block`** predeploy instead of Tea's CGT-aware variant, that predeploy never forwards
`updateGasTokenPriceRatio`, so the slot is never written and stays `0` forever.

## Why this is harmless (the fix)

The residual "unwritable slot" cannot cause a wrong fee, fund loss, or consensus issue, because the whole
TEA price machinery is **gated on the L1Block custom-gas-token flag** at both layers:

1. **Contract** — `GasPriceOracle` (proxied predeploy `0x42…000F`) gates `getL1Fee` / `getL1FeeUpperBound` /
   `convertETHToTea` on the CGT flag. **Off-CGT it returns the identity multiplier (`1e18`)**, so the oracle
   reduces to the standard OP fee and never reads the unwritten slot for a TEA-denominated value. This is
   documented in `src/L2/GasPriceOracle.sol:102-108`.
2. **Genesis** — `L2Genesis.setL1Block(useCustomGasToken)` installs the **CGT-aware `L1Block`** (`IL1BlockCGT`,
   which *does* forward `updateGasTokenPriceRatio`) on CGT chains, and the plain `L1Block` on non-CGT chains.
   So on any real Tea (CGT) deployment the slot **is** written every block by the system tx.
3. **Execution layer** — `tea-l1-cost`'s `cgt_enabled()` gate (tea-reth `evm/factory.rs`, mirrored in the kona
   FPVM client) returns **no multiplier** off-CGT, so the EL charge matches the contract quote. A non-CGT chain
   pays the standard OP L1 fee at both the contract and the EVM.

Net: **on a CGT chain the slot is written; on a non-CGT chain the slot is irrelevant because the oracle is
gated to the identity multiplier.** There is no deployment in which an unwritten slot yields a wrong fee.

## Independent verification

The v1.0.5 security audit (`docs/audit/v1.0.5-security-audit.md`, §4) reviewed this path adversarially:
- `forge inspect` confirms the GasPriceOracle storage layout (TEAO1-213) is intact.
- 70/70 contract tests pass, including `test_getL1Fee_emptyCachedSlot_usesBackup` and the CGT-gate regression
  tests, proving the off-CGT identity path and the empty-slot behavior.
- The EL/contract fee paths were checked for divergence; off-CGT both reduce to the standard OP fee.

## Why the Apex per-PR scan flags it

The Apex Fix Review Scan reviewed PR #23 (the oracle change) in isolation. The two halves that complete the
remediation — the `L2Genesis` CGT-aware `L1Block` install and the EL `cgt_enabled` gate — live in sibling PRs
(#21, #22) that were not in #23's base at scan time. Reviewed against the assembled `tea-reth` (all siblings
merged), the gate is complete and the finding does not reproduce.

## Disposition

**Remediated.** The unwritable-slot condition is reachable only on a non-CGT deployment, where it is harmless
by the identity-multiplier gate. No code change is warranted; the residual flag is a per-PR-scope artifact of
reviewing #23 without its siblings.
