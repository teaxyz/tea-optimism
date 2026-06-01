# Cantina Audit (tea-optimism, 2025-05-27) — Remediation Tracker

Tracks **all 61 findings** from the Cantina `tea-optimism` audit: the PR that addresses each, and whether it's **Addressed / Deferred / Won't-fix / N-A / Out-of-scope**.

Scope basis: the 52-file Tea fork delta vs upstream Optimism `v1.16.7`. Triage in `docs/audit/cantina-triage-fork-scope.md`.

## Status at a glance

| Status | Count | Meaning |
|---|---|---|
| ✅ Addressed | 15 | Fixed in an open PR (verified by tests) |
| ⏸️ Deferred | 16 | Real but needs a decision (consensus change, fork a vendored crate, or design choice) — not yet implemented |
| 🚫 Won't-fix | 1 | Conscious decision not to change |
| ⚪ N/A (documented) | 7 | Doesn't apply under Tea's invariants / launch posture; documented |
| ⛔ Out of scope | 22 | Pre-existing upstream Optimism — not in the Tea fork delta |
| **Total** | **61** | |

> **Updated 2026-06-01:** 6 fault-proof findings moved Deferred → N/A after the permissioned-launch decision (see [Update 2026-06-01](#update-2026-06-01) below). The later 2026-05-19 precompile security audit (F-1…F-8) is **not** part of these 61 — it is folded into the update section for completeness.

## PR → findings

| PR | Findings addressed |
|----|--------------------|
| #11 — read TEA/ETH multiplier in FPVM EVM (§2.1) — **MERGED** | FPVM-side multiplier read (predates #21's EL gate) |
| #19 — GPG precompile hardening | 141, 144, 148, 160, 166, 172 |
| #20 — SSH/SSHSIG precompile hardening | 163, 168, 183 |
| #21 — chain-gate multiplier + per-spec precompiles | 132, 145 |
| #22 — CGT deployer intent validation + bridge wiring | 139 |
| #23 — TeaWAP fee-math (de-quantize / cache-consistent / backup fallback) + oracle write-guard tests | 165, 185, 189 |
| #27 — mirror Tea GPG/SSH/SSHSIG precompiles into the kona FPVM | 174 (N/A under permissioned — see update) + precompile-audit F-1/F-2/F-4 |
| #24 — `build-tea-reth` recipe fix | _(not an audit finding — build infra)_ |
| #25 — `.gitignore .waaah` | _(not an audit finding — chore)_ |

---

## <a name="update-2026-06-01"></a>Update 2026-06-01 — re-disposition + precompile audit

Two changes since the 2025-05-27 triage: (1) mainnet launches with the **permissioned** dispute game and **kona** (not the Go op-program) as the fault-proof client — which makes the deferred fault-proof findings N/A for launch; (2) a separate **2026-05-19 precompile security audit** (tea-infra-do `docs/audits/tea-reth-precompiles-2026-05-19.md`) surfaced findings outside the Cantina 61.

**Re-dispositioned Deferred → N/A (6):**

| ID | New status | Rationale |
|----|-----------|-----------|
| TEAO1-174 | ⚪ N/A (permissioned) | #27 makes kona's FPVM byte-match the EL off-chain (GPG/SSH/SSHSIG + multiplier). Under the permissioned dispute game the on-chain `step()` is never adversarially reached and op-challenger uses the rollup provider, not kona. **Permissionless prerequisite (separate, not gating launch):** the on-chain `PreimageOracle` validates precompile preimages via an L1 `staticcall`, which cannot reproduce Tea's L2-only `0x0696`-`0x0698` — so permissionless additionally needs native-in-FPVM precompiles or a forked oracle (tea-infra-do `how-to/dispute-game-prestate-upgrade.md` §9). |
| TEAO1-143 | ⚪ N/A (permissioned) | Interop host re-execution. Tea's fault-proof client is **kona** (the registered prestate is kona-client), not the interop host; permissioned games don't reach the adversarial step. Revisit with the permissionless prerequisite. |
| TEAO1-184 | ⚪ N/A (permissioned) | Go `op-program` bypasses Tea fee math — but Tea does **not** deploy op-program; kona is the client. |
| TEAO1-187 | ⚪ N/A (permissioned) | Go `op-program` fails open — same as 184 (op-program not in Tea's fault-proof path). |
| TEAO1-136 | ⚪ N/A while genesis-active — **guarded** | The clobber is op-node injecting **stock GPO/L1Block implementation bytecode** (an impl swap via `upgradeTo`, *not* a fallback-storage reset) at a fork-**activation** block. Tea mainnet has every fork at `time:0`; op-node does not inject upgrade txs for genesis-active forks (`IsEcotoneActivationBlock` — "activation at genesis does not count"), so it never fires. **GUARD:** any future fork scheduled at a non-zero timestamp MUST first patch that fork's `*_upgrade_transactions.go` to inject Tea's `+CGT` bytecode. |
| TEAO1-140 | ⚪ N/A while genesis-active — **guarded** | Sibling of 136 (Ecotone would replace `L1BlockCGT` with stock `L1Block`, dropping the `updateGasTokenPriceRatio()` hook). Same genesis-active disarm + future-fork guard. |

**Precompile audit (2026-05-19) — outside the Cantina 61, tracked here for completeness:**

| F | Sev | Status |
|---|-----|--------|
| F-1 GPG `0x0696` ABI-decoder panic → consensus halt | Critical | ✅ **Fixed** in #27 (`d84f9e39b3`). Was live on the mainnet EL; empirically reproduced, hardened (checked_add / upper-24 reject / try_from) + regression-tested. |
| F-2 ECDSA compressed-key aliasing | Medium | ✅ Fixed in #27 (uncompressed-SEC1 gate). |
| F-4 `gpg_required_gas` overflow | Low | ✅ Fixed in #27 (saturating). |
| F-3 GPG `Err` vs `bytes32(0)` | Low | 🚫 Won't-fix (FPVM stubs depend on the `Err`-propagation convention). |
| F-8 GPG missing byte caps | Info | 🚫 Won't-do (uncappable — a real multi-subkey key fixture is 9504 bytes; already bounded by `input.len()` + pgp parser). |
| F-5 / F-6 / F-7 | Info | Open (cosmetic / future gas-sizing). |

⚠️ **Deployment dependency:** because F-1/F-2 change EL precompile behavior, merging #27 requires an **EL (tea-reth) fleet redeploy in lockstep with the new FPVM prestate** so EL ≡ kona-host ≡ FPVM.

---

## ✅ Addressed (15) — in an open PR, tests passing

| ID | Sev | Title | PR |
|----|-----|-------|----|
| TEAO1-132 | Critical | Generic kona-client replays non-Tea chains with the 1.5Mx backup multiplier (factory not chain-gated) | #21 |
| TEAO1-145 | Critical | TeaEvmFactory permanently reuses the first hardfork's precompile set | #21 |
| TEAO1-141 | High | Unverified OpenPGP subkey bindings let 0x0696 forge any trusted primary key | #19 |
| TEAO1-144 | High | GPG verify does not bind the claimed keyId to the key that verified | #19 |
| TEAO1-160 | High | GPG verify elevates encryption-only RSA subkeys into signing authorities | #19 |
| TEAO1-139 | Medium | L1CGTBridge-only intents silently deploy a no-bridge L2 and strand deposits | #22 |
| TEAO1-148 | Medium | 0x0696 accepts Timestamp/Standalone sigs binding only one byte | #19 |
| TEAO1-163 | Medium | SSH/SSHSIG ECDSA accept mismatched SSH key_type prefixes | #20 |
| TEAO1-166 | Medium | 0x0696 text-mode signatures don't bind the exact bytes32 | #19 |
| TEAO1-168 | Medium | SSH RSA accepts signless negative mpints (key aliasing) | #20 |
| TEAO1-172 | Medium | 0x0696 ignores later concatenated OpenPGP objects in pubkey/sig blobs | #19 |
| TEAO1-189 | Medium | Non-18-decimal CGT quantizes TeaWAPOracle into fee undercharges (gwei-sample floor) | #23 |
| TEAO1-165 | Low | Plain L1Block deployments leave the cached price slot unwritable → getL1Fee quotes 0 | #23 |
| TEAO1-183 | Low | ECDSA SSH sigs accept missing mandatory mpint sign pads | #20 |
| TEAO1-185 | Low | convertETHToTea bypasses the cached multiplier + 5-min oracle grace | #23 |

---

## ⏸️ Deferred (22) — real, needs a decision before implementing

### Tea-code fixes awaiting a decision (7)
| ID | Sev | Title | Planned | Why deferred |
|----|-----|-------|---------|--------------|
| TEAO1-147 | High | TEA multiplier frozen before the block's L1-attributes tx (one block late) | #21 (plan) | Intra-block refresh **changes Tea output roots** + edits vendored op-revm consensus handler — needs product sign-off it matches canonical tea-geth timing |
| TEAO1-134 | Medium | Fresh CGT deployments never init TeaWAPOracle → pin 1.5M backup rate | #22 (plan) | Genesis oracle/fallback seeding: full Velodrome-oracle vs fallback-only, + a genesis owner-ordering change |
| TEAO1-170 | Low | Tea wrapper keeps the default raw-Fjord receipt converter | P7 | New Tea receipt converter wired via `main.rs` |
| TEAO1-133 | Low | RPC receipts rebuild Tea L1 fees without the multiplier | P7 | Same Tea receipt converter as 170 |
| TEAO1-161 | Low | Tea RPC receipts report raw Fjord L1 fees | P7 | Same Tea receipt converter as 170 |
| TEAO1-176 | Low | Price-change blocks expose 3 inconsistent Tea L1 fee surfaces | P7 + 147 | Receipt leg = P7 converter; execution leg = the 147 fix |
| TEAO1-182 | Info | Directly deployed L1CGTBridge can be seized before first initialize | P6 | Lives in the **tea-cgt-bridge** repo → separate PR there |

### Borderline — exposure is Tea-created but the fix touches a vendored/unforked crate (15)
| ID | Sev | Title | Fix site (unforked) |
|----|-----|-------|---------------------|
| TEAO1-174 | Critical | Tea precompiles execute on tea-reth but replay as empty-address calls in Kona FPVM | kona `fpvm_evm/precompiles/provider.rs` — **EL↔FPVM divergence; highest-priority** |
| TEAO1-136 | Critical | op-node hardfork payloads freeze TEA fee pricing (clobber Tea GasPriceOracle) | op-node `*_upgrade_transactions.go` (Tea-aware bytecode) |
| TEAO1-140 | High | Ecotone upgrade replaces L1BlockCGT with plain L1Block | op-node upgrade bytecode (sibling of 136) |
| TEAO1-143 | High | Interop host re-executes optimistic Tea blocks with raw OP fees | kona `bin/host/src/interop/*` |
| TEAO1-184 | High | Go fault-proof program bypasses Tea shared L1 fee math | op-program `client/*` |
| TEAO1-187 | High | Go fault-proof program fails open on Tea claims | op-program `client/*` (sibling of 184) |
| TEAO1-167 | Medium | State conditionals stop protecting Tea txs once the multiplier changes | op-reth `crates/{rpc,txpool,payload}` |
| TEAO1-171 | Medium | ETH-mode retry split lets portal deposits cash out honest L1 CGT backing | op-deployer init/apply (unforked) |
| TEAO1-152 | Low | tea-reth accepts proof-history flags but never installs the stack | op-reth `node/src/proof_history.rs` |
| TEAO1-164 | Low | eth_simulateV1 omits the mandatory L1-attributes deposit | op-reth/reth `crates/rpc` |
| TEAO1-175 | Low | Txpool balance checks ignore Tea's multiplier | op-reth `txpool/src/validator.rs` |
| TEAO1-178 | Low | Transaction trace replay reloads the multiplier after the L1-attributes tx | op-reth `crates/rpc` trace path |
| TEAO1-186 | Info | Txpool admits txs that can't pay the TEA-scaled L1 fee | op-reth `txpool/src/validator.rs` |
| TEAO1-151 | Info | Pooled txs never demote when OP/Tea fee state changes across heads | op-reth `txpool/**` |
| TEAO1-181 | Info | Tea single-chain proofs trust host-supplied rollup configs | kona registry / `bin/host/single/**` |

---

## 🚫 Won't-fix (1)

| ID | Sev | Title | Decision |
|----|-----|-------|----------|
| TEAO1-191 | Medium | Tea slot-0 packing makes hardfork GPO upgrades forget active forks | Won't change GasPriceOracle storage layout. Safe because **Tea always owns/deploys its own GPO bytecode** (consistent layout end-to-end); only the contract view helpers (not consensus charging) would be affected, and only on an upstream-bytecode upgrade (the 136/140 path). _Follow-up: regenerate the stale `snapshots/storageLayout/GasPriceOracle.json` to reflect the real Tea layout._ |

## ⚪ N/A — documented invariant (1)

| ID | Sev | Title | Disposition |
|----|-----|-------|-------------|
| TEAO1-138 | High | Fallback/backup multipliers off by 10^(18−d) on non-18-decimal CGT | Tea assumes an **18-decimal** gas token (like ETH); the WAD-scaled backup is correct and there's no on-chain decimals source to scale against. Documented on `BACKUP_TEA_WEI_PER_ETH` in #23. |

---

## ⛔ Out of scope — pre-existing upstream Optimism (22)

Not in the Tea fork delta; rooted in vendored/upstream code Tea never modified. Listed for completeness — no Tea PR.

| ID | Sev | Title |
|----|-----|-------|
| TEAO1-149 | Critical | Isthmus withdrawals_root fail-open (op-reth consensus/engine) |
| TEAO1-142 | High | Interop proof accepts duplicate chain IDs in super roots (kona interop) |
| TEAO1-180 | High | Interop host misparses 40-byte L2StateNode hints (kona host/mpt) |
| TEAO1-135 | Medium | Kona accepts unverified L1 receipts even with `--l1-trust-rpc false` (kona providers) |
| TEAO1-146 | Medium | Genesis retries can overwrite a valid L1 genesis (op-deployer apply/init) |
| TEAO1-155 | Medium | use-forge bypasses deployment-target, live-broadcasts (op-deployer apply/forge) |
| TEAO1-169 | Medium | Jovian activation wipes DAFootprintGasScalar (op-node derive) |
| TEAO1-177 | Medium | Large-preimage challenger drops oracle coverage on restart (op-challenger) |
| TEAO1-179 | Medium | kona-node always exposes admin_postUnsafePayload (kona node crates) |
| TEAO1-190 | Medium | kona-node recipe ignores OP_RETH_IMAGE pin (kona docker recipe) |
| TEAO1-131 | Low | Holocene/Jovian genesis ignore custom EIP1559DenominatorCanyon (op-chain-ops) |
| TEAO1-150 | Low | Late CGT genesis failures can strand ERC20 deposits (op-deployer apply/start_block) |
| TEAO1-154 | Low | Per-chain dispute-game overrides ignored on initial deploy (op-deployer/OPCM) |
| TEAO1-156 | Low | BuildL2Genesis skips CGT bridge-state check (op-chain-ops genesis) |
| TEAO1-157 | Low | First Jovian block wipes MinBaseFee (op-node system_config) |
| TEAO1-158 | Low | Jovian-at-genesis ignores minBaseFee on first block (op-chain-ops genesis) |
| TEAO1-159 | Low | Re-applying with new gasLimit rewrites artifacts (op-deployer init) |
| TEAO1-162 | Low | kona-node Docker recipe ignores trust-RPC env knobs (kona docker/docs) |
| TEAO1-173 | Low | Removed L2 dev prefunds survive failed-retry recovery (op-deployer prefund; dev-only) |
| TEAO1-137 | Info | txinclude hardcodes Isthmus operator-fee formula (op-service/txinclude) |
| TEAO1-153 | Info | CombineDeployConfig ignores Eip1559DenominatorCanyon, emits 250 (op-deployer deploy_config) |
| TEAO1-188 | Info | Interop proof path ignores message-expiry overrides (kona interop) |

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
