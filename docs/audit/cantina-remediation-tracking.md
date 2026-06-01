# Cantina Audit (tea-optimism, 2025-05-27) — Remediation Matrix

Every one of the **61 findings**, its disposition, the PR that addresses it, and the fix/response. Scope basis: the 52-file Tea fork delta vs upstream Optimism `v1.16.7` (triage in `docs/audit/cantina-triage-fork-scope.md`). Disposition is one of **Addressed / Deferred / Won't-fix / Out-of-scope** — there is no "N/A" bucket.

## Status at a glance

| Status | Count | Meaning |
|---|---|---|
| ✅ Addressed | 15 | Fixed in an open PR, verified by tests |
| ⏸️ Deferred | 22 | Real; not yet implemented (needs a decision, a vendored-crate change, or a future trigger) |
| 🚫 Won't-fix | 2 | Conscious decision not to change (by design / invariant) |
| ⛔ Out of scope | 22 | Pre-existing upstream Optimism — not in the Tea fork delta, no Tea PR |
| **Total** | **61** | |

> **2026-06-01:** the former "N/A" items are re-categorized — the fault-proof findings (174/143/184/187/136/140) are **Deferred** (not applicable to the *permissioned* launch; revisit before permissionless / before a future non-zero-timestamp fork), and 138 is **Won't-fix** (design invariant). Added merged #11 and #27 to the PR map. This tracker covers the **61 Cantina findings only**; the separate 2026-05-19 precompile audit (F-1…F-8) and 2026-05-27 security audit (CR-/H-/L-) live in their own tea-infra-do docs.

## PR → findings

| PR | Findings |
|----|----------|
| #11 — read TEA/ETH multiplier in FPVM EVM (§2.1) — **MERGED** | FPVM multiplier read (predates #21's EL gate) |
| #19 — GPG `0x0696` hardening | 141, 144, 148, 160, 166, 172 |
| #20 — SSH/SSHSIG hardening | 163, 168, 183 |
| #21 — chain-gate multiplier + per-spec precompiles | 132, 145 (147 planned) |
| #22 — CGT deployer intent + bridge wiring | 139 (134 planned) |
| #23 — TeaWAP fee-math + oracle write-guards | 165, 185, 189 (138 documented) |
| #27 — mirror Tea precompiles into kona FPVM | 174 |
| #24 / #25 | build/chore — not audit findings |

---

## Master matrix — all 61 findings

Ordered by disposition, then severity. PR column links the remediation; `—` = no Tea PR (deferred-vendored or upstream).

| ID | Sev | Status | Title | PR | Response & fix |
|----|-----|--------|-------|----|----------------|
| TEAO1-132 | Critical | ✅ Addressed | kona-client replays non-Tea chains with the 1.5M× backup multiplier | #21 | Gate the multiplier on `tea_l1_cost::is_tea(chain_id)`; non-Tea chains resolve `None`. Regression test asserts `None` off a Tea chain. |
| TEAO1-145 | Critical | ✅ Addressed | TeaEvmFactory reuses the first hardfork's precompile set (`OnceLock` latch) | #21 | Removed the `OnceLock`; rebuild precompiles per spec. Test asserts FJORD≠ISTHMUS sets, both carry 0x0696-98. |
| TEAO1-141 | High | ✅ Addressed | Unverified subkey bindings let 0x0696 forge any trusted primary key | #19 | Require a valid binding signature before a subkey is an eligible signer. Test grafts an attacker subkey and asserts binding fails. |
| TEAO1-144 | High | ✅ Addressed | GPG verify doesn't bind the claimed keyId to the verifying key | #19 | Require the claimed keyId to name the key that actually verified. Test: subkey-signed sig can't claim the primary id. |
| TEAO1-160 | High | ✅ Addressed | GPG verify elevates encryption-only subkeys into signers | #19 | Filter to `key_flags().sign()` subkeys. Test discriminates signing vs non-signing subkey on a real cert. |
| TEAO1-139 | Medium | ✅ Addressed | L1CGTBridge-only intent silently strands deposits | #22 | Bridge-only intent now enters the CGT consistency check (rejected without name/symbol). Regression test on the bridge-only intent. |
| TEAO1-148 | Medium | ✅ Addressed | 0x0696 accepts Timestamp/Standalone sigs (bind only one byte) | #19 | Binary-only signature-type gate. Explicit unit test across Binary(accept)/Text/Standalone/Timestamp(reject). |
| TEAO1-163 | Medium | ✅ Addressed | SSH/SSHSIG ECDSA accept a mismatched outer key_type | #20 | Gate `key_type == sig_algo`. Test: nistp256 key_type over a self-consistent nistp384 sig is rejected. |
| TEAO1-166 | Medium | ✅ Addressed | 0x0696 text-mode signatures don't bind the exact bytes32 | #19 | Same binary-only gate. Regression test rejects a text-mode detached sig. |
| TEAO1-168 | Medium | ✅ Addressed | SSH RSA accepts signless negative mpints (key aliasing) | #20 | `strip_mpint_pad` rejects a high-bit value with no `0x00` pad. Regression test on `[0x80,…]`. |
| TEAO1-172 | Medium | ✅ Addressed | 0x0696 ignores later concatenated OpenPGP objects | #19 | Single-object parse; reject trailing objects in pubkey/sig blobs. Regression tests for both. |
| TEAO1-189 | Medium | ✅ Addressed | Non-18-dec CGT quantizes the oracle (gwei-sample floor) | #23 | Sample the oracle at full `1e18` WAD instead of GWEI. Test asserts exact rate (no floor). |
| TEAO1-165 | Low | ✅ Addressed | Plain L1Block leaves the cached slot unwritable → getL1Fee quotes 0 | #23 | `_cachedPriceOrBackup()` falls back to the backup rate on an empty slot. Test zeroes the slot, asserts backup fee. |
| TEAO1-183 | Low | ✅ Addressed | ECDSA SSH sigs accept a missing mandatory mpint sign pad | #20 | r/s routed through `strip_mpint_pad`. Regression test on a signless `r`. |
| TEAO1-185 | Low | ✅ Addressed | convertETHToTea bypasses the cached multiplier + grace | #23 | Reads cached price (+backup), not live. Test breaks the live oracle, asserts cached value returned. |
| TEAO1-174 | Critical | ⏸️ Deferred | Tea precompiles replay as empty-address calls in the kona FPVM | #27 | **N/A for the permissioned launch** — #27 makes kona's FPVM byte-match the EL off-chain (precompiles + multiplier), and permissioned games never reach an adversarial on-chain `step()`. Deferred: permissionless additionally needs the on-chain `PreimageOracle` fixed (native-in-FPVM precompiles or a forked oracle, since the L1 staticcall can't reproduce L2-only 0x0696-98). |
| TEAO1-136 | Critical | ⏸️ Deferred | op-node hardfork payloads clobber the Tea GasPriceOracle | — | **Disarmed:** all forks are genesis-active and op-node skips upgrade-tx injection for genesis-active forks (`IsEcotoneActivationBlock`). The clobber is a stock-impl bytecode swap (not a fallback reset). **GUARD:** before scheduling any future non-zero-timestamp fork, patch that fork's `*_upgrade_transactions.go` to inject Tea's `+CGT` bytecode. |
| TEAO1-140 | High | ⏸️ Deferred | Ecotone would replace L1BlockCGT with plain L1Block | — | Sibling of 136 (drops the `updateGasTokenPriceRatio()` hook). Same genesis-active disarm + future-fork guard. |
| TEAO1-143 | High | ⏸️ Deferred | Interop host re-executes Tea blocks with raw OP fees | — | Tea's fault-proof client is **kona**, not the interop host, and the launch is permissioned. Revisit for permissionless / if interop is enabled. |
| TEAO1-184 | High | ⏸️ Deferred | Go op-program bypasses Tea shared L1 fee math | — | Tea does **not** deploy the Go op-program (kona is the client). Revisit only if op-program is ever put in the fault-proof path. |
| TEAO1-187 | High | ⏸️ Deferred | Go op-program fails open on Tea claims | — | Sibling of 184; op-program is not in Tea's fault-proof path. |
| TEAO1-147 | High | ⏸️ Deferred | TEA multiplier frozen one block before the L1-attributes tx | #21 (plan) | Intra-block refresh **changes Tea output roots** and edits the vendored op-revm handler — needs product sign-off that it matches canonical tea-geth timing. |
| TEAO1-134 | Medium | ⏸️ Deferred | Fresh CGT deploys never init TeaWAPOracle → pin 1.5M backup | #22 (plan) | Needs a genesis oracle/fallback-seeding design + a genesis owner-ordering change. |
| TEAO1-167 | Medium | ⏸️ Deferred | State conditionals stop protecting Tea txs after a multiplier change | — | Fix is in vendored op-reth (`rpc`/`txpool`/`payload`); not in the Tea delta. |
| TEAO1-171 | Medium | ⏸️ Deferred | ETH-mode retry split lets deposits cash out L1 CGT backing | — | Fix is in vendored op-deployer init/apply. |
| TEAO1-170 | Low | ⏸️ Deferred | Tea wrapper keeps the default raw-Fjord receipt converter | P7 | New Tea receipt converter wired via `main.rs`. |
| TEAO1-133 | Low | ⏸️ Deferred | RPC receipts rebuild Tea L1 fees without the multiplier | P7 | Same Tea receipt converter as 170. |
| TEAO1-161 | Low | ⏸️ Deferred | Tea RPC receipts report raw Fjord L1 fees | P7 | Same Tea receipt converter as 170. |
| TEAO1-176 | Low | ⏸️ Deferred | Price-change blocks expose 3 inconsistent fee surfaces | P7 + 147 | Receipt leg = P7 converter; execution leg = the 147 fix. |
| TEAO1-152 | Low | ⏸️ Deferred | proof-history flags accepted but the stack is never installed | — | Vendored op-reth. |
| TEAO1-164 | Low | ⏸️ Deferred | eth_simulateV1 omits the L1-attributes deposit | — | Vendored op-reth/reth rpc. |
| TEAO1-175 | Low | ⏸️ Deferred | Txpool balance checks ignore Tea's multiplier | — | Vendored op-reth txpool. |
| TEAO1-178 | Low | ⏸️ Deferred | Trace replay reloads the multiplier after the L1-attributes tx | — | Vendored op-reth rpc trace path. |
| TEAO1-182 | Info | ⏸️ Deferred | Directly-deployed L1CGTBridge seizable before initialize | P6 | Lives in the separate **tea-cgt-bridge** repo. |
| TEAO1-186 | Info | ⏸️ Deferred | Txpool admits txs that can't pay the TEA-scaled L1 fee | — | Vendored op-reth txpool. |
| TEAO1-151 | Info | ⏸️ Deferred | Pooled txs never demote when fee state changes across heads | — | Vendored op-reth txpool. |
| TEAO1-181 | Info | ⏸️ Deferred | Single-chain proofs trust host-supplied rollup configs | — | Vendored kona registry / host. |
| TEAO1-138 | High | 🚫 Won't-fix | Fallback multipliers off by 10^(18−d) on non-18-decimal CGT | #23 (doc) | **By design:** Tea assumes an 18-decimal gas token; the WAD-scaled backup is correct and there's no on-chain decimals source to scale against. Documented on `BACKUP_TEA_WEI_PER_ETH`. |
| TEAO1-191 | Medium | 🚫 Won't-fix | Slot-0 packing makes hardfork GPO upgrades forget active forks | — | Won't change GPO storage layout. Safe because Tea always owns/deploys its own GPO bytecode (consistent layout); only view helpers (not consensus charging) are affected, and only on an upstream-bytecode upgrade (the 136/140 path). Follow-up: regenerate the stale `snapshots/storageLayout/GasPriceOracle.json`. |
| TEAO1-149 | Critical | ⛔ Out of scope | Isthmus withdrawals_root fail-open | — | Upstream op-reth consensus/engine; not in the Tea delta. |
| TEAO1-142 | High | ⛔ Out of scope | Interop proof accepts duplicate chain IDs in super roots | — | Upstream kona interop. |
| TEAO1-180 | High | ⛔ Out of scope | Interop host misparses 40-byte L2StateNode hints | — | Upstream kona host/mpt. |
| TEAO1-135 | Medium | ⛔ Out of scope | Kona accepts unverified L1 receipts even with `--l1-trust-rpc false` | — | Upstream kona providers. |
| TEAO1-146 | Medium | ⛔ Out of scope | Genesis retries can overwrite a valid L1 genesis | — | Upstream op-deployer apply/init. |
| TEAO1-155 | Medium | ⛔ Out of scope | use-forge bypasses deployment-target, live-broadcasts | — | Upstream op-deployer apply/forge. |
| TEAO1-169 | Medium | ⛔ Out of scope | Jovian activation wipes DAFootprintGasScalar | — | Upstream op-node derive. |
| TEAO1-177 | Medium | ⛔ Out of scope | Large-preimage challenger drops oracle coverage on restart | — | Upstream op-challenger. |
| TEAO1-179 | Medium | ⛔ Out of scope | kona-node always exposes admin_postUnsafePayload | — | Upstream kona node crates. |
| TEAO1-190 | Medium | ⛔ Out of scope | kona-node recipe ignores OP_RETH_IMAGE pin | — | Upstream kona docker recipe. |
| TEAO1-131 | Low | ⛔ Out of scope | Holocene/Jovian genesis ignore custom EIP1559DenominatorCanyon | — | Upstream op-chain-ops. |
| TEAO1-150 | Low | ⛔ Out of scope | Late CGT genesis failures can strand ERC20 deposits | — | Upstream op-deployer apply/start_block. |
| TEAO1-154 | Low | ⛔ Out of scope | Per-chain dispute-game overrides ignored on initial deploy | — | Upstream op-deployer/OPCM. |
| TEAO1-156 | Low | ⛔ Out of scope | BuildL2Genesis skips CGT bridge-state check | — | Upstream op-chain-ops genesis. |
| TEAO1-157 | Low | ⛔ Out of scope | First Jovian block wipes MinBaseFee | — | Upstream op-node system_config. |
| TEAO1-158 | Low | ⛔ Out of scope | Jovian-at-genesis ignores minBaseFee on first block | — | Upstream op-chain-ops genesis. |
| TEAO1-159 | Low | ⛔ Out of scope | Re-applying with a new gasLimit rewrites artifacts | — | Upstream op-deployer init. |
| TEAO1-162 | Low | ⛔ Out of scope | kona-node Docker recipe ignores trust-RPC env knobs | — | Upstream kona docker/docs. |
| TEAO1-173 | Low | ⛔ Out of scope | Removed L2 dev prefunds survive failed-retry recovery (dev-only) | — | Upstream op-deployer prefund. |
| TEAO1-137 | Info | ⛔ Out of scope | txinclude hardcodes the Isthmus operator-fee formula | — | Upstream op-service/txinclude. |
| TEAO1-153 | Info | ⛔ Out of scope | CombineDeployConfig ignores Eip1559DenominatorCanyon (emits 250) | — | Upstream op-deployer deploy_config. |
| TEAO1-188 | Info | ⛔ Out of scope | Interop proof path ignores message-expiry overrides | — | Upstream kona interop. |

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
