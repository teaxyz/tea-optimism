# Cantina Audit — Fork-Scope Triage (First Pass)

**Source:** [`cantina-audit-25-05-27.md`](cantina-audit-25-05-27.md) — 61 findings.
**Scope basis:** the 52-file Tea fork delta vs upstream Optimism `v1.16.7` (`git diff 3019251e80..HEAD`), saved at `.waaah/ralph/001-cantina-scope-triage/scope_files.txt`.
**Question answered per finding:** *does the root cause AND a natural fix land in a file Tea actually modified?*

## Scope definition

**IN scope — files Tea modified:**
- `rust/tea-reth/**` (new crate: precompiles `gpg_verify`/`ssh_verify`/`ssh_sig_verify`/`ssh_common`, `evm/factory.rs`, `main.rs`, `chainspec.rs`, `l1_cost.rs`)
- `rust/tea-l1-cost/**` (new crate)
- `rust/patches/op-revm-l1-cost-multiplier.patch`
- `rust/kona/bin/client/src/fpvm_evm/factory.rs` **(only this file in kona)** + `tests/cross_executor_l1_cost_parity.rs`
- `rust/op-reth/crates/evm/src/lib.rs` **(only this file in op-reth)**
- `packages/contracts-bedrock/src/L2/{GasPriceOracle,L1Block,L1BlockCGT,TeaWAPOracle}.sol`, `interfaces/L2/{IGasPriceOracle,IVelodromePool}.sol`, `scripts/L2Genesis.s.sol`, `scripts/deploy/DeployConfig.s.sol`, `lib/tea-cgt-bridge/**`, related tests + `foundry.toml`
- `op-deployer/pkg/deployer/{opcm/l2genesis.go, pipeline/l2genesis.go, state/chain_intent.go}` **(only these 3 go files)**
- `README.md`, `rust/{Cargo.toml,Cargo.lock,justfile}`, `rust/vendor/.gitignore`, `op-rbuilder` (deleted)

**OUT of scope — vendored / upstream Optimism Tea never touched:** all of `rust/op-reth/` except `crates/evm/src/lib.rs`; all of `rust/kona/` except the one client factory + parity test; all `op-node`/`op-program`/`op-challenger`/`op-service`/`op-chain-ops`/`op-acceptance-tests`; any `op-deployer` file outside the 3 above; upstream contracts (`OptimismPortal2`, `OPContractsManager`, `L1StandardBridge`, `WETH98`, `CrossDomainMessenger`, `StandardBridge`, etc.).

## Verdict legend

- **KEEP** — root cause and a natural fix are inside Tea-modified files. **Tea should fix these.**
- **BORDERLINE** — Tea's diff *creates* the exposure, but the natural fix touches a vendored op-reth/kona/op-program file Tea hasn't forked (or a sealed op-deployer path). **Needs a decision: fork the vendored file vs ship a tea-side shim vs accept.**
- **EJECT** — defect and fix live entirely in vendored/upstream code Tea never modified. **Pre-existing Optimism issue — "does not apply / do not fix" for our fork.** ← *these are the ones you wanted to review manually.*

## Tally

| Verdict | Critical | High | Medium | Low | Info | Total |
|---|---|---|---|---|---|---|
| **KEEP** | 2 | 5 | 9 | 7 | 1 | **24** |
| **BORDERLINE** | 2 | 4 | 2 | 4 | 3 | **15** |
| **EJECT** | 1 | 2 | 7 | 9 | 3 | **22** |
| Total | 5 | 11 | 18 | 20 | 7 | **61** |

> **Revised after adversarial re-audit (iter 1):** 133 & 161 BORDERLINE→KEEP (same Tea receipt-converter fix as 170); 187 EJECT→BORDERLINE (identical class to 184); 181 EJECT→BORDERLINE (Tea's absence from Kona's registry is the trigger). **(iter 2):** 176 BORDERLINE→KEEP — all three of its fee surfaces are Tea-controlled. **(iter 3):** 140 EJECT→BORDERLINE — identical mechanism to 136 (op-node hardfork bytecode clobbers a Tea custom predeploy).

---

## KEEP — fix in Tea-owned files (24)

| ID | Sev | Title | Fix lands in | Why in-scope |
|----|-----|-------|--------------|--------------|
| TEAO1-132 | Critical | Generic kona-client replays non-Tea chains with Tea's 1.5Mx backup multiplier (factory not chain-gated) | `kona/.../fpvm_evm/factory.rs`, `tea-reth/.../evm/factory.rs`, `tea-l1-cost/src/lib.rs` | Unconditional multiplier install + zero-slot 1.5M×WAD fallback are Tea code; chain-gating lands in those files. |
| TEAO1-145 | Critical | TeaEvmFactory permanently reuses first hardfork's precompile set | `tea-reth/src/evm/factory.rs` | Process-global `OnceLock<Precompiles>` latches first `OpSpecId`; rebuild-per-spec fix is self-contained. |
| TEAO1-138 | High | Fallback/backup multipliers off by 10^(18−d) on non-18-decimal CGT | `TeaWAPOracle.sol`, `GasPriceOracle.sol`, `tea-l1-cost/src/lib.rs` | Hardcoded `1e18`-scaled constants ignore CGT decimals; decimal-aware scaling is in Tea files. |
| TEAO1-141 | High | Unverified OpenPGP subkey bindings let 0x0696 forge any trusted primary key | `tea-reth/.../gpg_verify.rs` | Membership gate + `primary‖any_subkey` accept logic is Tea's; authenticate bindings before iterating. |
| TEAO1-144 | High | GPG verify does not bind claimed keyId to the key that actually verified | `tea-reth/.../gpg_verify.rs` | Self-contained: bind verifying key to claimed keyId. |
| TEAO1-147 | High | TEA multiplier frozen before block's L1-attributes tx (updates apply one block late) | `tea-reth/.../evm/factory.rs`, `kona/.../fpvm_evm/factory.rs`, `op-revm` patch | Pre-exec snapshot + stale-multiplier preservation in the patch are all Tea-authored. |
| TEAO1-160 | High | GPG verify elevates encryption-only RSA subkeys into signing authorities | `tea-reth/.../gpg_verify.rs` | Filter subkeys by signing key-flags before verify — Tea code. |
| TEAO1-134 | Medium | Fresh CGT deployments never init TeaWAPOracle, pin 1.5M backup rate | `chain_intent.go`, `pipeline/l2genesis.go`, `L2Genesis.s.sol`, `TeaWAPOracle.sol`, `GasPriceOracle.sol` | Whole CGT genesis-seeding path is Tea's; carry oracle fields + seed slots (or fail closed). |
| TEAO1-139 | Medium | L1CGTBridge-only intents silently deploy a no-bridge L2 and strand deposits | `chain_intent.go` (+ `pipeline/l2genesis.go`, `tea-cgt-bridge/**`) | Validation gap in Tea's `ChainIntent.Check()`; require full CGT tuple. |
| TEAO1-148 | Medium | 0x0696 accepts Timestamp/Standalone sigs binding only one byte | `tea-reth/.../gpg_verify.rs` | Reject non-Binary signature classes before verify. |
| TEAO1-163 | Medium | SSH/SSHSIG ECDSA accept mismatched SSH key_type prefixes | `tea-reth/.../{ssh_common,ssh_verify,ssh_sig_verify}.rs` | Thread `key_type` into `verify_ssh_ecdsa` and enforce equality. |
| TEAO1-166 | Medium | 0x0696 text-mode signatures don't bind exact bytes32 | `tea-reth/.../gpg_verify.rs` | Reject `Text` signature type / enforce exact binding. |
| TEAO1-168 | Medium | SSH RSA accepts signless negative mpints (key aliasing) | `tea-reth/.../ssh_common.rs` | Tighten `strip_mpint_pad()` to reject missing-sign-pad high-bit mpints. |
| TEAO1-172 | Medium | 0x0696 ignores later concatenated OpenPGP objects in pubkey/sig blobs | `tea-reth/.../gpg_verify.rs` | Reject trailing objects at Tea's `from_bytes` call site. |
| TEAO1-189 | Medium | Non-18-decimal CGT quantizes TeaWAPOracle into network-wide fee undercharges | `TeaWAPOracle.sol` (+ `tea-cgt-bridge/**`) | `teaPerETH()` samples only `1e9` WETH; fix sampling precision. |
| TEAO1-191 | Medium | Tea slot-0 packing makes hardfork GPO upgrades forget active forks | `GasPriceOracle.sol`, `TeaWAPOracle.sol` | `GasPriceOracle is TeaWAPOracle` shifts upstream fork flags; move `owner` to unstructured slot. |
| TEAO1-165 | Low | Plain L1Block deployments leave Tea's cached price slot permanently unwritable | `L2Genesis.s.sol` (+ `GasPriceOracle.sol`, `L1BlockCGT.sol`) | Gate Tea oracle on CGT mode / add authorized non-CGT update path. |
| TEAO1-170 | Low | Tea wrapper keeps default raw-Fjord receipt converter on every receipt path | `tea-reth/src/main.rs` | Recommendation is exactly "wire a Tea-specific converter from tea-reth" — new code in Tea crate via `with_add_ons`. |
| TEAO1-133 | Low | RPC receipts rebuild Tea L1 fees without the multiplier | `tea-reth/src/main.rs` (Tea-owned receipt converter) | Same receipt surface as 170; a Tea converter re-reading the oracle slot + `tea_l1_cost::multiplier_from_oracle_value()` closes it without forking op-reth. *(was BORDERLINE)* |
| TEAO1-161 | Low | Tea RPC receipts report raw Fjord L1 fees | `tea-reth/src/main.rs` (Tea-owned receipt converter) | Identical to 170/133 — wire `tea_l1_cost::apply_tea_exchange_rate()` into the converter via the add-ons builder. *(was BORDERLINE)* |
| TEAO1-176 | Low | Price-change blocks expose 3 mutually inconsistent Tea L1 fee surfaces | `tea-reth/.../evm/factory.rs` + `op-revm` patch (execution) **and** `tea-reth/src/main.rs` (receipt converter) | All 3 surfaces are Tea-controlled: refresh execution multiplier after the L1-attributes deposit (= the 147 fix) + hydrate the multiplier in the Tea receipt converter (= the 170 fix); `GasPriceOracle.getL1Fee()` is already a Tea contract. Recommendation's both options land in Tea files. *(was BORDERLINE)* |
| TEAO1-183 | Low | ECDSA SSH sigs accept missing mandatory mpint sign pads | `tea-reth/.../ssh_common.rs` | One-line fix in Tea's `strip_mpint_pad`. |
| TEAO1-185 | Low | convertETHToTea bypasses cached multiplier + 5-min oracle grace | `TeaWAPOracle.sol`, `GasPriceOracle.sol` | Tea function; read cached/grace-governed price like execution does. |
| TEAO1-182 | Info | Directly deployed L1CGTBridge can be seized before first initialize | `tea-cgt-bridge/src/L1/L1CGTBridge.sol` | `_disableInitializers()` / atomic factory init in Tea submodule. |

---

## BORDERLINE — Tea creates the exposure, natural fix touches unforked vendored code (15)

> These are real Tea-introduced risks. Closing each means either (a) forking the named vendored file, (b) shipping a tea-reth-side shim, or (c) accepting the risk. **Decide per finding.**

| ID | Sev | Title | Exposure (Tea) | Natural fix site (out of scope) |
|----|-----|-------|----------------|----------------------------------|
| TEAO1-174 | Critical | Tea precompiles execute on tea-reth but replay as empty-address calls in Kona FPVM | precompiles added in `tea-reth` | `kona/.../fpvm_evm/precompiles/provider.rs` (`OpFpvmPrecompiles`) must host them, or a tea-side FPVM precompile provider. **Highest-priority borderline — consensus/output-root divergence.** |
| TEAO1-136 | Critical | Upstream GasPriceOracle hardfork payloads permanently freeze TEA fee pricing | Tea's `GasPriceOracle.sol`/`TeaWAPOracle.sol` carry the fee-refresh surface | `op-node/rollup/derive/ecotone_upgrade_transactions.go` bakes upstream OP bytecode that omits it; fix = bake Tea-aware upgrade payloads (fork the op-node Go). |
| TEAO1-140 | High | Ecotone upgrade replaces L1BlockCGT with plain L1Block, shuts off CGT fee updates | Tea's `L1BlockCGT.sol` custom predeploy | **Same mechanism as 136** (sibling): op-node etches upstream `L1Block`/`GasPriceOracle` bytecode over Tea's CGT predeploys at the fork boundary; exposure exists only because Tea deployed custom predeploys. Fix = Tea-aware upgrade bytecode in `op-node/rollup/derive/` (Tea hasn't forked op-node). *(was EJECT)* |
| TEAO1-143 | High | Interop host re-executes optimistic Tea blocks with raw OP fees | multiplier only in client `FpvmOpEvmFactory` | `kona/bin/host/src/interop/{handler,cfg}.rs` needs a Tea-aware factory. |
| TEAO1-184 | High | Go fault-proof program bypasses Tea shared L1 fee math | multiplier only in Rust EL/FPVM | `op-program/client/...` Go fault-proof executor uses raw op-geth fees. |
| TEAO1-187 | High | Go fault-proof program fails open on Tea claims | Tea precompiles + fee math only in Rust EL/FPVM | `op-program/client/{program.go, l2/engineapi/*}` Go executor lacks Tea semantics; same class as 184 — add a Tea chain-gate / port semantics into the Go backend. *(was EJECT)* |
| TEAO1-167 | Medium | State-based conditionals stop protecting Tea txs once oracle multiplier changes | `L1BlockCGT`-driven mid-block slot change | `op-reth/crates/{rpc,txpool,payload}` must revalidate `knownAccounts`. |
| TEAO1-171 | Medium | ETH-mode retry split lets portal deposits cash out honest L1 CGT backing | Tea CGT mode mutable across retries | clean fix in `op-deployer/.../{apply,opchain,init}.go`; partial guard possible in `chain_intent.go` / `L2CGTBridge.sol`. |
| TEAO1-152 | Low | tea-reth accepts proof-history flags but never installs the stack | `main.rs` ignores the flag | `op-reth/.../proof_history.rs` hardcodes plain OpNode; can fail-closed in-scope. |
| TEAO1-164 | Low | eth_simulateV1 omits the mandatory L1-attributes deposit | per-block fee snapshotting | `op-reth`/reth `crates/rpc/**` simulate path. |
| TEAO1-175 | Low | Txpool balance checks ignore Tea's multiplier (mempool admit/execute gap) | `op-revm` patch multiplier | `op-reth/crates/txpool/src/validator.rs`. |
| TEAO1-178 | Low | Transaction trace replay reloads Tea's multiplier after L1-attributes tx | per-block snapshot in `evm/factory.rs` | `op-reth/crates/rpc/**` tracer rebuilds fresh EVM. |
| TEAO1-186 | Info | Tea txpool balance checks admit txs that can't pay TEA-scaled L1 fee | multiplier injection | `op-reth/crates/txpool/src/validator.rs` (helper exists in `tea-l1-cost`). |
| TEAO1-151 | Info | Pooled txs never demote when OP/Tea fee state changes across heads | multiplier widens stale-affordability gap | `op-reth/crates/txpool/**` reclassification state machine. |
| TEAO1-181 | Info | Tea single-chain proofs trust host-supplied rollup configs | Tea chain not compiled into Kona's registry → host-config fallback | primary fix is Tea-owned (ship Tea's rollup config in Kona's registry / reproducible custom-config prestate build); immediate code site is unforked `kona/bin/host/src/single/**`. *(was EJECT)* |

---

## EJECT — pre-existing Optimism / does not apply to our fork (22)

> **These are the proposals to review manually.** Each is rooted in vendored/upstream code Tea never modified. The **Why ejected** column states the concrete reason it does not apply to our PR-diff scope.

| ID | Sev | Title | Out-of-scope fix site | Why ejected |
|----|-----|-------|------------------------|-------------|
| TEAO1-149 | Critical | Isthmus withdrawals_root fail-open lets tea-reth accept blocks Kona replays differently | `op-reth/crates/{node/src/engine.rs, consensus/src/lib.rs}` | The fail-open `return Ok(())` is pre-existing upstream op-reth consensus/engine behavior, Tea-agnostic. Tea only forked `op-reth/crates/evm/src/lib.rs` (a trait-bound tweak); the validation path is sealed vendored code. |
| TEAO1-142 | High | Interop proof accepts duplicate chain IDs in decoded super roots | `kona/crates/protocol/interop/src/root.rs`, `crates/proof/proof-interop/**` | Missing structural validation in `SuperRoot::decode` — entirely vendored kona interop crates. Tea's only kona file is the client EVM factory; unrelated. Tea doesn't run interop. |
| TEAO1-180 | High | Interop host misparses 40-byte L2StateNode hints, wedges trie preimage fetches | `kona/bin/host/src/interop/handler.rs`, `crates/proof/mpt/src/node.rs` | `try_into()` over the wrong buffer slice + infinite retry are pre-existing kona interop-host bugs in vendored code Tea never touched. |
| TEAO1-135 | Medium | Kona accepts unverified L1 receipts even with `--l1-trust-rpc false` | `kona/crates/{providers/providers-alloy, protocol/derive}/**` | Receipt-trust enforcement gap lives in vendored kona provider/derive crates. Tea forked none of them; pre-existing upstream kona issue. |
| TEAO1-146 | Medium | Genesis retries can overwrite a valid L1 genesis with an empty host | `op-deployer/.../{apply.go, pipeline/init.go, state/*}` | The resume/reseal logic (empty `DefaultScriptHost`, skip gates) is in op-deployer files Tea did NOT fork. Tea touched only `l2genesis.go`×2 + `chain_intent.go`; the `l2genesis.go` skip gate is incidental, not the root cause. |
| TEAO1-155 | Medium | use-forge bypasses noop/calldata deployment-target, live-broadcasts CGT deploys | `op-deployer/.../{apply.go, opcm/forge_env.go}` | The `--use-forge`-always-broadcasts branch is in upstream deployer backend files Tea never forked. `chain_intent.go` merely carries CGT config; it is not where the broadcast decision is made. |
| TEAO1-169 | Medium | Jovian activation wipes preconfigured DAFootprintGasScalar, falls back to 400 | `op-node/rollup/derive/` SystemConfig reconstruction | The reconstruction/fallback is upstream op-node Go derivation logic, unmodified by Tea. |
| TEAO1-177 | Medium | Large-preimage challenger drops old oracle coverage across hotfix restarts | `op-challenger/game/**`, upstream OPCM/DeployImplementations | Defect + fix are in upstream `op-challenger` Go and upstream L1 contracts. Tea modified none of these; Tea does not operate the challenger today. |
| TEAO1-179 | Medium | kona-node always exposes admin_postUnsafePayload to public RPC | `kona/crates/node/{...rpc/actor.rs, rpc/src/admin.rs}`, `bin/node/.../rpc.rs` | Unconditional admin-RPC registration is in vendored kona node crates/binary Tea never forked; pre-existing upstream kona issue. |
| TEAO1-190 | Medium | kona-node recipe ignores documented OP_RETH_IMAGE pin, boots generic op-reth | `kona/docker/recipes/kona-node/**` | Env-var mismatch is entirely in vendored kona Docker recipe files (not in Tea's 52-file delta); pre-existing packaging bug. |
| TEAO1-131 | Low | Holocene/Jovian genesis ignore custom EIP1559DenominatorCanyon on block 1 | `op-chain-ops/genesis/genesis.go` extraData encoding | Hardcoded `250` in upstream Go `extraData` encoding; `op-chain-ops` is unmodified upstream. No Tea file is the fix site. |
| TEAO1-150 | Low | Late CGT genesis failures can strand ERC20 bridge deposits | `op-deployer/.../{apply.go, pipeline/start_block.go}`; upstream `L1StandardBridge.sol` | The orchestration defect (preflight genesis / pin start block before broadcasting) is in upstream pipeline files Tea did not fork. The CGT init-failure is only an example trigger, not the locus of the fix. |
| TEAO1-154 | Low | Per-chain dispute-game depth/clock overrides ignored on initial deployment | `op-deployer/.../opcm/opchain.go`, upstream OPCM/DeployImplementations/DeployOPChain | The shared impl is fixed from globals at DeployImplementations time — all upstream OPCM/deployer code. Tea's `DeployConfig.s.sol` only reads the values; it isn't where overrides are dropped. |
| TEAO1-156 | Low | BuildL2Genesis exports valid genesis without checking CGT bridge state | `op-chain-ops/genesis/layer_two.go`, `op-deployer/.../inspect/genesis.go` | The recommended integrity check belongs in `BuildL2Genesis()` in upstream `op-chain-ops/genesis`, unmodified by Tea. CGT is Tea's, but the sink for the check is not a Tea file. |
| TEAO1-157 | Low | First Jovian block wipes preconfigured MinBaseFee to zero | `op-node/rollup/derive/system_config.go` | The SystemConfig reconstruction at Jovian activation is upstream op-node Go; Tea never touched it. |
| TEAO1-158 | Low | Jovian-at-genesis deployments ignore configured minBaseFee on first block | `op-chain-ops/genesis/{genesis,config}.go` | The hardcoded `EncodeJovianExtraData(250,6,0)` genesis constant is upstream Go in `op-chain-ops`, unmodified by Tea. |
| TEAO1-159 | Low | Re-applying with new gasLimit rewrites genesis/rollup/prestate artifacts | `op-deployer/.../pipeline/init.go` | The immutable-field enforcement gap is in `init.go` (not one of Tea's 3 deployer files) and the regeneration paths are unmodified upstream Go. |
| TEAO1-162 | Low | kona-node Docker recipe ignores documented trust-RPC env knobs | `kona/docker/recipes/kona-node/**`, kona docs | Entirely in vendored kona Docker recipe/docs, outside Tea's two allowed kona files; pre-existing upstream packaging issue. |
| TEAO1-173 | Low | Removed L2 dev prefunds survive failed-retry recovery on CGT chains | `op-deployer/.../pipeline/prefund_l2_dev_genesis.go` | A **dev-only** operator-workflow recovery bug; the stale-prefund reuse and its fix live in `prefund_l2_dev_genesis.go` (not Tea's), independent of CGT — the bridge contracts are only the downstream redemption surface. |
| TEAO1-137 | Info | txinclude hardcodes Isthmus operator-fee formula on Jovian chains | `op-service/txinclude/isthmus_cost_oracle.go` | Defect + fix are entirely in the upstream `op-service/txinclude` Go package, which Tea did not modify. |
| TEAO1-153 | Info | CombineDeployConfig ignores ChainIntent.Eip1559DenominatorCanyon, emits 250 | `op-deployer/.../state/deploy_config.go` | The hardcoded `250` is in `CombineDeployConfig()` in `deploy_config.go` (upstream commit #11964, not Tea). Tea modified `chain_intent.go` which only *validates* the field; the drop + fix are in the unmodified file. |
| TEAO1-188 | Info | Interop proof path ignores dependency-set message expiry overrides | `kona/crates/{protocol/interop, proof/proof-interop}/**` | Entirely within vendored kona interop/proof crates, outside Tea's fork delta. No Tea file is involved; Tea does not run interop. |

---

## PR grouping plan — minimize the number of PRs

Findings are grouped so each PR touches **one coherent file set / subsystem**, lets you reuse a single test harness, and gets one review pass. KEEP groups (P1–P7) are the actionable fix PRs. BORDERLINE groups (P8–P14) each require a "fork the vendored file vs ship a tea-side shim vs accept" decision *before* opening the PR.

### KEEP — ready-to-fix PRs (7 PRs cover all 23)

| PR | Theme | Files | Findings |
|----|-------|-------|----------|
| **P1** | GPG precompile hardening | `tea-reth/src/precompiles/gpg_verify.rs` | 141, 144, 148, 160, 166, 172 |
| **P2** | SSH/SSHSIG precompile hardening | `tea-reth/src/precompiles/{ssh_common,ssh_verify,ssh_sig_verify}.rs` | 163, 168, 183 |
| **P3** | EVM factory: multiplier gating + timing + per-spec precompiles | `tea-reth/src/evm/factory.rs`, `kona/.../fpvm_evm/factory.rs`, `tea-l1-cost/src/lib.rs`, `op-revm` patch | 132, 145, 147 *(+ execution leg of 176)* |
| **P4** | TeaWAPOracle / GasPriceOracle fee-math correctness | `TeaWAPOracle.sol`, `GasPriceOracle.sol`, `L2Genesis.s.sol`, `tea-l1-cost` (138's backup const) | 138, 165, 185, 189, 191 |
| **P5** | CGT deployer intent validation | `state/chain_intent.go`, `pipeline/l2genesis.go`, `L2Genesis.s.sol` | 134, 139 |
| **P6** | L1CGTBridge initialization safety | `lib/tea-cgt-bridge/src/L1/L1CGTBridge.sol` | 182 |
| **P7** | Tea RPC receipt converter (TEA-denominated `l1Fee`) | `tea-reth/src/main.rs` + new Tea converter module | 170, 133, 161, 176 *(receipt leg; execution leg of 176 is in P3)* |

### BORDERLINE — decide-then-PR (group by where the fix would land)

| PR | Theme | Decision needed | Findings |
|----|-------|-----------------|----------|
| **P8** | Kona FPVM parity (precompiles + Tea-aware host factory) | fork `kona/.../fpvm_evm/precompiles/provider.rs` + `bin/host/src/interop/*` | 174, 143 |
| **P9** | Go fault-proof (op-program) Tea semantics + chain-gate | fork/patch `op-program/client/*` | 184, 187 |
| **P10** | op-reth txpool affordability with Tea multiplier | fork `op-reth/crates/txpool/src/validator.rs` (+ maintain.rs) | 175, 186, 151 |
| **P10b** | op-reth conditional-tx `knownAccounts` revalidation at inclusion *(split from P10 — a storage-predicate re-check, not L1-fee affordability)* | ✅ Addressed (#21 via #34): shared `txpool/conditional.rs` evaluator wired into `payload/builder.rs` (re-check `Slots` vs pending build state, pre-execution — the load-bearing leg), head eviction in `txpool/maintain.rs`, admission in `rpc/eth/ext.rs` | 167 |
| **P11** | op-reth RPC simulate/trace block-fee context | fork `op-reth/crates/rpc/**` | 164, 178 |
| **P12** | tea-reth proof-history wiring | ✅ Addressed (#21): fail-closed in `main.rs` (`ensure_proofs_history_unsupported`) — Tea does not serve proof history, so the flag is rejected rather than wiring the unused `OpProofsExEx` stack | 152 |
| **P13** | CGT deployer mode-immutability across retries | fork `op-deployer/.../init.go`/`apply.go` or guard in `chain_intent.go` | 171 |
| **P14** | op-node Tea-aware hardfork upgrade bytecode | bake Tea-aware upgrade payloads for `GasPriceOracle` (136) + `L1BlockCGT` (140) in `op-node/rollup/derive/` | 136, 140 |
| **P15** | Kona registry / host-config trust for Tea | ship Tea's rollup config in Kona's registry / reproducible custom-config prestate | 181 |

> Net: **the 24 KEEP findings collapse into 7 PRs (P1–P7)**; the 15 BORDERLINE findings into 9 decision-gated PRs (P8–P15, with 167 split out of P10 as P10b). 176 spans two KEEP PRs (execution leg in P3, receipt leg in P7) — land P3 first, then P7, to reconcile all three fee surfaces.

## Notes for manual review

1. **The EJECT list is not "ignore."** Several are genuine risks for a Tea chain operator — they just can't be fixed by editing Tea's current files. The realistic options for an ejected finding are: (a) fork the upstream file into Tea's vendored tree, (b) carry an upstream patch, or (c) accept and document. They are *out of the current PR-diff scope*, which is what you asked to filter on.
2. **TEAO1-174 is the most consequential borderline:** unlike the fee findings (which mostly affect RPC reporting / mempool), an un-mirrored precompile is a hard EL↔FPVM state-root divergence — a challengeable output root. Treat its "fix site is vendored" status as a blocker to resolve, not a reason to defer.
3. **CGT-deployer cluster.** Tea only modified 3 op-deployer files (`opcm/l2genesis.go`, `pipeline/l2genesis.go`, `state/chain_intent.go`). Findings 134/139 fit those (KEEP, P5); 146/150/155/159/173 root-cause in *other* op-deployer files (EJECT) and 171 in unforked init logic (BORDERLINE, P13) even though they concern CGT.
4. **171 vs 173 consistency (flagged in re-audit):** both are CGT-redeemable retry bugs whose fixes live in out-of-scope op-deployer files. 171 is BORDERLINE because the mode-flip exposure is directly CGT-born; 173 is EJECT because it's a generic dev-only prefund-recovery bug that exists independent of CGT. Worth a second human look.
