# TEAO1-181 — Host-supplied rollup config trust: disposition

**Finding (Cantina/Apex TEAO1-181, severity Info):** "Tea single-chain proofs trust
host-supplied rollup configs whenever custom configs are needed." When Tea is not present
in Kona's embedded superchain registry, the single-chain host path can feed an
operator-supplied JSON config into `L2_ROLLUP_CONFIG_KEY`, and `BootInfo::load()`
deserializes it on a registry miss without verifying it against a canonical chain/config
commitment. The disputed block is then replayed under host-chosen `hardforks`, `genesis`,
and system-config values.

**Disposition: permissionless-readiness item — not a current vulnerability.** Tracked as
**P15** in [`cantina-triage-fork-scope.md`](./cantina-triage-fork-scope.md). This document
records why it is not a live exploit in Tea's deployment and what would actually close it.

---

## Why it is not reachable today: Tea fault proofs are permissioned

The entire exploit requires an **untrusted prover** to submit a dispute game that replays
the block under a forged config. Tea does not run permissionless fault proofs. The
respected game type is the **PermissionedDisputeGame (type 1)**, enforced at deploy and at
runtime:

- `scripts/mainnet/deploy-12-finalize.sh` asserts `ASR.respectedGameType() == 1`
  (`= PermissionedDisputeGame`) and fails the deploy otherwise.
- The challenger runs with `--trace-type permissioned`
  (`kubernetes/challenger/challenger-deployment.yaml`).

Consequently, only the **authorized proposer/challenger** (holding specific keys) can create
a *respected* dispute game, and those roles run the host with the canonical Tea rollup
config. An untrusted party cannot submit a respected game at all, so the
`--rollup-config-path` / `L2_ROLLUP_CONFIG_KEY` fallback is never reached through an
adversarial on-chain path. The finding's assumption *"the prover controls the host inputs"*
holds only for a **trusted** prover.

This is consistent with the finding's own **Info** severity rating.

## Causation: upstream Kona behavior, not a Tea regression

The registry-miss → oracle/local-input fallback in `BootInfo::load()`
(`rust/kona/crates/proof/proof/src/boot.rs`) is **upstream Kona design** for custom
(non-superchain) chains. Tea simply is not in the embedded superchain registry because it is
a custom chain (id 6122); the host-config path is how Kona bootstraps any such chain. Tea did
not introduce or widen the fallback — it is only a *soundness* concern under a permissionless
model Tea has not adopted. (See the triage note: *"181 → BORDERLINE: Tea's absence from
Kona's registry is the trigger."*)

## It is not the binding constraint on permissionless proofs

Even setting the config-trust issue aside, Tea's fault-proof VM is **permissioned-sound
only** for a separate, larger reason: the Tea-specific precompiles (`0x0696`–`0x0698`) are
host-accelerated into the Kona FPVM and cannot be reproduced permissionlessly (an L1
`staticcall` cannot reproduce L2-only precompiles). That gap already prevents a sound
permissionless deployment. TEAO1-181 is therefore **one of several prerequisites** for
permissionless proofs, and not the one currently gating it.

---

## What would actually close it (permissionless-readiness)

When/if Tea pursues permissionless fault proofs, the invariant — *"proof replay must not
depend on host-chosen config"* — is satisfied by **committing to the config**, not by input
sanitization. The work must land **together** with the precompile-FPVM soundness solution:

1. Ship Tea's rollup config in Kona's registry, or build the prestate from a **reproducibly
   baked custom-config build**, so the config is bound into the FPVM program the prestate
   hash commits to.
2. Have the dispute game commit to the expected **rollup-config hash** (and L1-config hash if
   needed) and verify it before boot.
3. Refuse to start production proof clients when `BootInfo::load()` would take the
   oracle/local-input fallback.

## Optional defense-in-depth (does NOT close the finding)

These are cheap footgun-prevention guards that improve robustness/forensics even under the
permissioned posture. They do **not** satisfy the invariant (a trusted prover can still
supply a *consistent* forged config), so they are not represented as the fix:

- Reject `l2_chain_id == 0` in the local bootstrap (`single/local_kv.rs` currently
  `unwrap_or_default()`s a missing id to `0`).
- Allow passing both `--l2-chain-id` and `--rollup-config-path`, then require
  `rollup_config.l2_chain_id.id() == l2_chain_id` (`single/cfg.rs` currently makes them
  mutually exclusive).
- Emit the active rollup-config hash in logs and proof metadata so mismatches are visible
  during disputes (`boot.rs`).

---

## Summary

| | |
|---|---|
| **Finding** | TEAO1-181 (Info) — host-supplied rollup config trust |
| **Reachable today?** | No — `RespectedGameType = 1` (PermissionedDisputeGame); only trusted provers submit respected games, with the canonical config |
| **Causation** | Upstream Kona registry-miss fallback; Tea's custom-chain absence from the registry is the trigger; not a Tea regression |
| **Binding permissionless blocker?** | No — the host-accelerated Tea-precompile FPVM gap already blocks sound permissionless proofs |
| **Real fix** | On-chain rollup-config-hash commitment + registry/baked-prestate config + refuse fallback — landed *with* the precompile-FPVM solution |
| **Tracking** | P15 in `cantina-triage-fork-scope.md` (permissionless-readiness) |
