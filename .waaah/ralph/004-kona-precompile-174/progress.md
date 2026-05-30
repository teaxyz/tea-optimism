# TEAO1-174 — mirror Tea precompiles into the kona FPVM (design + impl)

## Task (verbatim)
"yes, do it locally. Is there anyway we can reuse the existing rust. I REALLY DON'T WANT
parallel implementations... Is there a canonical way to add precompile stuff to kona?
Are there any official docs?"

## Answers (evidence-based)

### Canonical way to add a precompile to kona? YES — two layers, both official:
1. **Custom EvmFactory** (documented: rust/docs/docs/pages/kona/sdk/proof/exec-ext.mdx —
   "kona-executor Extensions / Example - Custom Precompile"). This is how you register a
   precompile in the FPVM's EVM. Tea ALREADY uses this (FpvmOpEvmFactory / TeaEvmFactory).
2. **Accelerated precompiles** (the ecrecover/kzg/bls pattern) — for crypto that can't or
   shouldn't run inside the no_std MIPS/RISC-V FPVM. Mechanism:
   - FPVM client stub (e.g. ecrecover.rs::fpvm_ec_recover) uses `precompile_run!` →
     sends `HintType::L1Precompile (address‖gas‖input)` → reads result from the preimage
     oracle (PreimageKeyType::Precompile). NO crypto in the FPVM.
   - Host (single/handler.rs `HintType::L1Precompile`) → `eth::execute(address,input,gas)`
     → looks the precompile up BY ADDRESS in `ACCELERATED_PRECOMPILES: &[revm Precompile]`
     and runs it NATIVELY, serving the result via the preimage KV.

### Reuse existing rust / NO parallel implementation? YES:
- `revm` is a SINGLE workspace version (34.0.0) used by BOTH tea-reth EL and kona-host
  (kona-host: `revm = { workspace = true }`). So `revm::precompile::Precompile` is the
  SAME type in both. tea-reth's `gpg_verify::precompile()` ALREADY returns that type.
- => The crypto logic lives ONCE. Extract tea-reth/src/precompiles/ into a shared crate
  `tea-precompiles` (std; deps pgp/rsa/ed25519/p256/sha2 + revm-precompile). Then:
    * tea-reth EL: TeaEvmFactory uses tea_precompiles::{gpg,ssh,sshsig}::precompile().
    * kona-host: add those same `Precompile` objects to ACCELERATED_PRECOMPILES → host
      runs the EXACT same fns. (mirrors the tea-l1-cost shared-crate pattern for the multiplier)
    * kona-client FPVM: 3 thin accelerated stubs (hint→oracle), ~15 lines each, no crypto.
- The only "new" code is the 3 FPVM stubs (plumbing) + host registration. Zero duplicated crypto.

## Plan (stacked on the HARDENED precompiles = #19 GPG + #20 SSH)
1. Extract `rust/tea-precompiles` crate from tea-reth/src/precompiles/ (hardened versions).
2. tea-reth depends on it; factory.rs uses tea_precompiles::*::precompile().
3. kona-host: add the 3 Tea precompiles to ACCELERATED_PRECOMPILES (eth/precompiles.rs).
4. kona-client FPVM: 3 accelerated stubs + register in OpFpvmPrecompiles::new_with_spec.
5. Parity test: call 0x0696 through the FPVM accelerated path; assert == host/native result.
   (extends cross_executor_l1_cost_parity which today explicitly does NOT test precompiles)

## Notes
- FPVM client builds + tests NATIVELY (accelerated tests use tokio) — so this is locally testable.
- Stacking: 174 must sit on #19+#20 so the shared crate carries the security hardening.

## Iteration 1 — extraction + no_std gas split (DONE, verified)
- Stage A: moved 4 precompile files + testdata → `rust/tea-precompiles` (std crate).
  tea-reth consumes via `tea_precompiles::*`. 142 unit + 13 integration tests pass.
  Committed: 42f8aeb5.
- Stage B: split out no_std `gas` module (addresses + gas schedule + 3 required_gas
  fns). Crypto modules re-export from `crate::gas` (zero call-site changes). Crate is
  now feature-gated: `default=["std"]` (crypto), `--no-default-features` = gas-only.
  Verified: std tests 142 pass; `cargo build --no-default-features --target
  riscv32imac-unknown-none-elf` succeeds (crypto excluded). Added to justfile check-no-std.
- Next: Stage C kona-host ACCELERATED_PRECOMPILES + FPVM stubs (use gas:: for gas).
