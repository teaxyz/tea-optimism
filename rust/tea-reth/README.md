# tea-reth

Custom OP Stack execution client for the [Tea](https://tea.xyz) L2 chain.

tea-reth is a thin wrapper around [op-reth](../op-reth/) that adds Tea-specific functionality. It replaces [tea-geth](https://github.com/teaxyz/tea-geth) (fork of op-geth), which is being deprecated upstream.

## What it does

Tea is an Optimism L2 that uses a custom gas token (TEA). tea-reth extends the standard op-reth node with three things:

1. **GPG signature verification precompile** at address `0x0696` — verifies ed25519 and RSA GPG signatures on-chain
2. **TEA-denominated L1 cost function** — wraps the standard Fjord L1 cost with a TEA/ETH exchange rate read from the on-chain GasPriceOracle
3. **Chain ID detection** — identifies Tea networks (mainnet `6122`, testnet `10218`)

All other behavior (consensus, networking, RPC, sync, etc.) is inherited from op-reth unchanged.

## Building

From the `rust/` directory:

```sh
# Build (release) — automatically vendors op-revm and applies patches
just build-tea-reth

# Or manually:
just vendor-patch          # vendor op-revm + apply Tea patch (idempotent)
cargo build -p tea-reth    # debug build
cargo build -p tea-reth --release
```

The binary is output to `target/release/tea-reth` (or `target/debug/tea-reth`).

## Running

tea-reth accepts the same CLI flags as op-reth:

```sh
tea-reth node \
  --chain <chainspec.json> \
  --rollup.sequencer-http <sequencer-url> \
  --authrpc.port 8551 \
  --authrpc.jwtsecret <jwt-secret-path>
```

See the [op-reth docs](https://reth.rs/) for full CLI reference — tea-reth is a drop-in replacement.

## Testing

```sh
# Run all 26 tests
cargo test -p tea-reth
```

### Test coverage

All tests are ported from tea-geth commit `46ec0efe` with Go source references documented inline.

| Module | Tests | Ported from |
|--------|-------|-------------|
| `chainspec` | 1 | `params/config.go` — `IsTea()` |
| `l1_cost` | 11 | `core/types/rollup_cost.go` and `rollup_cost_test.go` |
| `precompiles::gpg_verify` | 10 | `core/vm/contracts.go` and `contracts_test.go` |
| `evm_integration` | 4 | EVM-level precompile registration tests |

## Architecture

```
src/
  lib.rs              — module declarations
  chainspec.rs        — Tea chain ID constants and is_tea() detection
  l1_cost.rs          — TEA/ETH exchange rate math (pure functions)
  main.rs             — CLI binary entry point with TeaExecutorBuilder
  evm/
    mod.rs            — re-exports
    factory.rs        — TeaEvmFactory: precompiles + TEA/ETH L1 cost multiplier
  precompiles/
    mod.rs            — re-exports
    gpg_verify.rs     — GPG signature verification precompile implementation
```

### How it plugs in

tea-reth uses the standard `OpNode` with a custom `ExecutorBuilder` that swaps in `TeaEvmFactory`. The factory:
1. Clones all standard OP precompiles and adds the GPG verify precompile at `0x0696`
2. Reads the TEA/ETH exchange rate from the GasPriceOracle and sets the L1 cost multiplier on `L1BlockInfo`

Everything else — block building, consensus, networking, RPC — is unmodified op-reth.

### Key dependencies

- `pgp` (rpgp) v0.19 — pure Rust OpenPGP for GPG signature verification
- `reth-op` — op-reth node, EVM, and RPC infrastructure
- `reth-optimism-cli` — CLI framework and chain spec parser
- `op-revm` v15.0.0 (vendored) — patched with L1 cost multiplier support

## Upstream fork notes

This crate lives in a fork of the [optimism monorepo](https://github.com/ethereum-optimism/optimism) at tag `v1.16.7`. Two changes were made to upstream/vendored code:

- **`op-reth/crates/evm/src/lib.rs`**: The `ConfigureEngineEvm` impl for `OpEvmConfig` was made generic over the `EvmFactory` type parameter (matching the existing `ConfigureEvm` impl). This is necessary for any custom `EvmFactory` to launch a real node. See the comment in that file for details.

- **`vendor/op-revm`** (vendored from crates.io): Added an optional `l1_cost_multiplier` field to `L1BlockInfo` that scales L1 transaction costs by a `(numerator, denominator)` ratio. This mirrors tea-geth's `NewL1CostFuncTea` cost function wrapper. The patch is in `patches/op-revm-l1-cost-multiplier.patch`.

### Why vendor op-revm?

op-revm is an external crate published to crates.io. Tea needs to add a single field (`l1_cost_multiplier`) to `L1BlockInfo` — a struct we don't own. Since Rust doesn't support monkey-patching structs, we vendor the crate locally and apply a small patch (~25 lines across 2 files).

The `vendor/` directory is `.gitignored` — only the patch file in `patches/` is committed. This keeps our fork diff minimal: we carry a 63-line patch description rather than a full copy of op-revm's source. The `[patch.crates-io]` directive in workspace `Cargo.toml` redirects all `op-revm` references to the local vendored copy.

A `build.rs` approach was considered but won't work: cargo resolves `[patch.crates-io]` at the workspace level _before_ any crate compiles, so a build script can't bootstrap a dependency that cargo needs to even start.

### Vendored dependency maintenance

**op-revm is vendored via the justfile.** Run `just vendor-patch` from `rust/` to set up or refresh it. The `build-tea-reth` recipe does this automatically.

```sh
# From the rust/ directory:
just vendor-patch        # idempotent — skips if already present
just vendor-patch-force  # re-vendor from scratch
```

When upgrading op-revm to a new version:

1. Update `OP_REVM_VERSION` in the root `justfile`
2. Update the version in workspace `Cargo.toml` (`[workspace.dependencies]` and `[patch.crates-io]`)
3. Run `just vendor-patch-force`
4. If the patch fails to apply, regenerate it:
   - Copy the new op-revm from `~/.cargo/registry/src/*/op-revm-<version>/`
   - Make the Tea changes (see `patches/op-revm-l1-cost-multiplier.patch` for what to add)
   - `diff -ruN original/ modified/ > patches/op-revm-l1-cost-multiplier.patch`
5. Run `cargo test -p tea-reth` to verify
