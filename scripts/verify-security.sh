#!/usr/bin/env bash
#
# verify-security.sh -- the local test gate every Tea security fix MUST pass.
#
# WHY THIS EXISTS: the "Apex Fix Review Scan" CI check is a per-finding security
# review of the diff -- it does NOT compile the workspace or run a single test.
# Before this script, "passed verification" silently meant only "the Apex scan
# liked the diff", so real test failures (and a latent GPG consensus-halt in #19)
# sat undetected in branches that looked green. This makes "passed local testing"
# a real, reproducible, all-or-nothing gate:
#
#   1. cargo check --workspace --all-targets   (does the whole thing compile?)
#   2. cargo test  <Tea + audit-touched crates> (do the tests actually pass?)
#   3. forge test  <Tea contract suites>        (do the contract tests pass?)
#
# Branch-agnostic: it intersects the target crate/contract lists with what the
# checked-out branch actually contains, so the SAME gate runs on any PR branch.
#
# Usage:   scripts/verify-security.sh [REPO_ROOT]
#          REPO_ROOT defaults to the git toplevel of the current directory.
# Honors:  CARGO_TARGET_DIR (export it to share a build cache across branches).
# Exit:    0 only if every present stage passes; non-zero otherwise.
#
set -uo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$ROOT" || { echo "FATAL: cannot cd to repo root '$ROOT'"; exit 2; }
REV="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
REF="$(git describe --all --contains HEAD 2>/dev/null || echo '?')"
LOGD="${VS_LOGDIR:-/tmp/verify-security-logs}"; mkdir -p "$LOGD"

echo "=================================================================="
echo " verify-security gate   root=$ROOT  rev=$REV  ref=$REF"
echo "=================================================================="

FAIL=0
declare -a SUMMARY
record() { SUMMARY+=("$(printf '  %-26s %s' "$1" "$2")"); [ "$2" = "FAIL" ] && FAIL=1; }

# A cargo/forge log "failed" iff it has a real failure marker (NOT the benign
# "0 failed" that every green line contains).
log_failed() {
  grep -qE 'result: FAILED|; [1-9][0-9]* failed|error\[|error: (could not|test failed|aborting)|panicked|FAILED \(' "$1"
}

# ---------------------------------------------------------------------------
# Stage 1 + 2 : Rust
# ---------------------------------------------------------------------------
if [ -d rust ]; then
  cd rust

  WANT="tea-precompiles tea-l1-cost tea-trace-ctx tea-reth kona-client kona-host \
reth-optimism-rpc reth-optimism-txpool reth-optimism-payload-builder \
reth-optimism-evm reth-optimism-node"

  MEMBERS="$(cargo metadata --no-deps --format-version 1 2>/dev/null \
    | python3 -c 'import sys,json; print(" ".join(p["name"] for p in json.load(sys.stdin)["packages"]))' 2>/dev/null)"

  PKGS=""; PRESENT=""
  for c in $WANT; do
    case " $MEMBERS " in *" $c "*) PKGS="$PKGS -p $c"; PRESENT="$PRESENT $c";; esac
  done

  echo; echo "## [1/3] cargo check --workspace --all-targets"
  cargo check --workspace --all-targets > "$LOGD/build.log" 2>&1; rc=$?
  tail -2 "$LOGD/build.log"
  if [ $rc -eq 0 ] && ! log_failed "$LOGD/build.log"; then record "rust build (workspace)" PASS
  else record "rust build (workspace)" FAIL; fi

  echo; echo "## [2/3] cargo test$PKGS"
  echo "   crates:$PRESENT"
  if [ -n "$PKGS" ]; then
    cargo test $PKGS > "$LOGD/test.log" 2>&1; rc=$?
    grep -E 'test result: (ok|FAILED)|running [0-9]+ test|^test .* FAILED|panicked at' "$LOGD/test.log" | tail -40
    PASSED=$(awk '/test result: ok\./ {p+=$4} END{print p+0}' "$LOGD/test.log")
    FAILED=$(awk -F'[. ]+' '/test result: FAILED\./ {for(i=1;i<=NF;i++) if($i=="FAILED") f+=$(i+2)} END{print f+0}' "$LOGD/test.log")
    echo "   -> $PASSED passed, $FAILED failed"
    if [ $rc -eq 0 ] && ! log_failed "$LOGD/test.log"; then record "rust tests ($PASSED ok)" PASS
    else record "rust tests ($PASSED ok, $FAILED FAILED)" FAIL; fi
  else
    record "rust tests (no target crates)" "SKIP"
  fi
  cd "$ROOT"
else
  record "rust (no rust/ dir)" "SKIP"
fi

# ---------------------------------------------------------------------------
# Stage 3 : Contracts (Tea oracle / TeaWAP / genesis suites)
# ---------------------------------------------------------------------------
CB="packages/contracts-bedrock"
if [ -d "$CB" ] && ! [ -f "$CB/lib/forge-std/src/Vm.sol" ]; then
  echo; echo "## [3/3] contracts SKIPPED -- forge submodules not initialized"
  echo "   (run 'git submodule update --init --recursive' to enable; not a branch defect)"
  record "contract tests (no submodules)" "SKIP"
elif [ -d "$CB" ] && command -v forge >/dev/null 2>&1; then
  echo; echo "## [3/3] forge test --match-contract '(GasPriceOracle|TeaWAP|L2Genesis)'"
  ( cd "$CB" && forge test --match-contract '(GasPriceOracle|TeaWAP|L2Genesis)' ) \
    > "$LOGD/forge.log" 2>&1; rc=$?
  grep -E 'Suite result:|tests passed|FAIL|Ran [0-9]+ test suite' "$LOGD/forge.log" | tail -20
  CPASS=$(awk '/Suite result: ok\./ {p+=$4} END{print p+0}' "$LOGD/forge.log")
  if [ $rc -eq 0 ] && ! log_failed "$LOGD/forge.log"; then record "contract tests ($CPASS ok)" PASS
  else record "contract tests" FAIL; fi
else
  record "contract tests (no forge / no contracts)" "SKIP"
fi

# ---------------------------------------------------------------------------
echo; echo "=================================================================="
echo " SUMMARY   root=$ROOT  rev=$REV"
printf '%s\n' "${SUMMARY[@]}"
if [ $FAIL -eq 0 ]; then echo "  RESULT                     ALL GREEN"; else echo "  RESULT                     >>> FAILURES <<<"; fi
echo " logs: $LOGD/{build,test,forge}.log"
echo "=================================================================="
exit $FAIL
