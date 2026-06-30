#!/usr/bin/env bash
# run_local.sh — full local setup and demo for OpenVM × Stellar proof aggregator
#
# Usage:
#   bash run_local.sh          # default N=5 proofs
#   bash run_local.sh --n 10   # custom N
#
# Works on: macOS, Linux, Windows (Git Bash / WSL)

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo -e "${CYAN}[run_local]${RESET} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${RESET} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${RESET} $*"; }
fail() { echo -e "${RED}[ FAIL ]${RESET} $*"; exit 1; }
section() {
    echo
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  $*${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
}

run() {
    # Print the command in yellow, then execute it with full output visible
    echo -e "${YELLOW}\$ $*${RESET}"
    "$@"
}

# ── Parse args ────────────────────────────────────────────────────────────────
N=5
while [[ $# -gt 0 ]]; do
    case "$1" in
        --n) N="$2"; shift 2 ;;
        --n=*) N="${1#--n=}"; shift ;;
        *) warn "Unknown argument: $1"; shift ;;
    esac
done

# ── Locate repo root ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGG_DIR="$SCRIPT_DIR"

echo
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║    OpenVM × Stellar — Local Setup & Demo                     ║${RESET}"
echo -e "${BOLD}║    N = ${N} proof-of-balance claims → 1 aggregated STARK proof ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo
log "Repo root : $REPO_ROOT"
log "Agg dir   : $AGG_DIR"
log "N         : $N"

# ─────────────────────────────────────────────────────────────────────────────
section "STEP 1/7 — Check prerequisites"
# ─────────────────────────────────────────────────────────────────────────────

# ── Rust / cargo ──────────────────────────────────────────────────────────────
log "Checking for cargo..."
if ! command -v cargo &>/dev/null; then
    warn "cargo not found. Installing Rust via rustup..."
    run curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # Source the env so cargo is available in this shell session
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi
run cargo --version
ok "cargo found"

# ── rustup ───────────────────────────────────────────────────────────────────
log "Checking for rustup..."
if ! command -v rustup &>/dev/null; then
    fail "rustup not found even after install. Please restart your shell and re-run."
fi
run rustup --version
ok "rustup found"

# ─────────────────────────────────────────────────────────────────────────────
section "STEP 2/7 — Install required Rust toolchains"
# ─────────────────────────────────────────────────────────────────────────────

NIGHTLY="nightly-2025-08-02"

log "Installing stable toolchain (pinned in rust-toolchain.toml)..."
run rustup toolchain install stable
ok "stable toolchain ready"

log "Installing nightly toolchain $NIGHTLY (required for guest RISC-V compilation)..."
run rustup toolchain install "$NIGHTLY"
ok "nightly $NIGHTLY ready"

log "Adding rust-src component for nightly (required by OpenVM build)..."
run rustup component add rust-src --toolchain "$NIGHTLY"
ok "rust-src added"

log "Adding RISC-V target (needed to compile guest programs)..."
run rustup target add riscv32im-risc0-zkvm-elf --toolchain "$NIGHTLY" || \
    warn "riscv32im-risc0-zkvm-elf not available for this toolchain (may already be bundled)"
ok "RISC-V target ready"

log "Current installed toolchains:"
run rustup toolchain list

# ─────────────────────────────────────────────────────────────────────────────
section "STEP 3/7 — Install cargo-nextest"
# ─────────────────────────────────────────────────────────────────────────────

if command -v cargo-nextest &>/dev/null; then
    ok "cargo-nextest already installed: $(cargo nextest --version)"
else
    log "Installing cargo-nextest (picking version compatible with active rustc)..."
    # Detect active rustc minor version and pick the newest compatible release.
    # cargo-nextest 0.9.129+ requires rustc 1.91; 0.9.128 supports 1.89+.
    RUSTC_MINOR=$(rustc --version | grep -oP '1\.\K[0-9]+')
    log "Active rustc minor version: 1.${RUSTC_MINOR}"
    if [[ "$RUSTC_MINOR" -ge 91 ]]; then
        NEXTEST_VER="0.9.138"
    else
        NEXTEST_VER="0.9.128"
    fi
    log "Installing cargo-nextest $NEXTEST_VER..."
    run cargo install cargo-nextest --version "$NEXTEST_VER" --locked
    ok "cargo-nextest installed: $(cargo nextest --version)"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "STEP 4/7 — Verify OpenVM workspace builds"
# ─────────────────────────────────────────────────────────────────────────────

cd "$REPO_ROOT"
log "Running cargo check on core OpenVM crates (sanity check)..."
run cargo check -p openvm-sdk -p openvm-circuit 2>&1
ok "OpenVM workspace check passed"

# ─────────────────────────────────────────────────────────────────────────────
section "STEP 5/7 — Build guest program (RISC-V ELF)"
# ─────────────────────────────────────────────────────────────────────────────

cd "$AGG_DIR/guest/balance-aggregator"
log "Building guest program with nightly toolchain..."
log "  Source : $AGG_DIR/guest/balance-aggregator/src/main.rs"
log "  Target : riscv32im-risc0-zkvm-elf"
run cargo +"$NIGHTLY" build --release 2>&1
ok "Guest ELF built"

# ─────────────────────────────────────────────────────────────────────────────
section "STEP 6/7 — Run host orchestrator (execute + prove + benchmark)"
# ─────────────────────────────────────────────────────────────────────────────

cd "$AGG_DIR"
log "Running host orchestrator with N=$N proofs..."
log "  This will:"
log "    1. Compile guest → RISC-V ELF via OpenVM toolchain"
log "    2. Generate $N random balance witnesses"
log "    3. Execute the guest program (fast dry-run)"
log "    4. Generate aggregate STARK proof  ← takes 2-10 min on first run"
log "    5. Verify the STARK proof locally"
log "    6. Print Stellar cost comparison"
echo

START_TIME=$(date +%s)
run cargo run --release -p stellar-aggregator-host -- --n "$N" 2>&1
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo
ok "Host orchestrator completed in ${ELAPSED}s"

# ─────────────────────────────────────────────────────────────────────────────
section "STEP 7/7 — Build Soroban verifier contract (optional)"
# ─────────────────────────────────────────────────────────────────────────────

cd "$AGG_DIR/contracts/stellar-verifier"

# Check for wasm32 target
if rustup target list --installed | grep -q "wasm32-unknown-unknown"; then
    log "wasm32-unknown-unknown already installed"
else
    log "Adding wasm32-unknown-unknown target for Soroban contract build..."
    run rustup target add wasm32-unknown-unknown
fi

log "Building Soroban verifier contract → WASM..."
run cargo build --target wasm32-unknown-unknown --release 2>&1

WASM_PATH="$AGG_DIR/contracts/stellar-verifier/target/wasm32-unknown-unknown/release/stellar_aggregated_verifier.wasm"
if [[ -f "$WASM_PATH" ]]; then
    WASM_SIZE=$(wc -c < "$WASM_PATH")
    ok "Contract built: $(basename "$WASM_PATH") (${WASM_SIZE} bytes)"
else
    warn "WASM file not found at expected path — check build output above"
fi

log "Running Soroban contract unit tests..."
run cargo test --features testutils 2>&1
ok "Contract tests passed"

# ─────────────────────────────────────────────────────────────────────────────
section "DONE"
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${GREEN}${BOLD}All steps completed successfully!${RESET}"
echo
echo "  Summary:"
echo "    • Guest ELF     : $AGG_DIR/guest/balance-aggregator/target/riscv32im-risc0-zkvm-elf/release/balance-aggregator"
echo "    • Soroban WASM  : $WASM_PATH"
echo
echo "  Next steps:"
echo "    • Deploy contract to Stellar Testnet:"
echo "        stellar contract deploy \\"
echo "          --wasm $WASM_PATH \\"
echo "          --source <your-keypair> --network testnet"
echo
echo "    • Re-run demo with more proofs:"
echo "        bash $SCRIPT_DIR/run_local.sh --n 10"
echo
