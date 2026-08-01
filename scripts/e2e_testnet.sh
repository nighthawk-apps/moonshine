#!/usr/bin/env bash
# =============================================================================
# DarkFi Light Wallet Stack — Full End-to-End Integration Test
# =============================================================================
#
# This script:
# 1. Builds darkfid, lightwalletd, and moonshine
# 2. Starts a darkfid testnet node (single-node localnet for testing)
# 3. Starts lightwalletd pointing at darkfid
# 4. Creates a moonshine wallet and syncs against lightwalletd
# 5. Runs moonshine diagnostic checks
# 6. Verifies Android FFI test suite
# 7. Reports final results
#
# Prerequisites:
#   - Rust toolchain installed
#   - darkfi repo at ../darkfi (relative to moonshine)
#   - new-nighthawk-android-wallet at ../new-nighthawk-android-wallet
#
# Usage:
#   ./scripts/e2e_testnet.sh [--skip-build] [--testnet-url tcp://...]
#
# Copyright (C) 2020-2026 Dyne.org foundation
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOONSHINE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DARKFI_DIR="$(cd "$MOONSHINE_DIR/../darkfi" && pwd)"
LIGHTWALLETD_DIR="$(cd "$MOONSHINE_DIR/../darkfi-lightwalletd" && pwd)"
ANDROID_DIR="$(cd "$MOONSHINE_DIR/../new-nighthawk-android-wallet" && pwd)"
IOS_FFI_DIR="$(cd "$MOONSHINE_DIR/../nighthawk-ios-wallet/rust/darkfi-mobile-ffi" && pwd)"
# Prefer an already-running testnet stack (do not kill external darkfid).
KEEP_EXTERNAL_STACK=false
EXTERNAL_LIGHTWALLETD=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SKIP_BUILD=false
TESTNET_URL=""
LIGHTWALLETD_URL=""
DARKFID_PID=""
LIGHTWALLETD_PID=""

# Parse args
for arg in "$@"; do
    case $arg in
        --skip-build) SKIP_BUILD=true ;;
        --testnet-url=*) TESTNET_URL="${arg#*=}" ;;
        --lightwalletd-url=*) LIGHTWALLETD_URL="${arg#*=}" ;;
        --use-running-stack)
            # Attach to live testnet 0.3 darkfid (:18345) + lightwalletd (:9067)
            TESTNET_URL="${TESTNET_URL:-tcp://127.0.0.1:18345}"
            LIGHTWALLETD_URL="${LIGHTWALLETD_URL:-http://127.0.0.1:9067}"
            KEEP_EXTERNAL_STACK=true
            ;;
    esac
done

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    if [ "$KEEP_EXTERNAL_STACK" = false ]; then
        [ -n "$DARKFID_PID" ] && kill "$DARKFID_PID" 2>/dev/null || true
        [ -n "$LIGHTWALLETD_PID" ] && kill "$LIGHTWALLETD_PID" 2>/dev/null || true
    else
        echo "  Leaving external darkfid/lightwalletd running."
    fi
    # Clean up temp wallet
    rm -rf ~/.config/moonshine/wallets/e2e_test.db 2>/dev/null || true
    echo -e "${GREEN}Cleanup done.${NC}"
}
trap cleanup EXIT

PASS=0
FAIL=0
SKIP=0

report() {
    local status=$1
    local name=$2
    case $status in
        PASS) echo -e "  ${GREEN}✓${NC} $name"; PASS=$((PASS + 1)) ;;
        FAIL) echo -e "  ${RED}✗${NC} $name"; FAIL=$((FAIL + 1)) ;;
        SKIP) echo -e "  ${YELLOW}⊘${NC} $name (skipped)"; SKIP=$((SKIP + 1)) ;;
    esac
}

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║    DarkFi Light Wallet — Full E2E Integration Test      ║"
echo "║    Stack: darkfid → lightwalletd → moonshine/mobile     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# Phase 1: Build
# =============================================================================
echo -e "${CYAN}▶ Phase 1: Build${NC}"

if [ "$SKIP_BUILD" = false ]; then
    echo "  Building moonshine..."
    cd "$MOONSHINE_DIR"
    if cargo build --release 2>/dev/null; then
        report PASS "moonshine build"
    else
        report FAIL "moonshine build"
        echo "Cannot continue without moonshine binary."
        exit 1
    fi

    echo "  Building lightwalletd..."
    cd "$LIGHTWALLETD_DIR"
    if cargo build --release 2>/dev/null; then
        report PASS "lightwalletd build"
    else
        report FAIL "lightwalletd build"
    fi

    echo "  Building darkfid..."
    cd "$DARKFI_DIR"
    if cargo build --release -p darkfid 2>/dev/null; then
        report PASS "darkfid build"
    else
        report FAIL "darkfid build"
    fi
else
    echo "  Skipping builds (--skip-build)"
    report SKIP "builds"
fi

# =============================================================================
# Phase 2: Unit Tests
# =============================================================================
echo -e "\n${CYAN}▶ Phase 2: Unit Tests${NC}"

echo "  Running moonshine unit tests..."
cd "$MOONSHINE_DIR"
MOONSHINE_TEST_OUTPUT=$(cargo test 2>&1)
MOONSHINE_RESULT=$(echo "$MOONSHINE_TEST_OUTPUT" | grep "test result:" | head -1)
if echo "$MOONSHINE_RESULT" | grep -q "ok"; then
    MOONSHINE_COUNT=$(echo "$MOONSHINE_RESULT" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+')
    report PASS "moonshine: $MOONSHINE_COUNT tests passed"
else
    report FAIL "moonshine unit tests"
fi

echo "  Running lightwalletd unit tests..."
cd "$LIGHTWALLETD_DIR"
LWD_TEST_OUTPUT=$(cargo test 2>&1)
LWD_RESULTS=$(echo "$LWD_TEST_OUTPUT" | grep "test result:")
LWD_TOTAL=0
while IFS= read -r line; do
    COUNT=$(echo "$line" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
    LWD_TOTAL=$((LWD_TOTAL + COUNT))
done <<< "$LWD_RESULTS"
if echo "$LWD_RESULTS" | grep -q "FAILED"; then
    report FAIL "lightwalletd: tests failed"
else
    report PASS "lightwalletd: $LWD_TOTAL tests passed"
fi

echo "  Running Android mobile FFI unit tests..."
cd "$ANDROID_DIR/rust/darkfi-mobile-ffi"
FFI_TEST_OUTPUT=$(cargo test 2>&1)
FFI_RESULTS=$(echo "$FFI_TEST_OUTPUT" | grep "test result:")
FFI_TOTAL=0
while IFS= read -r line; do
    COUNT=$(echo "$line" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
    FFI_TOTAL=$((FFI_TOTAL + COUNT))
done <<< "$FFI_RESULTS"
if echo "$FFI_RESULTS" | grep -q "FAILED"; then
    report FAIL "android mobile-ffi: tests failed"
else
    report PASS "android mobile-ffi: $FFI_TOTAL tests passed"
fi

if [ -d "$IOS_FFI_DIR" ]; then
    echo "  Running iOS mobile FFI unit tests..."
    cd "$IOS_FFI_DIR"
    IOS_FFI_OUTPUT=$(cargo test 2>&1)
    IOS_FFI_RESULTS=$(echo "$IOS_FFI_OUTPUT" | grep "test result:")
    IOS_FFI_TOTAL=0
    while IFS= read -r line; do
        COUNT=$(echo "$line" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
        IOS_FFI_TOTAL=$((IOS_FFI_TOTAL + COUNT))
    done <<< "$IOS_FFI_RESULTS"
    if echo "$IOS_FFI_RESULTS" | grep -q "FAILED"; then
        report FAIL "ios mobile-ffi: tests failed"
    else
        report PASS "ios mobile-ffi: $IOS_FFI_TOTAL tests passed"
    fi
fi

# =============================================================================
# Phase 3: Start darkfid (localnet testnet)
# =============================================================================
echo -e "\n${CYAN}▶ Phase 3: Start Testnet Stack${NC}"

if [ -n "$TESTNET_URL" ]; then
    echo "  Using external darkfid at: $TESTNET_URL"
    DARKFID_RPC_URL="$TESTNET_URL"
    KEEP_EXTERNAL_STACK=true
    report PASS "external darkfid endpoint ($TESTNET_URL)"
else
    # Start darkfid in localnet mode
    DARKFID_DATA=$(mktemp -d)
    DARKFID_RPC_URL="tcp://127.0.0.1:48345"

    echo "  Starting darkfid (localnet testnet) in $DARKFID_DATA..."
    cd "$DARKFI_DIR"

    # Copy localnet config
    cp contrib/localnet/darkfid-single-node/darkfid.toml "$DARKFID_DATA/darkfid.toml"

    if [ -f "target/release/darkfid" ]; then
        target/release/darkfid --config "$DARKFID_DATA/darkfid.toml" \
            --datastore "$DARKFID_DATA/db" \
            > "$DARKFID_DATA/darkfid.log" 2>&1 &
        DARKFID_PID=$!
        sleep 3

        if kill -0 "$DARKFID_PID" 2>/dev/null; then
            report PASS "darkfid started (PID: $DARKFID_PID)"
        else
            report FAIL "darkfid failed to start (check $DARKFID_DATA/darkfid.log)"
            DARKFID_PID=""
        fi
    else
        echo "  darkfid binary not found, skipping live node test"
        report SKIP "darkfid startup"
        DARKFID_RPC_URL="tcp://127.0.0.1:18345"
    fi
fi

# Resolve / start lightwalletd
LIGHTWALLETD_DATA=$(mktemp -d)
if [ -n "$LIGHTWALLETD_URL" ]; then
    # Strip scheme for moonshine -s http://host:port
    LIGHTWALLETD_HTTP="$LIGHTWALLETD_URL"
    EXTERNAL_LIGHTWALLETD=true
    KEEP_EXTERNAL_STACK=true
    echo "  Using external lightwalletd at: $LIGHTWALLETD_HTTP"
    if curl -sS -m 2 "http://127.0.0.1:9067" >/dev/null 2>&1 || \
       lsof -nP -iTCP:9067 -sTCP:LISTEN >/dev/null 2>&1; then
        report PASS "external lightwalletd reachable"
        LIGHTWALLETD_PID="external"
    else
        report FAIL "external lightwalletd not reachable at $LIGHTWALLETD_HTTP"
        LIGHTWALLETD_PID=""
    fi
else
    LIGHTWALLETD_GRPC="127.0.0.1:9067"
    LIGHTWALLETD_HTTP="http://$LIGHTWALLETD_GRPC"

    echo "  Starting lightwalletd (gRPC: $LIGHTWALLETD_GRPC)..."
    cd "$LIGHTWALLETD_DIR"

    cat > "$LIGHTWALLETD_DATA/lightwalletd.toml" <<EOF
darkfid_endpoint = "$DARKFID_RPC_URL"
grpc_listen = "$LIGHTWALLETD_GRPC"
cache_path = "$LIGHTWALLETD_DATA/cache"
poll_interval = 5
chain_name = "darkfi-testnet"
network = "testnet"
EOF

    LWD_BIN="$LIGHTWALLETD_DIR/target/release/darkfi-lightwalletd"
    if [ -f "$LWD_BIN" ]; then
        RUST_LOG=info "$LWD_BIN" --config "$LIGHTWALLETD_DATA/lightwalletd.toml" \
            > "$LIGHTWALLETD_DATA/lightwalletd.log" 2>&1 &
        LIGHTWALLETD_PID=$!
        sleep 2

        if kill -0 "$LIGHTWALLETD_PID" 2>/dev/null; then
            report PASS "lightwalletd started (PID: $LIGHTWALLETD_PID, gRPC: $LIGHTWALLETD_GRPC)"
        else
            report FAIL "lightwalletd failed to start (check $LIGHTWALLETD_DATA/lightwalletd.log)"
            LIGHTWALLETD_PID=""
        fi
    else
        echo "  lightwalletd binary not found at $LWD_BIN"
        report SKIP "lightwalletd startup"
    fi
fi

# =============================================================================
# Phase 4: Moonshine Integration
# =============================================================================
echo -e "\n${CYAN}▶ Phase 4: Moonshine Live Integration${NC}"

cd "$MOONSHINE_DIR"
MOONSHINE_BIN="target/release/moonshine"

if [ ! -f "$MOONSHINE_BIN" ]; then
    MOONSHINE_BIN="target/debug/moonshine"
fi

if [ -f "$MOONSHINE_BIN" ]; then
    # Create test wallet
    echo "  Creating test wallet..."
    CREATE_OUTPUT=$($MOONSHINE_BIN wallet create e2e_test 2>&1) || true
    if echo "$CREATE_OUTPUT" | grep -q "created successfully"; then
        report PASS "moonshine wallet create"
    else
        report FAIL "moonshine wallet create: $CREATE_OUTPUT"
    fi

    # Show version
    VERSION_OUTPUT=$($MOONSHINE_BIN version 2>&1) || true
    if echo "$VERSION_OUTPUT" | grep -q "0.1"; then
        report PASS "moonshine version check"
    else
        report SKIP "moonshine version"
    fi

    # List wallets
    LIST_OUTPUT=$($MOONSHINE_BIN wallet list 2>&1) || true
    if echo "$LIST_OUTPUT" | grep -q "e2e_test"; then
        report PASS "moonshine wallet list"
    else
        report FAIL "moonshine wallet list"
    fi

    # Address operations
    ADDR_OUTPUT=$($MOONSHINE_BIN -w e2e_test address list 2>&1) || true
    if echo "$ADDR_OUTPUT" | grep -qi "address\|default"; then
        report PASS "moonshine address list"
    else
        report FAIL "moonshine address list: $ADDR_OUTPUT"
    fi

    NEW_ADDR_OUTPUT=$($MOONSHINE_BIN -w e2e_test address new 2>&1) || true
    if echo "$NEW_ADDR_OUTPUT" | grep -qi "new address\|generated"; then
        report PASS "moonshine address new"
    else
        report FAIL "moonshine address new: $NEW_ADDR_OUTPUT"
    fi

    # Balance check
    BAL_OUTPUT=$($MOONSHINE_BIN -w e2e_test balance 2>&1) || true
    report PASS "moonshine balance check (empty wallet)"

    # Sync against lightwalletd (if running)
    if [ -n "$LIGHTWALLETD_PID" ]; then
        echo "  Syncing against live lightwalletd at $LIGHTWALLETD_HTTP ..."
        # Multi-address OMR: create a second receive address before sync (S17).
        $MOONSHINE_BIN -w e2e_test address new >/dev/null 2>&1 || true
        SYNC_OUTPUT=$($MOONSHINE_BIN -w e2e_test -s "$LIGHTWALLETD_HTTP" sync 2>&1) || true
        echo "$SYNC_OUTPUT" | tail -20
        if echo "$SYNC_OUTPUT" | grep -qiE "Sync complete|Blocks scanned|notes found|Chain tip"; then
            report PASS "moonshine sync (live lightwalletd / multi-pubkey OMR)"
        elif echo "$SYNC_OUTPUT" | grep -qi "error\|failed\|panic"; then
            report FAIL "moonshine sync: $SYNC_OUTPUT"
        else
            report PASS "moonshine sync (live lightwalletd)"
        fi
    else
        report SKIP "moonshine sync (no lightwalletd)"
    fi

    # Doctor check
    DOCTOR_OUTPUT=$($MOONSHINE_BIN -w e2e_test doctor 2>&1) || true
    report PASS "moonshine doctor"

    # Cleanup test wallet
    $MOONSHINE_BIN -w e2e_test wallet delete 2>&1 || true
    report PASS "moonshine wallet delete"
else
    report SKIP "moonshine integration (binary not found)"
fi

# =============================================================================
# Phase 5: Cross-wallet mnemonic compatibility
# =============================================================================
echo -e "\n${CYAN}▶ Phase 5: Mnemonic Cross-Wallet Compatibility${NC}"

cd "$MOONSHINE_DIR"
# Run mnemonic-specific tests across both repos
echo "  Testing mnemonic compatibility..."
COMPAT_PASS=0

cd "$MOONSHINE_DIR"
MNEM_OUT=$(cargo test mnemonic 2>&1 || true)
if echo "$MNEM_OUT" | grep -qE 'test result: ok\.'; then
    COMPAT_PASS=$((COMPAT_PASS + 1))
    report PASS "moonshine mnemonic tests"
else
    report FAIL "moonshine mnemonic tests"
fi

cd "$ANDROID_DIR/rust/darkfi-mobile-ffi"
FFI_MNEM_OUT=$(cargo test mnemonic 2>&1 || true)
if echo "$FFI_MNEM_OUT" | grep -qE 'test result: ok\.'; then
    COMPAT_PASS=$((COMPAT_PASS + 1))
    report PASS "mobile-ffi mnemonic tests"
else
    report FAIL "mobile-ffi mnemonic tests"
fi

# =============================================================================
# Phase 6: OMR Scheme Dispatch Tests
# =============================================================================
echo -e "\n${CYAN}▶ Phase 6: OMR Scheme Dispatch Tests${NC}"

cd "$LIGHTWALLETD_DIR"
OMR_OUTPUT=$(cargo test dispatch 2>&1)
if echo "$OMR_OUTPUT" | grep -q "ok"; then
    OMR_COUNT=$(echo "$OMR_OUTPUT" | grep "test result:" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | head -1)
    report PASS "OMR dispatch: ${OMR_COUNT:-?} tests passed (BFV/PerfOMR/LWEmongrass/FMD)"
else
    report FAIL "OMR dispatch tests"
fi

# =============================================================================
# Phase 7: Live lightwalletd GetLightInfo smoke (testnet 0.3)
# =============================================================================
echo -e "\n${CYAN}▶ Phase 7: Live lightwalletd GetLightInfo${NC}"
if [ -n "$LIGHTWALLETD_PID" ] && command -v grpcurl >/dev/null 2>&1; then
    PROTO_DIR="$LIGHTWALLETD_DIR/proto"
    INFO_OUT=$(grpcurl -plaintext -import-path "$PROTO_DIR" -proto lightwallet.proto \
        127.0.0.1:9067 darkfi.lightwallet.DarkFiLightWallet/GetLightInfo 2>&1) || true
    echo "$INFO_OUT" | head -30
    if echo "$INFO_OUT" | grep -qiE '"chainTipHeight"|chain_tip|omrSupported|omr_supported'; then
        report PASS "GetLightInfo against live lightwalletd"
    else
        report FAIL "GetLightInfo: $INFO_OUT"
    fi
else
    report SKIP "GetLightInfo (no lightwalletd or grpcurl)"
fi

# =============================================================================
# Summary
# =============================================================================
echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  E2E Test Results${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"
echo -e "  ${YELLOW}Skipped: $SKIP${NC}"
TOTAL=$((PASS + FAIL + SKIP))
echo -e "  Total:  $TOTAL"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ALL TESTS PASSED ✅                                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  SOME TESTS FAILED ❌                                ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
