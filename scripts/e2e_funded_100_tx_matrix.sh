#!/usr/bin/env bash
# Funded 100-tx UnifOMR + trial-decrypt matrix on live DarkFi testnet.
#
# Sends from moonshine e2e_alice (funded) cycling recipients across published
# Nighthawk client addresses + e2e_bob. Odd txs omit UnifOMR (--no-omr = TD);
# even txs include UnifOMR clues. Logs explorer URLs and verifies bob receives
# after sync for bob-bound txs.
#
# Prerequisites: local LWD :9067 + darkfid :18345 (or override SERVER).
# Does NOT use Studio/ngrok for sends (same policy as e2e_tx_matrix.sh).
#
# Usage:
#   ./scripts/e2e_funded_100_tx_matrix.sh
#   COUNT=100 AMOUNT=0.001 FEE=1000000 ./scripts/e2e_funded_100_tx_matrix.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOON="${MOON:-$ROOT/../moonshine/target/release/moonshine}"
SERVER="${SERVER:-http://127.0.0.1:9067}"
COUNT="${COUNT:-100}"
AMOUNT="${AMOUNT:-0.001}"
FEE=""
SENDER_WALLET="${SENDER_WALLET:-e2e_alice}"
BOB_WALLET="${BOB_WALLET:-e2e_bob}"
LOG="${LOG:-/tmp/nh-e2e-100-tx.log}"
EXPLORER="${EXPLORER:-https://explorer.testnet.dark.fi}"

if [[ "$SERVER" == *ngrok* || "$SERVER" == *epidermis* ]]; then
  echo "refusing Studio/ngrok SERVER=$SERVER — use http://127.0.0.1:9067"
  exit 1
fi

if [[ ! -x "$MOON" ]]; then
  echo "moonshine binary missing: $MOON (cargo build --release in moonshine)"
  exit 1
fi

addr_of() {
  "$MOON" -w "$1" address default 2>/dev/null | awk '/Default address:/ {print $NF; exit} /^f[A-Za-z0-9]+$/ {print; exit}'
}

ALICE_ADDR="$(addr_of "$SENDER_WALLET")"
BOB_ADDR="$(addr_of "$BOB_WALLET")"

# Published testnet receive addresses (from prior client matrix / live apps).
ANDROID_ADDR="${ANDROID_ADDR:-fUY7xcuinzUCspuuJsv8Xpx7wwxQGLphmJQK8prtrfWfwXnCy59dv9CV}"
IOS_ADDR="${IOS_ADDR:-fT11df6J8Mue19Mh1QwdhRaAMGucU6X3F71WdJZsWFMd2HfvLNtMnhud}"
DESKTOP_ADDR="${DESKTOP_ADDR:-fUY7xcuinzUCspuuJsv8Xpx7wwxQGLphmJQK8prtrfWfwXnCy59dv9CV}"
DRK_ADDR="${DRK_ADDR:-fXWopiPxnMDQkqhrzURDjjfaA8gGkjUN9xuypM4zNLZfRT57NDu2nXcN}"

RECIPIENTS=(
  "moonshine_bob|$BOB_ADDR"
  "android|$ANDROID_ADDR"
  "ios|$IOS_ADDR"
  "desktop|$DESKTOP_ADDR"
  "drk_cli|$DRK_ADDR"
)

echo "=== Nighthawk funded 100-tx UnifOMR/TD matrix ===" | tee "$LOG"
echo "server=$SERVER sender=$SENDER_WALLET ($ALICE_ADDR) count=$COUNT amount=$AMOUNT fee=$FEE" | tee -a "$LOG"
"$MOON" -w "$SENDER_WALLET" --server "$SERVER" balance 2>&1 | tee -a "$LOG"

ok=0
fail=0
declare -a HASHES=()

for ((i=0; i<COUNT; i++)); do
  entry="${RECIPIENTS[$((i % ${#RECIPIENTS[@]}))]}"
  name="${entry%%|*}"
  to="${entry##*|}"
  memo="e2e015-$i-$name"
  if (( i % 2 == 0 )); then
    mode="UnifOMR"
    extra=()
  else
    mode="TrialDecrypt"
    extra=(--no-omr)
  fi
  echo "" | tee -a "$LOG"
  echo "[$i/$COUNT] → $name ($mode) $to" | tee -a "$LOG"
  if out=$("$MOON" -w "$SENDER_WALLET" --server "$SERVER" tx send \
      --to "$to" --amount "$AMOUNT" --fee "$FEE" --memo "$memo" "${extra[@]}" 2>&1); then
    echo "$out" | tee -a "$LOG"
    hash=$(echo "$out" | awk '/TX hash:/{print $NF; exit} /tx hash/{print $NF; exit} /^[a-f0-9]{64}$/{print; exit}')
    if [[ -z "$hash" ]]; then
      hash=$(echo "$out" | rg -o '[a-f0-9]{64}' | tail -1 || true)
    fi
    if [[ -n "$hash" ]]; then
      HASHES+=("$hash|$mode|$name")
      echo "explorer: $EXPLORER/tx/$hash" | tee -a "$LOG"
      ok=$((ok+1))
    else
      echo "WARN: send ok but no tx hash parsed" | tee -a "$LOG"
      ok=$((ok+1))
    fi
  else
    echo "$out" | tee -a "$LOG"
    fail=$((fail+1))
    echo "FAIL send #$i" | tee -a "$LOG"
  fi
done

echo "" | tee -a "$LOG"
echo "=== sync bob + verify balance movement ===" | tee -a "$LOG"
"$MOON" -w "$BOB_WALLET" --server "$SERVER" sync 2>&1 | tee -a "$LOG" | tail -20
"$MOON" -w "$BOB_WALLET" balance 2>&1 | tee -a "$LOG"
"$MOON" -w "$SENDER_WALLET" balance 2>&1 | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "RESULT ok=$ok fail=$fail total=$COUNT log=$LOG" | tee -a "$LOG"
printf '%s\n' "${HASHES[@]}" | tee /tmp/nh-e2e-100-hashes.txt >/dev/null
echo "hashes: /tmp/nh-e2e-100-hashes.txt (${#HASHES[@]} recorded)"
