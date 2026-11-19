#!/usr/bin/env bash
# Moonshine ↔ iOS live testnet matrix:
#   - TX_COUNT wallet sends targeting the published iOS receive address
#   - UNIFOMR_COUNT UnifOMR sync/register iterations
#   - TRIAL_COUNT trial-decrypt sync iterations (random wallet each time)
#
# Attaches to local darkfid :18345 + lightwalletd :9067 (testnet). Refuses ngrok.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOON="${MOON:-$ROOT/target/release/moonshine}"
SERVER="${SERVER:-http://127.0.0.1:9067}"
TX_COUNT="${TX_COUNT:-50}"
UNIFOMR_COUNT="${UNIFOMR_COUNT:-200}"
TRIAL_COUNT="${TRIAL_COUNT:-450}"
AMOUNT="${AMOUNT:-0.00001}"
FEE="${FEE:-500000}"
IOS_ADDR="${IOS_ADDR:-fT11df6J8Mue19Mh1QwdhRaAMGucU6X3F71WdJZsWFMd2HfvLNtMnhud}"
LOG="${LOG:-/tmp/nh-e2e-ios-50-200-450.log}"
EXPLORER="${EXPLORER:-https://explorer.testnet.dark.fi}"

# e2e_pub_mne_1 holds the spendable DRK reserve for Phase A on live testnet.
SENDERS=(e2e_pub_mne_1 e2e_matrix_b e2e_bob e2e_alice)

if [[ "$SERVER" == *ngrok* || "$SERVER" == *epidermis* ]]; then
  echo "refusing Studio/ngrok SERVER=$SERVER"
  exit 1
fi
if [[ ! -x "$MOON" ]]; then
  echo "missing moonshine: $MOON"
  exit 1
fi
if ! lsof -nP -iTCP:9067 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "lightwalletd not on :9067"
  exit 1
fi

atomic_balance() {
  local w="$1"
  "$MOON" -w "$w" balance 2>/dev/null | sed -n 's/.*(\([0-9][0-9]*\) atomic units).*/\1/p' | head -1
}

pick_sender() {
  local w bal need
  need=$((FEE + 10000))
  for w in "${SENDERS[@]}"; do
    bal="$(atomic_balance "$w" || true)"
    bal="${bal:-0}"
    if [[ "$bal" =~ ^[0-9]+$ ]] && (( bal > need )); then
      echo "$w"
      return 0
    fi
  done
  return 1
}

: >"$LOG"
# NOTE: `exec > >(tee …)` can die under macOS nohup/SIGHUP. For detached runs
# use a double-fork/setsid wrapper (see /tmp/nh-mine/run_matrix_bc.sh pattern).
exec > >(tee -a "$LOG") 2>&1

echo "=== moonshine↔iOS matrix $(date '+%Y-%m-%dT%H:%M:%S%z') ==="
echo "server=$SERVER ios=$IOS_ADDR tx=$TX_COUNT unifomr=$UNIFOMR_COUNT trial=$TRIAL_COUNT amount=$AMOUNT fee=$FEE"
for w in "${SENDERS[@]}"; do
  echo "  $w balance_atomic=$(atomic_balance "$w" || echo 0)"
done

tx_ok=0
tx_fail=0
echo
echo "=== PHASE A: wallet txs → iOS ($TX_COUNT) ==="
for ((i=0; i<TX_COUNT; i++)); do
  sender="$(pick_sender || true)"
  if [[ -z "${sender}" ]]; then
    echo "STOP: no funded sender left after ok=$tx_ok fail=$tx_fail"
    break
  fi
  if (( i % 2 == 0 )); then
    mode=UnifOMR
    args=(tx send --to "$IOS_ADDR" --amount "$AMOUNT" --fee "$FEE" --memo "ios-e2e-u-$i")
  else
    mode=TrialDecrypt
    args=(tx send --to "$IOS_ADDR" --amount "$AMOUNT" --fee "$FEE" --memo "ios-e2e-t-$i" --no-omr)
  fi
  echo "[tx $((i+1))/$TX_COUNT] sender=$sender mode=$mode bal=$(atomic_balance "$sender")"
  # Sync with backoff when LWD rate-limits (common under parallel load).
  for attempt in 1 2 3 4 5; do
    sout=$("$MOON" -w "$sender" --server "$SERVER" sync --force-trial 2>&1) || true
    if echo "$sout" | rg -q 'rate limit'; then
      echo "  sync rate-limited; sleep $((attempt*5))s"
      sleep $((attempt * 5))
      continue
    fi
    echo "$sout" | tail -4
    break
  done
  out=$("$MOON" -w "$sender" --server "$SERVER" "${args[@]}" 2>&1) || true
  echo "$out" | tail -12
  if echo "$out" | rg -q 'broadcast successfully|TX hash:'; then
    hash=$(echo "$out" | rg -o '[a-f0-9]{64}' | tail -1 || true)
    echo "  OK hash=$hash explorer=$EXPLORER/tx/$hash"
    tx_ok=$((tx_ok+1))
    # Let tip advance / change mature before next spend.
    sleep 8
  else
    echo "  FAIL"
    tx_fail=$((tx_fail+1))
    if echo "$out" | rg -q 'Failed simulating|broadcast failed'; then
      sleep 15
    fi
  fi
done
echo "PHASE A RESULT ok=$tx_ok fail=$tx_fail"

echo
echo "=== PHASE B: UnifOMR register/sync iterations ($UNIFOMR_COUNT) ==="
echo "NOTE: if LWD reports OMR disabled, register success still counts; detection may fail closed."
u_ok=0
u_fail=0
for ((i=0; i<UNIFOMR_COUNT; i++)); do
  idx=$((RANDOM % ${#SENDERS[@]}))
  w="${SENDERS[$idx]}"
  out=""
  for attempt in 1 2 3 4 5; do
    out=$("$MOON" -w "$w" --server "$SERVER" sync --unifomr 2>&1) || true
    if echo "$out" | rg -q 'rate limit|ResourceExhausted'; then
      echo "[unifomr $((i+1))] rate-limited; sleep $((attempt*8))s"
      sleep $((attempt * 8))
      continue
    fi
    break
  done
  # Success: full sync OK, or RegisterCluePublicKey landed (unix key_version).
  if echo "$out" | rg -q 'Registered UnifOMR clue|Sync complete|already registered|Caught up'; then
    u_ok=$((u_ok+1))
  elif echo "$out" | rg -q 'OMR detection failed|strict UnifOMR refuses' && echo "$out" | rg -q 'Registered UnifOMR clue'; then
    u_ok=$((u_ok+1))
  else
    u_fail=$((u_fail+1))
    echo "[unifomr $((i+1))] FAIL wallet=$w"
    echo "$out" | tail -8
  fi
  if (( (i+1) % 25 == 0 )); then
    echo "[unifomr $((i+1))/$UNIFOMR_COUNT] ok=$u_ok fail=$u_fail"
  fi
  sleep 0.2
done
echo "PHASE B RESULT ok=$u_ok fail=$u_fail"

echo
echo "=== PHASE C: trial-decrypt sync iterations ($TRIAL_COUNT, random wallets) ==="
t_ok=0
t_fail=0
for ((i=0; i<TRIAL_COUNT; i++)); do
  idx=$((RANDOM % ${#SENDERS[@]}))
  w="${SENDERS[$idx]}"
  if (( RANDOM % 2 == 0 )); then
    cmd=(sync --force-trial)
    label=force-trial
  else
    cmd=(sync)
    label=trial-default
  fi
  if out=$("$MOON" -w "$w" --server "$SERVER" "${cmd[@]}" 2>&1); then
    t_ok=$((t_ok+1))
  else
    t_fail=$((t_fail+1))
    echo "[trial $((i+1))] FAIL wallet=$w mode=$label"
    echo "$out" | tail -5
  fi
  if (( (i+1) % 50 == 0 )); then
    echo "[trial $((i+1))/$TRIAL_COUNT] ok=$t_ok fail=$t_fail"
  fi
done
echo "PHASE C RESULT ok=$t_ok fail=$t_fail"

echo
echo "=== SUMMARY ==="
echo "tx: ok=$tx_ok fail=$tx_fail / $TX_COUNT"
echo "unifomr: ok=$u_ok fail=$u_fail / $UNIFOMR_COUNT"
echo "trial: ok=$t_ok fail=$t_fail / $TRIAL_COUNT"
echo "log=$LOG"
# Soft-pass if we got any txs (when requested) and unifomr/trial mostly green.
if (( TX_COUNT > 0 && tx_ok == 0 )); then
  echo "HARD FAIL: zero successful wallet txs (likely funding / tip stuck)"
  exit 2
fi
if (( u_fail > u_ok || t_fail > t_ok )); then
  exit 1
fi
exit 0
