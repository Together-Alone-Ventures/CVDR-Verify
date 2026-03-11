#!/bin/bash
# ============================================================
# CVDR-Verify: MKTd02 quick verification helper
# Performs V1 (sanity-only), V3, and V4 checks via dfx for
# both mktd02-v2 and mktd02-v3 receipts.
# V2 certificate-path verification is provided by the Rust CLI.
# ============================================================

set -euo pipefail

# --- Argument parsing ---
if [ $# -lt 2 ]; then
  echo "Usage: $0 <canister-id> <receipt-id-hex> [--network <dfx-network>]"
  echo ""
  echo "  canister-id    : Principal of the canister that holds the receipt"
  echo "  receipt-id-hex : Hex-encoded receipt ID"
  echo "  --network      : dfx network (default: local)"
  exit 1
fi

CANISTER_ID="$1"
RECEIPT_ID="$2"
NETWORK="local"

shift 2
while [ $# -gt 0 ]; do
  case "$1" in
    --network) NETWORK="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

NETWORK_FLAG="--network $NETWORK --identity anonymous"
PASS=0
FAIL=0
V1_RESULT=""
V3_RESULT=""
V4_RESULT=""

echo "============================================================"
echo " CVDR-Verify: MKTd02 Quick Verification Helper"
echo " Canister : $CANISTER_ID"
echo " Receipt  : $RECEIPT_ID"
echo " Network  : $NETWORK"
echo "============================================================"
echo ""

# --- Step 1: Fetch receipt ---
echo "[1/4] Fetching receipt..."

RECEIPT_RAW=$(dfx canister call "$CANISTER_ID" mktd_get_receipt "(\"$RECEIPT_ID\")" $NETWORK_FLAG 2>&1) || {
  echo "FATAL: Failed to fetch receipt. dfx output:"
  echo "$RECEIPT_RAW"
  exit 1
}

# Check for success — look for "record" in response
if ! echo "$RECEIPT_RAW" | grep -q "record"; then
  echo "FATAL: Receipt not found. Response:"
  echo "$RECEIPT_RAW"
  exit 1
fi

echo "  Receipt fetched successfully."
echo ""

# --- Extract fields from Candid text output ---
# dfx may return numeric field IDs if a local .did is unavailable.
# This helper only parses the subset needed for V1 sanity + V3 + V4:
#   protocol_version, pre_state_hash, post_state_hash, module_hash,
#   deletion_seq (v2 fallback: nonce), timestamp
# record_id is supported by the Rust CLI path and is not required for this
# quick helper's V1-sanity/V3/V4 checks.

# Extract a quoted hex string field by key
extract_hex() {
  local raw="$1"
  local key="$2"
  echo "$raw" | grep -oP "${key}\s*=\s*\"\K[0-9a-fA-F]{64}" | head -1 || echo ""
}

# Extract a numeric field by key (strips underscores)
extract_num() {
  local raw="$1"
  local key="$2"
  echo "$raw" | grep -oP "${key}\s*=\s*\K[0-9_]+" | head -1 | tr -d '_' || echo ""
}

# Use numeric Candid field IDs (dfx returns these without .did file)
# Also try named fields in case Candid interface is available
PRE_STATE_HASH=$(extract_hex "$RECEIPT_RAW" "3_547_308_504")
[ -z "$PRE_STATE_HASH" ] && PRE_STATE_HASH=$(extract_hex "$RECEIPT_RAW" "pre_state_hash")
POST_STATE_HASH=$(extract_hex "$RECEIPT_RAW" "1_590_697_147")
[ -z "$POST_STATE_HASH" ] && POST_STATE_HASH=$(extract_hex "$RECEIPT_RAW" "post_state_hash")
MODULE_HASH=$(extract_hex "$RECEIPT_RAW" "2_928_387_969")
[ -z "$MODULE_HASH" ] && MODULE_HASH=$(extract_hex "$RECEIPT_RAW" "module_hash")
PROTOCOL_VERSION=$(echo "$RECEIPT_RAW" | grep -oP 'protocol_version\s*=\s*"\K[^"]+' | head -1 || echo "")
DELETION_SEQ=$(extract_num "$RECEIPT_RAW" "2_680_573_167")
[ -z "$DELETION_SEQ" ] && DELETION_SEQ=$(extract_num "$RECEIPT_RAW" "deletion_seq")
[ -z "$DELETION_SEQ" ] && DELETION_SEQ=$(extract_num "$RECEIPT_RAW" "nonce")
TIMESTAMP=$(extract_num "$RECEIPT_RAW" "2_781_795_542")
[ -z "$TIMESTAMP" ] && TIMESTAMP=$(extract_num "$RECEIPT_RAW" "timestamp")

ZEROS="0000000000000000000000000000000000000000000000000000000000000000"

# --- Step 2: V1 Partial — Field Sanity Checks ---
echo "[2/4] V1 (sanity-only): Field sanity checks..."
if [ -n "$PROTOCOL_VERSION" ]; then
  echo "  protocol_version: $PROTOCOL_VERSION"
fi

V1_PASS=true
V1_DETAILS=""

if [ -z "$PRE_STATE_HASH" ] || [ -z "$POST_STATE_HASH" ]; then
  V1_PASS=false
  V1_DETAILS="  FAIL: Could not parse state hashes from receipt"
elif [ "$PRE_STATE_HASH" = "$POST_STATE_HASH" ]; then
  V1_PASS=false
  V1_DETAILS="  FAIL: pre_state_hash == post_state_hash (state did not change)"
elif [ "$PRE_STATE_HASH" = "$ZEROS" ]; then
  V1_PASS=false
  V1_DETAILS="  FAIL: pre_state_hash is all zeros (uninitialised)"
fi

if [ -z "$DELETION_SEQ" ] || [ "$DELETION_SEQ" -le 0 ] 2>/dev/null; then
  V1_PASS=false
  V1_DETAILS="${V1_DETAILS}\n  FAIL: deletion_seq is zero or missing (v2 fallback key: nonce)"
fi

if [ -z "$TIMESTAMP" ] || [ "$TIMESTAMP" -le 0 ] 2>/dev/null; then
  V1_PASS=false
  V1_DETAILS="${V1_DETAILS}\n  FAIL: timestamp is zero or missing"
fi

if [ "$V1_PASS" = true ]; then
  V1_RESULT="PASS"
  echo "  V1 (sanity-only): PASS — state transition fields look consistent"
else
  V1_RESULT="FAIL"
  echo "  V1 (sanity-only): FAIL"
  echo -e "$V1_DETAILS"
fi
echo ""

# --- Step 3: V3 — Module Hash Check ---
echo "[3/4] V3: Module hash verification..."

CANISTER_INFO=$(dfx canister info "$CANISTER_ID" $NETWORK_FLAG 2>&1) || {
  echo "  WARNING: Could not fetch canister info. V3 skipped."
  V3_RESULT="SKIPPED"
  CANISTER_INFO=""
}

if [ -n "$CANISTER_INFO" ]; then
  ONCHAIN_HASH=$(echo "$CANISTER_INFO" | grep -oP "Module hash:\s*0x\K[0-9a-fA-F]{64}" | head -1)

  if [ -z "$ONCHAIN_HASH" ]; then
    ONCHAIN_HASH=$(echo "$CANISTER_INFO" | grep -oP "Module hash:\s*\K[0-9a-fA-F]{64}" | head -1)
  fi

  if [ -z "$ONCHAIN_HASH" ]; then
    echo "  WARNING: Could not parse module hash from canister status."
    V3_RESULT="SKIPPED"
  elif [ -z "$MODULE_HASH" ]; then
    echo "  WARNING: Could not parse module hash from receipt."
    V3_RESULT="SKIPPED"
  elif [ "${MODULE_HASH,,}" = "$ZEROS" ]; then
    V3_RESULT="MISMATCH-SUSPICIOUS"
    echo "  V3: MISMATCH-SUSPICIOUS — receipt has dev zeros, cannot verify code provenance"
  elif [ "${ONCHAIN_HASH,,}" = "${MODULE_HASH,,}" ]; then
    V3_RESULT="MATCH"
    echo "  V3: MATCH — canister code unchanged since deletion"
  else
    V3_RESULT="MISMATCH-EXPECTED"
    echo "  V3: MISMATCH-EXPECTED — canister upgraded since deletion"
    echo "       Receipt remains valid under prior code version."
  fi
fi
echo ""

# --- Step 4: V4 — Tombstone Persistence ---
echo "[4/4] V4: Tombstone persistence check..."

V4_PASS=true
V4_DETAILS=""

TOMBSTONE_RAW=$(dfx canister call "$CANISTER_ID" mktd_get_tombstone_status $NETWORK_FLAG 2>&1) || {
  echo "  WARNING: Could not query tombstone status."
  V4_PASS=false
  V4_DETAILS="  FAIL: tombstone status query failed"
}

if [ "$V4_PASS" = true ]; then
  if echo "$TOMBSTONE_RAW" | grep -qE "is_tombstoned.*=.*true|3_838_882_660.*=.*true"; then
    echo "  Tombstone: active"
  else
    V4_PASS=false
    V4_DETAILS="  FAIL: canister is not tombstoned"
  fi
fi

if [ "$V4_PASS" = true ]; then
  STATE_HASH_RAW=$(dfx canister call "$CANISTER_ID" mktd_get_state_hash $NETWORK_FLAG 2>&1) || {
    V4_PASS=false
    V4_DETAILS="  FAIL: state hash query failed"
  }

  if [ "$V4_PASS" = true ]; then
    # State hash may be returned as blob "\xx\xx..." or hex string
    CURRENT_HASH=$(echo "$STATE_HASH_RAW" | grep -oP '[0-9a-fA-F]{64}' | head -1 || true)
    if [ -z "$CURRENT_HASH" ]; then
      CURRENT_HASH=$(echo "$STATE_HASH_RAW" | grep -o 'blob "[^"]*"' | head -1 | sed 's/blob "//;s/"//;s/\\//g' || true)
    fi

    if [ -z "$CURRENT_HASH" ]; then
      V4_PASS=false
      V4_DETAILS="  FAIL: could not parse current state hash"
    elif [ "${CURRENT_HASH,,}" = "${POST_STATE_HASH,,}" ]; then
      echo "  State hash: matches post_state_hash from receipt"
    else
      V4_PASS=false
      V4_DETAILS="  FAIL: current state hash differs from receipt post_state_hash"
      V4_DETAILS="${V4_DETAILS}\n    Receipt:  $POST_STATE_HASH"
      V4_DETAILS="${V4_DETAILS}\n    Current:  $CURRENT_HASH"
    fi
  fi
fi

if [ "$V4_PASS" = true ]; then
  V4_RESULT="PASS"
  echo "  V4: PASS — tombstone intact, state hash matches"
else
  V4_RESULT="FAIL"
  echo "  V4: FAIL"
  echo -e "$V4_DETAILS"
fi
echo ""

# --- Summary ---
echo "============================================================"
echo " CVDR Verification Summary"
echo "============================================================"
printf " %-16s : %s\n" "V1 (sanity)" "$V1_RESULT"
printf " %-16s : %s\n" "V2 (BLS cert)" "SKIPPED — requires Rust CLI"
printf " %-16s : %s\n" "V3 (module)" "$V3_RESULT"
printf " %-16s : %s\n" "V4 (tombstone)" "$V4_RESULT"
echo "============================================================"

# Exit code
if [ "$V1_RESULT" = "PASS" ] && [ "$V4_RESULT" = "PASS" ] && [ "$V3_RESULT" != "FAIL" ]; then
  exit 0
else
  exit 1
fi
