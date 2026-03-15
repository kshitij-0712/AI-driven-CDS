#!/usr/bin/env bash
#
# Batch Deep Analysis Runner
# ===========================
#
# Processes ALL remaining binaries (Ghidra + angr) unattended, using
# analyze_single.py for each binary with subprocess isolation.
#
# Key design choices:
#   - Shell script (not Python) so it survives Python/angr crashes
#   - Each binary is analyzed in its own Python subprocess
#   - If one subprocess crashes (segfault, OOM, etc.), the script continues
#   - Uses analyze_single.py's tracker file for skip/resume logic
#   - Runs Ghidra first, then angr, per binary (can't run in parallel — memory)
#   - Logs everything to data/processed/batch_analysis.log
#
# Usage:
#   bash src/run_batch_analysis.sh              # Run all pending
#   bash src/run_batch_analysis.sh --ghidra-only  # Only Ghidra passes
#   bash src/run_batch_analysis.sh --angr-only    # Only angr passes
#   bash src/run_batch_analysis.sh --dry-run      # Show what would run
#

set -o pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
PYTHON="${BASE_DIR}/.venv/bin/python"
ANALYZE_SCRIPT="${SCRIPT_DIR}/analyze_single.py"
LOG_FILE="${BASE_DIR}/data/processed/batch_analysis.log"
TRACKER_FILE="${BASE_DIR}/data/processed/analysis_tracker.txt"
GHIDRA_DIR="${BASE_DIR}/data/processed/ghidra_features"
ANGR_DIR="${BASE_DIR}/data/processed/angr_features"

export PYTHONPATH="${BASE_DIR}/src"

# --- Parse arguments ---
MODE="both"  # both, ghidra-only, angr-only
DRY_RUN=0
GHIDRA_TIMEOUT=1800
ANGR_TIMEOUT=900

for arg in "$@"; do
    case "$arg" in
        --ghidra-only) MODE="ghidra-only" ;;
        --angr-only)   MODE="angr-only" ;;
        --dry-run)     DRY_RUN=1 ;;
        --ghidra-timeout=*) GHIDRA_TIMEOUT="${arg#*=}" ;;
        --angr-timeout=*)  ANGR_TIMEOUT="${arg#*=}" ;;
    esac
done

# --- Logging ---
mkdir -p "$(dirname "$LOG_FILE")"
log() {
    local msg="[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $1"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE"
}

# --- Get the full target list from analyze_single.py --list ---
# Parse the output to extract SHA256 prefixes and their Ghidra/angr status
get_pending_binaries() {
    local tool="$1"  # "ghidra" or "angr"
    
    "$PYTHON" "$ANALYZE_SCRIPT" --list 2>/dev/null | \
    while IFS= read -r line; do
        # Lines look like:
        # 1    94f2e4d8d4436874   28.9MB miner                  90 PENDING  PENDING
        # Extract: number, sha_prefix, size, classification, priority, ghidra_status, angr_status
        if echo "$line" | grep -qE '^\s*[0-9]+\s+[0-9a-f]{16}'; then
            sha_prefix=$(echo "$line" | awk '{print $2}')
            ghidra_status=$(echo "$line" | awk '{print $6}')
            angr_status=$(echo "$line" | awk '{print $7}')
            size=$(echo "$line" | awk '{print $3}')
            classification=$(echo "$line" | awk '{print $4}')
            
            if [ "$tool" = "ghidra" ] && [ "$ghidra_status" = "PENDING" ]; then
                echo "${sha_prefix}|${size}|${classification}"
            elif [ "$tool" = "angr" ] && [ "$angr_status" = "PENDING" ]; then
                echo "${sha_prefix}|${size}|${classification}"
            fi
        fi
    done
}

# --- Main execution ---
log "========================================================"
log "BATCH DEEP ANALYSIS — Starting"
log "Mode: $MODE | Ghidra timeout: ${GHIDRA_TIMEOUT}s | angr timeout: ${ANGR_TIMEOUT}s"
log "========================================================"

# Collect pending binaries for each tool
GHIDRA_PENDING=""
ANGR_PENDING=""

if [ "$MODE" = "both" ] || [ "$MODE" = "ghidra-only" ]; then
    GHIDRA_PENDING=$(get_pending_binaries "ghidra")
    GHIDRA_COUNT=$(echo "$GHIDRA_PENDING" | grep -c '[0-9a-f]' || true)
    log "Ghidra pending: $GHIDRA_COUNT binaries"
fi

if [ "$MODE" = "both" ] || [ "$MODE" = "angr-only" ]; then
    ANGR_PENDING=$(get_pending_binaries "angr")
    ANGR_COUNT=$(echo "$ANGR_PENDING" | grep -c '[0-9a-f]' || true)
    log "angr pending: $ANGR_COUNT binaries"
fi

# Build a unique ordered list of all SHA prefixes that need work
# (process each binary fully: Ghidra then angr, before moving to next)
ALL_SHAS=""
if [ "$MODE" = "both" ]; then
    # Merge both lists, deduplicate, preserve order
    ALL_SHAS=$(echo -e "${GHIDRA_PENDING}\n${ANGR_PENDING}" | \
               awk -F'|' '{print $1}' | grep '[0-9a-f]' | awk '!seen[$0]++')
elif [ "$MODE" = "ghidra-only" ]; then
    ALL_SHAS=$(echo "$GHIDRA_PENDING" | awk -F'|' '{print $1}' | grep '[0-9a-f]')
elif [ "$MODE" = "angr-only" ]; then
    ALL_SHAS=$(echo "$ANGR_PENDING" | awk -F'|' '{print $1}' | grep '[0-9a-f]')
fi

TOTAL=$(echo "$ALL_SHAS" | grep -c '[0-9a-f]' || true)

if [ "$TOTAL" -eq 0 ]; then
    log "Nothing to do — all binaries already analyzed!"
    exit 0
fi

log "Total unique binaries to process: $TOTAL"

if [ "$DRY_RUN" -eq 1 ]; then
    log "[DRY RUN] Would process:"
    echo "$ALL_SHAS" | while read -r sha; do
        needs_ghidra=""
        needs_angr=""
        echo "$GHIDRA_PENDING" | grep -q "^${sha}" && needs_ghidra="Ghidra"
        echo "$ANGR_PENDING" | grep -q "^${sha}" && needs_angr="angr"
        log "  ${sha}: ${needs_ghidra} ${needs_angr}"
    done
    exit 0
fi

# --- Process each binary ---
DONE=0
GHIDRA_OK=0
GHIDRA_FAIL=0
ANGR_OK=0
ANGR_FAIL=0
START_TIME=$(date +%s)

echo "$ALL_SHAS" | while read -r sha; do
    [ -z "$sha" ] && continue
    
    DONE=$((DONE + 1))
    log "--------------------------------------------------------"
    log "[$DONE/$TOTAL] Processing: $sha"
    log "--------------------------------------------------------"
    
    # --- Ghidra pass ---
    if [ "$MODE" != "angr-only" ]; then
        # Check if Ghidra output already exists (in case tracker is stale)
        if [ -f "${GHIDRA_DIR}/${sha}"*.json ] 2>/dev/null; then
            log "  [Ghidra] SKIP — output file exists"
        elif echo "$GHIDRA_PENDING" | grep -q "^${sha}"; then
            log "  [Ghidra] Starting (timeout: ${GHIDRA_TIMEOUT}s)..."
            GHIDRA_START=$(date +%s)
            
            if "$PYTHON" "$ANALYZE_SCRIPT" \
                --ghidra-only \
                --ghidra-timeout "$GHIDRA_TIMEOUT" \
                "$sha" >> "$LOG_FILE" 2>&1; then
                GHIDRA_ELAPSED=$(( $(date +%s) - GHIDRA_START ))
                log "  [Ghidra] OK (${GHIDRA_ELAPSED}s)"
                GHIDRA_OK=$((GHIDRA_OK + 1))
            else
                GHIDRA_ELAPSED=$(( $(date +%s) - GHIDRA_START ))
                EXIT_CODE=$?
                log "  [Ghidra] FAILED — exit code $EXIT_CODE (${GHIDRA_ELAPSED}s)"
                GHIDRA_FAIL=$((GHIDRA_FAIL + 1))
            fi
        else
            log "  [Ghidra] SKIP — already done"
        fi
    fi
    
    # --- angr pass ---
    if [ "$MODE" != "ghidra-only" ]; then
        # Check if angr output already exists
        if [ -f "${ANGR_DIR}/${sha}"*.json ] 2>/dev/null; then
            log "  [angr] SKIP — output file exists"
        elif echo "$ANGR_PENDING" | grep -q "^${sha}"; then
            log "  [angr] Starting (base timeout: ${ANGR_TIMEOUT}s, auto-adjusted for size)..."
            ANGR_START=$(date +%s)
            
            if "$PYTHON" "$ANALYZE_SCRIPT" \
                --angr-only \
                --angr-timeout "$ANGR_TIMEOUT" \
                "$sha" >> "$LOG_FILE" 2>&1; then
                ANGR_ELAPSED=$(( $(date +%s) - ANGR_START ))
                log "  [angr] OK (${ANGR_ELAPSED}s)"
                ANGR_OK=$((ANGR_OK + 1))
            else
                ANGR_ELAPSED=$(( $(date +%s) - ANGR_START ))
                EXIT_CODE=$?
                log "  [angr] FAILED — exit code $EXIT_CODE (${ANGR_ELAPSED}s)"
                ANGR_FAIL=$((ANGR_FAIL + 1))
            fi
        else
            log "  [angr] SKIP — already done"
        fi
    fi
done

TOTAL_TIME=$(( $(date +%s) - START_TIME ))
log "========================================================"
log "BATCH ANALYSIS COMPLETE"
log "Total time: ${TOTAL_TIME}s ($(( TOTAL_TIME / 60 )) min)"
log "Ghidra: $GHIDRA_OK ok, $GHIDRA_FAIL failed"
log "angr: $ANGR_OK ok, $ANGR_FAIL failed"
log "========================================================"

# Print final status
"$PYTHON" "$ANALYZE_SCRIPT" --list
