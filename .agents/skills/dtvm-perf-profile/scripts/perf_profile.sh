#!/usr/bin/env bash
# DTVM perf profiling script
# Usage: perf_profile.sh [--perf PATH] [--output-dir DIR] [--skip-inject] -- <dtvm command...>
set -euo pipefail

PERF_BIN="perf"
OUTPUT_DIR="."
SKIP_INJECT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --perf)       PERF_BIN="$2"; shift 2;;
    --output-dir) OUTPUT_DIR="$2"; shift 2;;
    --skip-inject) SKIP_INJECT=true; shift;;
    --)           shift; break;;
    *)            break;;
  esac
done

if [[ $# -eq 0 ]]; then
  echo "Error: no dtvm command provided" >&2
  echo "Usage: $0 [--perf PATH] [--output-dir DIR] -- <dtvm command...>" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
PERF_DATA="$OUTPUT_DIR/perf_dtvm.data"
PERF_JIT_DATA="$OUTPUT_DIR/perf_dtvm_jit.data"
REPORT_TXT="$OUTPUT_DIR/perf_report.txt"
REPORT_DSO="$OUTPUT_DIR/perf_report_dso.txt"
PARSED="$OUTPUT_DIR/perf_parsed.txt"
SUMMARY="$OUTPUT_DIR/perf_summary.txt"

echo "=== Step 1: Cleaning old JIT dump files ==="
rm -f jit-*.dump "$PERF_DATA" "$PERF_JIT_DATA" 2>/dev/null || true

echo "=== Step 2: Running perf record ==="
echo "Command: $*"
"$PERF_BIN" record -k 1 -g -o "$PERF_DATA" -- "$@" 2>&1 | tee "$OUTPUT_DIR/perf_run.log"

echo ""
echo "=== Step 3: Injecting JIT symbols ==="
JIT_DUMP=$(ls jit-*.dump 2>/dev/null | head -1)
if [[ -n "$JIT_DUMP" ]] && [[ "$SKIP_INJECT" == "false" ]]; then
  echo "Found JIT dump: $JIT_DUMP"
  "$PERF_BIN" inject -j -i "$PERF_DATA" -o "$PERF_JIT_DATA" 2>&1
  REPORT_INPUT="$PERF_JIT_DATA"
else
  echo "No JIT dump found or inject skipped, using raw perf data"
  REPORT_INPUT="$PERF_DATA"
fi

echo ""
echo "=== Step 4: Generating reports ==="

"$PERF_BIN" report -i "$REPORT_INPUT" --no-children --sort=symbol --stdio \
  > "$REPORT_TXT" 2>&1 || true

"$PERF_BIN" report -i "$REPORT_INPUT" --no-children --sort=dso --stdio \
  > "$REPORT_DSO" 2>&1 || true

# Extract clean "pct symbol" pairs from the wide perf output
grep -oP '^\s+[\d.]+%\s+\[.\]\s+\S+' "$REPORT_TXT" 2>/dev/null | \
  awk '{printf "%s %s\n", $1, $NF}' > "$PARSED" || true

echo ""
echo "=== Step 5: Generating summary ==="

sum_pct() {
  awk '{s+=substr($1,1,length($1)-1)} END{printf "%.2f", s+0}'
}

{
  echo "================================================================"
  echo "  DTVM Perf Profiling Summary"
  echo "  Generated: $(date)"
  echo "  Command: $*"
  echo "================================================================"
  echo ""

  echo "--- EVM Basic Block Hotspots (JIT-compiled code) ---"
  grep "EVMBB" "$PARSED" 2>/dev/null | \
    awk '{printf "  %-8s %s\n", $1, $2}' || echo "  (none found)"
  BB_TOTAL=$(grep "EVMBB" "$PARSED" 2>/dev/null | sum_pct)
  echo "  ----"
  echo "  Total EVM BB: ${BB_TOTAL}%"
  echo ""

  echo "--- EVM Host Functions ---"
  grep -E "evm(Emit|Get|Set|Expand)" "$PARSED" 2>/dev/null | \
    while IFS= read -r line; do
    pct=$(echo "$line" | awk '{print $1}')
    sym=$(echo "$line" | awk '{print $2}')
    demangled=$(c++filt "$sym" 2>/dev/null || echo "$sym")
    short=$(echo "$demangled" | sed 's/COMPILER:://;s/(.*//')
    printf "  %-8s %s\n" "$pct" "$short"
  done
  HOST_TOTAL=$(grep -E "evm(Emit|Get|Set|Expand)" "$PARSED" 2>/dev/null | sum_pct)
  echo "  ----"
  echo "  Total Host: ${HOST_TOTAL}%"
  echo ""

  echo "--- Keccak / Hashing ---"
  grep -iE "keccak[f_]|ethash_keccak" "$PARSED" 2>/dev/null | \
    awk '{printf "  %-8s %s\n", $1, $2}' || echo "  (none)"
  KECCAK_TOTAL=$(grep -iE "keccak[f_]|ethash_keccak" "$PARSED" 2>/dev/null | sum_pct)
  echo "  ----"
  echo "  Total Keccak: ${KECCAK_TOTAL}%"
  echo ""

  echo "--- JIT Compilation (register allocator, ISel, etc.) ---"
  COMP_TOTAL=$(grep -E "CgLiveRange|CgRAGreedy|CgLiveInterval|CgCoalescer|CgSlotIndex|CgVirtReg|CgInterference|CgLiveRegMatrix|CgDeadCg|CgInstruction|EvictionAdvisor|IntervalMap" \
    "$PARSED" 2>/dev/null | sum_pct)
  echo "  Subtotal: ${COMP_TOTAL}%"
  echo ""

  echo "--- Profiling / Statistics Overhead ---"
  STAT_TOTAL=$(grep -iE "clock_gettime|vdso_clock|steady_clock|Statistics|parseAddress" \
    "$PARSED" 2>/dev/null | sum_pct)
  echo "  Subtotal: ${STAT_TOTAL}%"
  echo ""

  echo "--- Memory Allocation ---"
  MEM_TOTAL=$(grep -wE "malloc|cfree|_Znwm|_ZdlPv" "$PARSED" 2>/dev/null | sum_pct)
  echo "  Subtotal: ${MEM_TOTAL}%"
  echo ""

  echo "--- Instantiation ---"
  INST_TOTAL=$(grep -E "newEVMInstance|EVMInstanceD|createEVMInstance|Isolation" \
    "$PARSED" 2>/dev/null | sum_pct)
  echo "  Subtotal: ${INST_TOTAL}%"
  echo ""

  echo "--- By Shared Object (DSO) ---"
  grep -oP '^\s+[\d.]+%\s+\S+' "$REPORT_DSO" 2>/dev/null | \
    awk '{printf "  %-8s %s\n", $1, $NF}' | head -15
  echo ""
  echo "================================================================"
} > "$SUMMARY" 2>&1

cat "$SUMMARY"

echo ""
echo "=== Output files ==="
echo "  Summary:        $SUMMARY"
echo "  Full report:    $REPORT_TXT"
echo "  DSO report:     $REPORT_DSO"
echo "  Parsed symbols: $PARSED"
echo "  Run log:        $OUTPUT_DIR/perf_run.log"
echo "  Perf data:      $REPORT_INPUT"
