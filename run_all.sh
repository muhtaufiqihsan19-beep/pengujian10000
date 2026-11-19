#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/lab-run-$(date +%Y%m%d-%H%M%S)}"
FILES="${2:-10000}"
SIZE="${3:-4}"
START_EPOCH="$(python3 -c 'import time; print(time.time())')"
python3 "$HERE/lab.py" self-test
python3 "$HERE/lab.py" init --dir "$OUT" --files "$FILES" --size-kb "$SIZE"
python3 "$HERE/lab.py" verify --dir "$OUT"
python3 "$HERE/lab.py" rotate --dir "$OUT"
python3 "$HERE/lab.py" verify --dir "$OUT"
python3 "$HERE/lab.py" retire --dir "$OUT" --confirm-destroy-old
python3 "$HERE/lab.py" audit --dir "$OUT"
python3 "$HERE/lab.py" report --dir "$OUT" --wall-start-epoch "$START_EPOCH"
echo "DONE; text report: $OUT/LAPORAN_WAKTU_ROTASI_10000.txt"
echo "JSON report: $OUT/RESULTS.json"
