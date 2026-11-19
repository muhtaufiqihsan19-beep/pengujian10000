#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$(mktemp -d "${TMPDIR:-/tmp}/mlkem-rotation-test-XXXXXXXX")/workspace}"
python3 "$HERE/lab.py" self-test
python3 "$HERE/lab.py" init --dir "$OUT" --files 12 --size-kb 2
python3 "$HERE/lab.py" rotate --dir "$OUT" --stop-after 5
python3 "$HERE/lab.py" verify --dir "$OUT"
python3 "$HERE/lab.py" rotate --dir "$OUT"
python3 "$HERE/lab.py" verify --dir "$OUT"
python3 "$HERE/lab.py" retire --dir "$OUT" --confirm-destroy-old
python3 "$HERE/lab.py" audit --dir "$OUT"
echo "RESUME + RETIRE TEST PASSED: $OUT"
