#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
OUTBASE="${1:-$HERE/lab-output}"
N="${2:-10000}"
SIZE_KB="${3:-4}"
mkdir -p "$OUTBASE"
OUTBASE="$(cd "$OUTBASE" && pwd)"
JOB="run-$(date +%Y%m%d-%H%M%S)-$$"
IMAGE="mlkem-rotation-lab:local"
START_EPOCH="$(date +%s.%N)"
docker build -t "$IMAGE" .
run() {
  docker run --rm --user "$(id -u):$(id -g)" -v "$OUTBASE:/data" "$IMAGE" "$@"
}
run self-test
run init --dir "/data/$JOB" --files "$N" --size-kb "$SIZE_KB"
run verify --dir "/data/$JOB"
run rotate --dir "/data/$JOB"
run verify --dir "/data/$JOB"
run retire --dir "/data/$JOB" --confirm-destroy-old
run audit --dir "/data/$JOB"
run report --dir "/data/$JOB" --wall-start-epoch "$START_EPOCH"
echo "DONE: $OUTBASE/$JOB/LAPORAN_WAKTU_ROTASI_10000.txt"
