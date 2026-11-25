#!/usr/bin/env bash
# Reproduces the Fase 1 official (confirmatory) run: environment, precondition R, the 33 blocks,
# preconditions H0/C0, the confirmatory tests H1-H4 (Holm) and the 8 figures.
#
#   replication/scripts/reproduce_official.sh            # full run (500 seeds per cell)
#   replication/scripts/reproduce_official.sh --smoke    # 2 seeds per cell, pipeline test only
#
# Options: --smoke, --no-venv (use the current python3), --out DIR, --workers N.
# Stops with exit 1 if R, H0 or C0 fails (docs/fase1/08_preregistro_oficial.md §6).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(cd "$HERE/.." && pwd)"
if [ -d "$PKG/code" ]; then ROOT="$PKG/code"; else ROOT="$(cd "$PKG/.." && pwd)"; fi

SMOKE=""; VENV=1; OUT=""; WORKERS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) SMOKE="--smoke" ;;
    --no-venv) VENV=0 ;;
    --out) OUT="$2"; shift ;;
    --workers) WORKERS="--workers $2"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ -z "$OUT" ]; then
  # never results/fase1_oficial: that holds the reference run, and its checkpoints would skip every block
  if [ -n "$SMOKE" ]; then OUT="$ROOT/results/fase1_oficial_smoke"; else OUT="$ROOT/results/fase1_oficial_repro"; fi
fi

cd "$ROOT"
export PYTHONWARNINGS=ignore
[ -f "$PKG/COMMIT" ] && export REPRO_COMMIT="$(cat "$PKG/COMMIT")"

# 1. environment
if [ "$VENV" = 1 ]; then
  PY="${PYTHON:-python3}"
  "$PY" -m venv "$ROOT/.venv-repro"
  # shellcheck disable=SC1091
  . "$ROOT/.venv-repro/bin/activate"
  python -m pip install --quiet --upgrade pip
  python -m pip install --quiet -r "$PKG/environment/requirements.lock"
fi
want="$(cat "$PKG/environment/.python-version")"
have="$(python3 -c 'import platform; print(platform.python_version())')"
[ "$want" = "$have" ] || echo "WARNING: Python $have, the official run used $want" >&2

# 2. configs and pre-registration match the recorded hashes
( cd "$PKG/configs" && shasum -a 256 -c SHA256SUMS )
for f in config/fase1/thresholds_by_profile.yaml config/fase1/domains_sn.yaml; do
  cmp "$f" "$PKG/configs/$(basename "$f")"
done
cmp docs/fase1/08_preregistro_oficial.md "$PKG/preregistration/08_preregistro_oficial.md"

mkdir -p "$OUT"
D="simulation/fase1_oficial_experiments.py"

# 3. precondition R (Fase 8, Fase 1, Fase 1b regressions, byte for byte)
echo "== R"
python3 -m pytest -q -p no:warnings tests/test_fase1_phase8_regression.py tests/test_fase1b.py tests/test_fase1_oficial.py \
  | tee "$OUT/R_pytest.txt" | tail -1

# 4. blocks the preconditions need, then H0 and C0
echo "== blocks (pre)"
for b in $(python3 "$D" blocks --stage pre); do python3 "$D" run --block "$b" --out "$OUT" $SMOKE $WORKERS; done
echo "== H0, C0"
python3 "$D" check-pre --out "$OUT"

# 5. remaining blocks, analysis, figures
echo "== blocks (rest)"
for b in $(python3 "$D" blocks --stage rest); do python3 "$D" run --block "$b" --out "$OUT" $SMOKE $WORKERS; done
echo "== analysis"
python3 "$D" analyze --out "$OUT"
python3 analysis/fase1_oficial_figs.py --out "$OUT"

# 6. full run only: every raw block must match the reference run byte for byte
if [ -z "$SMOKE" ]; then
  echo "== compare with the reference run (sha256 per block)"
  python3 - "$PKG/reference/manifest.json" "$OUT/manifest.json" <<'PY'
import json, sys
ref, new = (json.load(open(p))["blocks"] for p in sys.argv[1:])
bad = [k for k in ref if new.get(k, {}).get("sha256") != ref[k]["sha256"]]
print(f"{len(ref) - len(bad)}/{len(ref)} blocks identical to the reference run")
sys.exit(1 if bad else 0)
PY
fi
echo "done: $OUT"
