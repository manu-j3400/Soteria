#!/usr/bin/env bash
# Score, cross-check, sample for labeling and compute precision for a dataset.
#
#   ./report.sh <data_dir> [tags...]          (tags default: baseline)
#
# Tag "baseline" uses ML_master/acidModel.pkl, any other tag
# ML_master/acidModel_<tag>.pkl. SKIP_SCORE=1 reuses existing score.py and
# dataflow_scan.py output. A live dir (has live_state.json) gets strata.json
# rebuilt every run, since the collector keeps adding releases.
# label_sheet.py keeps labels already filled in.
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <data_dir> [tags...]" >&2
    exit 2
fi
DATA=$1
shift
TAGS=("$@")
[ ${#TAGS[@]} -eq 0 ] && TAGS=(baseline)
HERE=$(cd "$(dirname "$0")" && pwd)
ML="$HERE/../ML_master"
PY="python3 -I"

if [ "${SKIP_SCORE:-0}" != 1 ]; then
    for tag in "${TAGS[@]}"; do
        model="$ML/acidModel.pkl"
        [ "$tag" != baseline ] && model="$ML/acidModel_$tag.pkl"
        echo "== score.py $tag"
        $PY "$HERE/score.py" --data "$DATA" --tag "$tag" --model "$model"
    done
    echo "== dataflow_scan.py"
    $PY "$HERE/dataflow_scan.py" --data "$DATA"
fi

refresh=--refresh-osv  # one download covers every tag
for tag in "${TAGS[@]}"; do
    echo "== crosscheck.py $tag"
    $PY "$HERE/crosscheck.py" --data "$DATA" --tag "$tag" $refresh
    refresh=
done

if [ ! -f "$DATA/strata.json" ] || [ -f "$DATA/live_state.json" ]; then
    echo "== live_strata.py"
    $PY "$HERE/live_strata.py" --data "$DATA"
fi

for tag in "${TAGS[@]}"; do
    echo "== label_sheet.py $tag"
    $PY "$HERE/label_sheet.py" --data "$DATA" --tag "$tag"
    echo "== precision.py $tag"
    $PY "$HERE/precision.py" --data "$DATA" --tag "$tag"
done
