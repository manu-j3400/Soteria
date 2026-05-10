"""
Engine 3: SNN Micro-Temporal Profiler — CSV Corpus Bootstrapper
================================================================

Trains a BaselineProfiler from scratch using the ACID malware corpus
(backend/CSV_master/finalData.csv), then calibrates the anomaly threshold
against the held-out validation split.

Intended usage
--------------
Run once to produce the initial checkpoint:

    python3 -m engines.kyber.snn.bootstrap \
        --csv backend/CSV_master/finalData.csv \
        --checkpoint engines/kyber/snn/snn_baseline.pt \
        --max-per-class 300

The middleware will then load the checkpoint at startup via:
    BaselineProfiler.load("engines/kyber/snn/snn_baseline.pt")

Design choices
--------------
  - Reservoir sampling ensures balanced class distribution and bounded
    memory/time even on large corpora.
  - Malware samples may raise exceptions during exec() — BaselineProfiler
    already handles that with a try/except in record_baseline().
  - ThresholdCalibrator is run on the profiler's built-in val split
    (sampled from _samples before train()) to avoid data leakage.
  - Progress is printed so long-running bootstraps can be monitored.
"""

from __future__ import annotations

import argparse
import csv
import io
import io as _io
import os
import random
import sys
import tempfile
import threading
from pathlib import Path
from typing import List, Optional, Tuple

from .calibration import ThresholdCalibrator
from .lif_network import LIFConfig
from .profiler import BaselineProfiler, ProfilerTrainConfig


# ---------------------------------------------------------------------------
# Core bootstrap function
# ---------------------------------------------------------------------------

def bootstrap_from_csv(
    csv_path:         str,
    profiler:         BaselineProfiler,
    max_per_class:    int            = 300,
    calibrate:        bool           = True,
    checkpoint_path:  Optional[str]  = None,
    seed:             int            = 42,
    verbose:          bool           = True,
) -> BaselineProfiler:
    """
    Train a BaselineProfiler on the ACID malware corpus CSV.

    Parameters
    ----------
    csv_path        Path to finalData.csv (columns: rawCode, normalizedCode, label, source).
    profiler        A freshly constructed BaselineProfiler (no training data yet).
    max_per_class   Maximum samples per class (0=clean, 1=malicious). Balanced.
    calibrate       If True, run ThresholdCalibrator after training.
    checkpoint_path If provided, save the trained profiler to this path.
    seed            Random seed for reservoir sampling.
    verbose         Print progress.

    Returns
    -------
    Trained (and optionally calibrated) BaselineProfiler.
    """
    rng = random.Random(seed)

    # ----------------------------------------------------------------
    # 1. Load and split by label
    # ----------------------------------------------------------------
    clean_rows:    List[str] = []
    malicious_rows: List[str] = []

    if verbose:
        print(f"[Bootstrap] Loading corpus from {csv_path} ...")

    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            code  = row.get("rawCode", "").strip()
            label = row.get("label", "").strip()
            if not code or label not in ("0", "1"):
                continue
            if label == "0":
                clean_rows.append(code)
            else:
                malicious_rows.append(code)

    if verbose:
        print(f"[Bootstrap] Found {len(clean_rows)} clean / {len(malicious_rows)} malicious samples.")

    if not clean_rows and not malicious_rows:
        raise ValueError(f"No usable samples found in {csv_path}. "
                         "Check that 'rawCode' and 'label' columns exist.")

    # ----------------------------------------------------------------
    # 2. Reservoir-sample up to max_per_class rows per class
    # ----------------------------------------------------------------
    def reservoir_sample(rows: List[str], k: int, rng: random.Random) -> List[str]:
        if len(rows) <= k:
            return list(rows)
        return rng.sample(rows, k)

    selected_clean    = reservoir_sample(clean_rows,    max_per_class, rng)
    selected_malicious = reservoir_sample(malicious_rows, max_per_class, rng)

    if verbose:
        print(f"[Bootstrap] Sampled {len(selected_clean)} clean / "
              f"{len(selected_malicious)} malicious for training.")

    # ----------------------------------------------------------------
    # 3. Record baselines (exec under sys.settrace)
    # ----------------------------------------------------------------
    n_total   = len(selected_clean) + len(selected_malicious)
    n_done    = 0
    n_failed  = 0

    all_samples: List[Tuple[str, float]] = (
        [(c, 0.0) for c in selected_clean] +
        [(m, 1.0) for m in selected_malicious]
    )
    rng.shuffle(all_samples)   # interleave classes for stable stats

    # Per-sample execution limits:
    #   - stdin redirected to empty StringIO (prevents input() blocking)
    #   - 5-second wall-clock timeout per sample (daemon thread abandoned on timeout)
    #   - cwd changed to a throwaway temp dir so file-system ops in malware
    #     samples cannot affect the project directory
    _SAMPLE_TIMEOUT_S = 5

    _orig_cwd    = os.getcwd()
    _safe_dir    = tempfile.mkdtemp(prefix="soteria_bootstrap_")
    _orig_stdin  = sys.stdin
    _orig_stdout = sys.stdout

    for code, label in all_samples:
        sys.stdin  = io.StringIO('')
        sys.stdout = _io.StringIO()   # suppress noise (e.g. input() prompts) from executed code
        os.chdir(_safe_dir)

        result_exc: List[Optional[Exception]] = [None]

        def _run(c: str = code, l: float = label) -> None:
            try:
                profiler.record_baseline(c, label=l)
            except Exception as exc:
                result_exc[0] = exc

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=_SAMPLE_TIMEOUT_S)

        # Restore cwd and stdio before any progress prints.
        os.chdir(_orig_cwd)
        sys.stdin  = _orig_stdin
        sys.stdout = _orig_stdout

        if t.is_alive():
            n_failed += 1
            if verbose and n_failed <= 5:
                print(f"[Bootstrap] record_baseline timeout >{_SAMPLE_TIMEOUT_S}s (showing first 5)")
        elif result_exc[0] is not None:
            n_failed += 1
            if verbose and n_failed <= 5:
                print(f"[Bootstrap] record_baseline error (showing first 5): {result_exc[0]}")

        n_done += 1
        if verbose and n_done % 50 == 0:
            print(f"[Bootstrap]   {n_done}/{n_total} samples recorded ...")

    n_recorded = len(profiler._samples)
    if verbose:
        print(f"[Bootstrap] {n_recorded} samples in training buffer "
              f"({n_failed} failed/skipped).")

    if n_recorded < 4:
        raise RuntimeError(
            f"Only {n_recorded} samples recorded — cannot train. "
            "Check that the code samples are executable Python."
        )

    # ----------------------------------------------------------------
    # 4. Train
    # ----------------------------------------------------------------
    if verbose:
        print("[Bootstrap] Training LIF network ...")
    profiler.train()

    # ----------------------------------------------------------------
    # 5. Calibrate threshold using val split retained by train()
    # ----------------------------------------------------------------
    if calibrate:
        if verbose:
            print("[Bootstrap] Calibrating anomaly threshold ...")

        # Use a held-out subset (last 15% of all_samples, matching val_split)
        val_split   = profiler.train_config.val_split
        n_val       = max(2, int(len(all_samples) * val_split))
        val_samples = all_samples[-n_val:]

        calibrator = ThresholdCalibrator()
        optimal_t  = calibrator.calibrate_from_profiler(profiler, val_samples)
        profiler.train_config.threshold = optimal_t

        if verbose:
            print(f"[Bootstrap] Calibrated threshold: {optimal_t:.4f}")

    # ----------------------------------------------------------------
    # 6. Save checkpoint
    # ----------------------------------------------------------------
    if checkpoint_path:
        profiler.train_config.checkpoint_path = checkpoint_path
        profiler.save(checkpoint_path)
        if verbose:
            print(f"[Bootstrap] Checkpoint saved to {checkpoint_path}")

    return profiler


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _suppress_daemon_stderr() -> None:
    """
    Redirect stderr to /dev/null at interpreter shutdown to suppress the
    cosmetic 'could not acquire lock for <stdout>' message emitted when
    daemon threads from sandboxed code execution are still alive at exit.
    """
    import atexit
    def _redirect() -> None:
        try:
            import sys, os
            sys.stderr = open(os.devnull, 'w')  # noqa: WPS515 — intentional at exit
        except Exception:
            pass
    atexit.register(_redirect)


def main() -> None:
    _suppress_daemon_stderr()
    parser = argparse.ArgumentParser(
        description="Bootstrap a SNN temporal anomaly profiler from the ACID malware corpus."
    )
    parser.add_argument(
        "--csv",
        default="backend/CSV_master/finalData.csv",
        help="Path to finalData.csv",
    )
    parser.add_argument(
        "--checkpoint",
        default="engines/kyber/snn/snn_baseline.pt",
        help="Output checkpoint path",
    )
    parser.add_argument(
        "--max-per-class",
        type=int,
        default=300,
        help="Max samples per class (higher = longer training but better accuracy)",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=100,
        help="Maximum training epochs",
    )
    parser.add_argument(
        "--no-calibrate",
        action="store_true",
        help="Skip threshold calibration",
    )
    parser.add_argument(
        "--device",
        default="cpu",
        help="Torch device (cpu / cuda)",
    )
    args = parser.parse_args()

    lif_config   = LIFConfig(device=args.device)
    train_config = ProfilerTrainConfig(epochs=args.epochs, device=args.device)
    profiler     = BaselineProfiler(lif_config=lif_config, train_config=train_config)

    bootstrap_from_csv(
        csv_path        = args.csv,
        profiler        = profiler,
        max_per_class   = args.max_per_class,
        calibrate       = not args.no_calibrate,
        checkpoint_path = args.checkpoint,
        verbose         = True,
    )

    print("[Bootstrap] Done.")


if __name__ == "__main__":
    main()
