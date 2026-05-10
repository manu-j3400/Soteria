"""
Engine 3: SNN Micro-Temporal Profiler — Baseline Profiler & Anomaly Detection
==============================================================================

Ties together ExecutionHook, LIFNetwork, and TemporalAnomalyLoss into a
complete training/inference pipeline.

Workflow
--------
  1. Collect baseline spike trains from known-clean executions:
         profiler = BaselineProfiler()
         profiler.record_baseline(source_code, label=0)

  2. Train the LIF network on the collected baseline data:
         profiler.train(epochs=100)

  3. Profile new code at inference time:
         result = profiler.profile(source_code)
         if result.is_anomalous:
             alert(result)

Design notes
------------
  - Training data is assembled as (T, B, N) batched spike tensors.
  - The profiler stores the trained model + normalizer state in a checkpoint
    so that it can be restored without re-training.
  - Inference fires the LIF network on a single sample (B=1) and returns
    the anomaly probability along with ISI statistics for interpretability.
"""

from __future__ import annotations

import builtins as _builtins_mod
import io
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.optim as optim
from torch import Tensor
from torch.utils.data import DataLoader, Dataset, random_split

from .encoder import SemanticEncoder, encode_semantic
from .lif_network import LIFConfig, LIFNetwork, TemporalAnomalyLoss
from .telemetry import ExecutionHook, SpikeTrain, encode_rate


# ---------------------------------------------------------------------------
# Sandboxing constants for record_baseline exec()
# ---------------------------------------------------------------------------

# Allowlist of safe builtins — blocks open(), __import__, eval, exec, compile
# to prevent malicious training samples from causing side effects.
_SAFE_BUILTINS: dict = {
    name: getattr(_builtins_mod, name)
    for name in (
        'abs', 'all', 'any', 'bin', 'bool', 'bytearray', 'bytes',
        'callable', 'chr', 'complex', 'dict', 'dir', 'divmod',
        'enumerate', 'filter', 'float', 'format', 'frozenset',
        'getattr', 'globals', 'hasattr', 'hash', 'hex', 'id', 'int',
        'isinstance', 'issubclass', 'iter', 'len', 'list', 'locals',
        'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct',
        'ord', 'pow', 'print', 'property', 'range', 'repr', 'reversed',
        'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod',
        'str', 'sum', 'super', 'tuple', 'type', 'vars', 'zip',
        # Exception types needed by most code
        'ArithmeticError', 'AssertionError', 'AttributeError',
        'BaseException', 'BufferError', 'EOFError', 'EnvironmentError',
        'Exception', 'FileExistsError', 'FileNotFoundError',
        'FloatingPointError', 'GeneratorExit', 'IOError', 'ImportError',
        'IndexError', 'IndentationError', 'KeyError', 'KeyboardInterrupt',
        'LookupError', 'MemoryError', 'ModuleNotFoundError', 'NameError',
        'NotImplemented', 'NotImplementedError', 'OSError', 'OverflowError',
        'RecursionError', 'ReferenceError', 'RuntimeError', 'StopIteration',
        'SyntaxError', 'SystemError', 'TabError', 'TimeoutError', 'TypeError',
        'UnboundLocalError', 'UnicodeDecodeError', 'UnicodeEncodeError',
        'UnicodeError', 'ValueError', 'ZeroDivisionError',
    )
    if hasattr(_builtins_mod, name)
}

_EXEC_TIMEOUT_S: float = 5.0   # per-sample execution wall-clock limit


# ---------------------------------------------------------------------------
# Profiling result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TemporalAnomalyResult:
    """
    Output of a single temporal profiling run.

    anomaly_prob   Float in [0, 1]. > threshold → anomalous execution rhythm.
    is_anomalous   True if anomaly_prob ≥ threshold.
    threshold      Decision boundary used (default 0.5).
    isi_cv         Coefficient of Variation of the inter-spike interval.
                   CV > 1 indicates bursty (high-risk) execution.
    firing_rate_hz Mean spike rate of the recorded execution in Hz.
    n_events       Total interpreter trace events captured.
    duration_us    Recording window in microseconds.
    inference_ms   Wall-clock time spent on the LIF forward pass (milliseconds).
    """
    anomaly_prob:   float
    is_anomalous:   bool
    threshold:      float
    isi_cv:         float
    firing_rate_hz: float
    n_events:       int
    duration_us:    float
    inference_ms:   float

    def __repr__(self) -> str:
        verdict = "ANOMALOUS" if self.is_anomalous else "clean"
        return (
            f"TemporalAnomalyResult({verdict} | "
            f"prob={self.anomaly_prob:.4f} | "
            f"ISI-CV={self.isi_cv:.3f} | "
            f"rate={self.firing_rate_hz:.1f} Hz)"
        )


# ---------------------------------------------------------------------------
# Spike train dataset
# ---------------------------------------------------------------------------

class SpikeBatchDataset(Dataset):
    """
    Dataset of (encoded_spike_train, label) pairs for LIF network training.

    Each item is a (T, N) float32 tensor representing one execution sample.
    """

    def __init__(
        self,
        samples: List[Tuple[np.ndarray, float]],  # (T, N) array + label
    ) -> None:
        self.samples = samples

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Tuple[Tensor, Tensor]:
        arr, label = self.samples[idx]
        return (
            torch.from_numpy(arr),                       # (T, N)
            torch.tensor(label, dtype=torch.float32),    # scalar
        )

    @staticmethod
    def collate(batch: List[Tuple[Tensor, Tensor]]) -> Tuple[Tensor, Tensor]:
        """Stack (T, N) samples into a (T, B, N) batch."""
        spikes = torch.stack([x for x, _ in batch], dim=1)   # (T, B, N)
        labels = torch.stack([y for _, y in batch])           # (B,)
        return spikes, labels


# ---------------------------------------------------------------------------
# Training configuration
# ---------------------------------------------------------------------------

@dataclass
class ProfilerTrainConfig:
    """Hyperparameters for the temporal profiler training loop."""
    epochs:          int   = 100
    batch_size:      int   = 16
    lr:              float = 1e-3
    weight_decay:    float = 1e-4
    val_split:       float = 0.15     # fraction of data held out for validation
    patience:        int   = 15       # early stopping patience (epochs)
    threshold:       float = 0.5     # anomaly decision boundary
    bin_size_us:     float = 10.0    # spike train bin resolution (µs)
    device:          str   = "cuda" if torch.cuda.is_available() else "cpu"
    checkpoint_path: Optional[str] = None


# ---------------------------------------------------------------------------
# Baseline profiler
# ---------------------------------------------------------------------------

class BaselineProfiler:
    """
    End-to-end temporal anomaly profiler powered by a LIF spiking neural network.

    Collects baseline execution telemetry, trains the LIF network, then
    profiles new code snippets at inference time.

    Usage
    -----
        profiler = BaselineProfiler(lif_config=LIFConfig(), train_config=ProfilerTrainConfig())

        # 1. Record training samples
        for clean_src in clean_corpus:
            profiler.record_baseline(clean_src, label=0.0)
        for malicious_src in malicious_corpus:
            profiler.record_baseline(malicious_src, label=1.0)

        # 2. Train
        profiler.train()

        # 3. Infer
        result = profiler.profile(new_source_code)
        print(result)
    """

    def __init__(
        self,
        lif_config:   Optional[LIFConfig]          = None,
        train_config: Optional[ProfilerTrainConfig] = None,
    ) -> None:
        self.lif_config   = lif_config   or LIFConfig()
        self.train_config = train_config or ProfilerTrainConfig()

        self.device = torch.device(self.train_config.device)

        self.model = LIFNetwork(
            n_inputs        = self.lif_config.n_inputs,
            hidden_1        = self.lif_config.hidden_1,
            hidden_2        = self.lif_config.hidden_2,
            beta_1          = self.lif_config.beta_1,
            beta_2          = self.lif_config.beta_2,
            threshold       = self.lif_config.threshold,
            surrogate_slope = self.lif_config.surrogate_slope,
            dropout         = self.lif_config.dropout,
        ).to(self.device)

        self.loss_fn = TemporalAnomalyLoss()

        # Collected training samples: list of (encoded_array, label)
        self._samples: List[Tuple[np.ndarray, float]] = []

        # Training history
        self.train_losses: List[float] = []
        self.val_losses:   List[float] = []

        self._trained = False

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def record_baseline(
        self,
        source_code:   str,
        label:         float = 0.0,           # 0 = clean, 1 = anomalous
        exec_globals:  Optional[Dict] = None,
        max_events:    int   = 200_000,
    ) -> Optional[SpikeTrain]:
        """
        Execute *source_code* under the telemetry hook, convert to a spike
        train, encode it, and add to the training buffer.

        Parameters
        ----------
        source_code    Python source string to execute and record.
        label          Ground-truth label: 0.0 = clean, 1.0 = anomalous.
        exec_globals   Global namespace for exec(). Defaults to empty dict.
        max_events     Hard cap on trace events (prevents memory explosion).

        Returns
        -------
        SpikeTrain captured during execution, or None if exec() raised.
        """
        hook = ExecutionHook(max_events=max_events)
        globs: dict = exec_globals if exec_globals is not None else {}
        # Restrict builtins: block open(), __import__, eval, exec, compile, etc.
        # Python adds __builtins__ automatically on exec(); we override with allowlist.
        globs.setdefault('__builtins__', _SAFE_BUILTINS)

        def _run_exec() -> None:
            """Execute profiled code inside its own thread (for timeout support)."""
            hook.start()
            try:
                exec(compile(source_code, "<profiler>", "exec"), globs)  # noqa: S102
            except Exception:
                pass   # capture what we got; anomalous code may raise
            finally:
                hook.stop()

        t = threading.Thread(target=_run_exec, daemon=True)
        t.start()
        t.join(timeout=_EXEC_TIMEOUT_S)
        if t.is_alive():
            # Thread exceeded wall-clock limit (infinite loop, heavy computation).
            # hook.stop() is not thread-safe here, but the max_events cap will
            # cause the trace callback to detach naturally on the next event.
            hook.stop()

        train = hook.to_spike_train(bin_size_us=self.train_config.bin_size_us)
        encoded = encode_semantic(
            train,
            hook._events,
            n_timesteps = self.lif_config.n_timesteps,
        )
        self._samples.append((encoded, label))
        return train

    def add_spike_train(self, spike_train: SpikeTrain, label: float) -> None:
        """
        Add a pre-recorded SpikeTrain directly (useful when execution was
        already captured by an external hook). Uses legacy encode_rate since
        raw events are unavailable.
        """
        encoded = encode_rate(
            spike_train,
            n_timesteps = self.lif_config.n_timesteps,
            n_features  = self.lif_config.n_inputs,
        )
        self._samples.append((encoded, label))

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self) -> None:
        """
        Train the LIF network on the collected baseline samples.

        Implements AdamW optimisation with cosine LR annealing and
        early stopping on validation loss.
        """
        if not self._samples:
            raise RuntimeError("No training samples collected. Call record_baseline() first.")

        dataset = SpikeBatchDataset(self._samples)

        n_val   = max(1, int(len(dataset) * self.train_config.val_split))
        n_train = len(dataset) - n_val
        if n_train < 1:
            raise RuntimeError("Not enough samples for a train/val split.")

        train_ds, val_ds = random_split(
            dataset, [n_train, n_val],
            generator=torch.Generator().manual_seed(42),
        )

        train_loader = DataLoader(
            train_ds,
            batch_size  = self.train_config.batch_size,
            shuffle     = True,
            collate_fn  = SpikeBatchDataset.collate,
        )
        val_loader = DataLoader(
            val_ds,
            batch_size  = self.train_config.batch_size,
            shuffle     = False,
            collate_fn  = SpikeBatchDataset.collate,
        )

        optimizer = optim.AdamW(
            self.model.parameters(),
            lr           = self.train_config.lr,
            weight_decay = self.train_config.weight_decay,
        )
        scheduler = optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=self.train_config.epochs, eta_min=1e-6
        )

        best_val   = float("inf")
        no_improve = 0
        best_state = None

        for epoch in range(1, self.train_config.epochs + 1):
            t0         = time.perf_counter()
            train_loss = self._train_epoch(train_loader, optimizer)
            val_loss   = self._eval_epoch(val_loader)

            self.train_losses.append(train_loss)
            self.val_losses.append(val_loss)
            scheduler.step()

            if val_loss < best_val - 1e-5:
                best_val   = val_loss
                no_improve = 0
                best_state = {k: v.clone() for k, v in self.model.state_dict().items()}
            else:
                no_improve += 1

            elapsed = (time.perf_counter() - t0) * 1000
            print(
                f"Epoch {epoch:03d}/{self.train_config.epochs} | "
                f"train={train_loss:.4f} | val={val_loss:.4f} | "
                f"lr={optimizer.param_groups[0]['lr']:.2e} | {elapsed:.0f} ms"
            )

            if no_improve >= self.train_config.patience:
                print(f"Early stopping at epoch {epoch} ({self.train_config.patience} epochs without improvement)")
                break

        if best_state is not None:
            self.model.load_state_dict(best_state)

        self._trained = True

        if self.train_config.checkpoint_path:
            self.save(self.train_config.checkpoint_path)

    def _train_epoch(self, loader: DataLoader, optimizer: optim.Optimizer) -> float:
        self.model.train()
        total = 0.0
        for spikes, labels in loader:
            spikes = spikes.to(self.device)   # (T, B, N)
            labels = labels.to(self.device)   # (B,)

            optimizer.zero_grad()
            spk_rec, _, anomaly_prob = self.model(spikes)
            loss = self.loss_fn(anomaly_prob, labels, spk_rec)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            optimizer.step()
            total += loss.item()
        return total / max(len(loader), 1)

    def _eval_epoch(self, loader: DataLoader) -> float:
        self.model.eval()
        total = 0.0
        with torch.no_grad():
            for spikes, labels in loader:
                spikes = spikes.to(self.device)
                labels = labels.to(self.device)
                spk_rec, _, anomaly_prob = self.model(spikes)
                loss = self.loss_fn(anomaly_prob, labels, spk_rec)
                total += loss.item()
        return total / max(len(loader), 1)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def profile(
        self,
        source_code:  str,
        exec_globals: Optional[Dict] = None,
        max_events:   int            = 200_000,
        threshold:    Optional[float] = None,
    ) -> TemporalAnomalyResult:
        """
        Execute *source_code* under the telemetry hook and return an anomaly
        assessment from the trained LIF network.

        Parameters
        ----------
        source_code   Python source string to profile.
        exec_globals  Global namespace for exec(). Defaults to empty dict.
        max_events    Hard cap on trace events.
        threshold     Override the training threshold for this call.

        Returns
        -------
        TemporalAnomalyResult with anomaly probability and ISI statistics.
        """
        if not self._trained:
            raise RuntimeError("Model not trained. Call train() first.")

        thresh = threshold if threshold is not None else self.train_config.threshold

        hook  = ExecutionHook(max_events=max_events)
        globs = exec_globals if exec_globals is not None else {}

        hook.start()
        try:
            exec(compile(source_code, "<profiler>", "exec"), globs)  # noqa: S102
        except Exception:
            pass
        finally:
            hook.stop()

        train = hook.to_spike_train(bin_size_us=self.train_config.bin_size_us)
        encoded = encode_semantic(
            train,
            hook._events,
            n_timesteps = self.lif_config.n_timesteps,
        )

        spike_tensor = torch.from_numpy(encoded).unsqueeze(1).to(self.device)  # (T, 1, N)

        t0 = time.perf_counter()
        self.model.eval()
        with torch.no_grad():
            _, _, anomaly_prob = self.model(spike_tensor)
        inference_ms = (time.perf_counter() - t0) * 1000

        prob = float(anomaly_prob.item())

        return TemporalAnomalyResult(
            anomaly_prob   = prob,
            is_anomalous   = prob >= thresh,
            threshold      = thresh,
            isi_cv         = train.isi_cv(),
            firing_rate_hz = train.firing_rate_hz,
            n_events       = train.n_events,
            duration_us    = train.duration_us,
            inference_ms   = inference_ms,
        )

    def profile_spike_train(
        self,
        spike_train: SpikeTrain,
        threshold:   Optional[float] = None,
    ) -> TemporalAnomalyResult:
        """
        Profile a pre-recorded SpikeTrain (e.g. from kernel-level eBPF telemetry).
        """
        if not self._trained:
            raise RuntimeError("Model not trained. Call train() first.")

        thresh = threshold if threshold is not None else self.train_config.threshold

        encoded = encode_rate(
            spike_train,
            n_timesteps = self.lif_config.n_timesteps,
            n_features  = self.lif_config.n_inputs,
        )
        spike_tensor = torch.from_numpy(encoded).unsqueeze(1).to(self.device)

        t0 = time.perf_counter()
        self.model.eval()
        with torch.no_grad():
            _, _, anomaly_prob = self.model(spike_tensor)
        inference_ms = (time.perf_counter() - t0) * 1000

        prob = float(anomaly_prob.item())
        return TemporalAnomalyResult(
            anomaly_prob   = prob,
            is_anomalous   = prob >= thresh,
            threshold      = thresh,
            isi_cv         = spike_train.isi_cv(),
            firing_rate_hz = spike_train.firing_rate_hz,
            n_events       = spike_train.n_events,
            duration_us    = spike_train.duration_us,
            inference_ms   = inference_ms,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        """Serialize model weights + config to a single checkpoint file."""
        torch.save(
            {
                "model_state":  self.model.state_dict(),
                "lif_config":   self.lif_config,
                "train_config": self.train_config,
                "train_losses": self.train_losses,
                "val_losses":   self.val_losses,
            },
            path,
        )

    @classmethod
    def load(cls, path: str, device: Optional[str] = None) -> "BaselineProfiler":
        """Restore a previously saved BaselineProfiler from a checkpoint."""
        ckpt  = torch.load(path, map_location="cpu", weights_only=False)  # nosec B614 - checkpoint is server-generated, not user-uploaded; contains custom config dataclasses incompatible with weights_only=True
        lif   = ckpt["lif_config"]
        train = ckpt["train_config"]
        if device:
            train.device = device

        profiler = cls(lif_config=lif, train_config=train)
        profiler.model.load_state_dict(ckpt["model_state"])
        profiler.model.to(profiler.device)
        profiler.train_losses = ckpt.get("train_losses", [])
        profiler.val_losses   = ckpt.get("val_losses",   [])
        profiler._trained     = True
        return profiler
