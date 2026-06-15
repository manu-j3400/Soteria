"""
HoneypotOrchestrator — Top-level controller for the DeceptiNet engine.

Ties together HoneypotEnv, PPOAgent, and HypergameModel into a single
production-facing interface. At inference time, observe() accepts a raw
network event dict, runs it through the particle filter, selects an
action via the trained PPO policy, and returns a human-readable
decision record.

At training time, train() runs a standard on-policy PPO rollout loop,
collecting experience batches from HoneypotEnv before updating the agent.
"""

from __future__ import annotations

import logging
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

from .env import HoneypotEnv, _ACTIONS
from .hypergame import AttackerType, DefenderAction, HypergameModel
from .particle_filter import BeliefStateParticleFilter
from .ppo_agent import PPOAgent

logger = logging.getLogger(__name__)

_ATTACKER_TYPE_NAMES: List[str] = [t.value for t in AttackerType]
_ROLLOUT_STEPS: int = 512   # steps to collect before each PPO update
_UPDATE_EPOCHS: int = 4     # number of PPO update epochs per rollout


@dataclass
class OrchestratorConfig:
    n_nodes: int = 20
    honeypot_ratio: float = 0.3
    n_particles: int = 500
    device: str = "cpu"
    tick_interval_s: float = 5.0
    seed: Optional[int] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "OrchestratorConfig":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class TickResult:
    tick_id: int
    chosen_action: str
    reward: float
    belief_summary: Dict[str, float]
    env_render: Dict[str, Any] = field(default_factory=dict)


class HoneypotOrchestrator:
    """
    High-level orchestrator for adaptive honeypot placement.

    Usage (inference)::

        orch = HoneypotOrchestrator(checkpoint_path="deceptinet.pt")
        decision = orch.observe({"scan_rate": 18.0, "lateral_move_count": 2, "exfil_kb": 45.0})
        print(decision["action"], decision["confidence"])

    Usage (training)::

        orch = HoneypotOrchestrator()
        metrics = orch.train(n_episodes=2000)
        orch.save("deceptinet.pt")
    """

    def __init__(
        self,
        config: Optional[OrchestratorConfig] = None,
        # Legacy kwargs kept for backwards compatibility
        n_nodes: int = 20,
        honeypot_ratio: float = 0.3,
        checkpoint_path: Optional[str] = None,
        device: str = "cpu",
        n_particles: int = 500,
        seed: Optional[int] = None,
    ) -> None:
        if config is not None:
            n_nodes       = config.n_nodes
            honeypot_ratio= config.honeypot_ratio
            n_particles   = config.n_particles
            device        = config.device
            seed          = config.seed

        self._model = HypergameModel(n_nodes=n_nodes, honeypot_ratio=honeypot_ratio)
        self._pf    = BeliefStateParticleFilter(n_particles=n_particles)
        self._env   = HoneypotEnv(n_nodes=n_nodes, honeypot_ratio=honeypot_ratio,
                                  n_particles=n_particles, seed=seed)
        self._agent = PPOAgent(
            obs_dim=HoneypotEnv.obs_dim,
            n_actions=HoneypotEnv.n_actions,
            device=device,
        )
        self._device   = device
        self._obs: Optional[np.ndarray] = self._env.reset()
        self._tick_id  = 0
        self._rollout_buffer: List[Dict] = []
        self._alert_queue: List[Dict] = []
        self._alert_lock  = threading.Lock()
        self._started      = False

        if checkpoint_path and os.path.isfile(checkpoint_path):
            self.load(checkpoint_path)
            logger.info("DeceptiNet checkpoint loaded from %s", checkpoint_path)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Initialise runtime state. Must be called before tick()."""
        if not self._started:
            self._obs = self._env.reset()
            self._started = True
            logger.info("DeceptiNet orchestrator started")

    def ingest_alert(self, alert: Dict) -> None:
        """Queue a raw network alert for processing on the next tick()."""
        if not isinstance(alert, dict):
            raise ValueError("alert must be a dict")
        with self._alert_lock:
            self._alert_queue.append(alert)

    def tick(self) -> TickResult:
        """
        Consume queued alerts, step the environment once, optionally update PPO.

        Returns a TickResult with the chosen action and current belief.
        """
        # Drain alert queue and fold into observation via particle filter
        with self._alert_lock:
            alerts = self._alert_queue[:]
            self._alert_queue.clear()

        belief = self._pf.update(alerts[0] if alerts else {}, self._model)

        if self._obs is not None:
            obs = self._obs.copy()
            obs[:len(belief)] = belief
        else:
            obs = np.concatenate([belief, np.zeros(5, dtype=np.float32)])

        action_idx, log_prob, value = self._agent.select_action(obs)
        next_obs, reward, done, _ = self._env.step(action_idx)

        self._rollout_buffer.append({
            "obs": obs, "action": action_idx, "log_prob": log_prob,
            "reward": reward, "value": value, "done": done,
        })

        if done:
            self._obs = self._env.reset()
        else:
            self._obs = next_obs

        # PPO update every _ROLLOUT_STEPS steps
        if len(self._rollout_buffer) >= _ROLLOUT_STEPS:
            for _ in range(_UPDATE_EPOCHS):
                self._agent.update(self._rollout_buffer)
            self._rollout_buffer.clear()

        defender_action: DefenderAction = _ACTIONS[action_idx]
        self._tick_id += 1

        env_render: Dict[str, Any] = {}
        if self._env._state is not None:
            nodes = self._env._state.nodes
            env_render = {
                "n_compromised": sum(1 for n in nodes.values() if n.compromised),
                "n_honeypots":   sum(1 for n in nodes.values() if n.is_honeypot),
                "n_patched":     sum(1 for n in nodes.values() if n.is_patched),
            }

        return TickResult(
            tick_id=self._tick_id,
            chosen_action=defender_action.value,
            reward=float(reward),
            belief_summary={_ATTACKER_TYPE_NAMES[i]: float(belief[i]) for i in range(len(_ATTACKER_TYPE_NAMES))},
            env_render=env_render,
        )

    def status(self) -> Dict[str, Any]:
        """Return a JSON-safe health/state summary."""
        with self._alert_lock:
            pending = len(self._alert_queue)
        return {
            "started":         self._started,
            "tick_id":         self._tick_id,
            "pending_alerts":  pending,
            "rollout_buffer":  len(self._rollout_buffer),
            "n_nodes":         self._env.n_nodes if hasattr(self._env, 'n_nodes') else None,
        }

    def load_checkpoint(self, path: str) -> None:
        """Load PPO weights from path (alias for load() used by server.py)."""
        self.load(path)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def observe(self, event: Dict) -> Dict:
        """
        Process a single network event observation and return a defender decision.

        Args:
            event: dict with any subset of keys used by observation_likelihood
                   (scan_rate, lateral_move_count, exfil_kb) plus optional extras.

        Returns:
            decision dict::

                {
                    "action":             "deploy_honeypot",
                    "belief":             {"noise": 0.05, "opportunist": 0.60, ...},
                    "confidence":         0.87,
                    "recommended_nodes":  ["node_12"],
                }
        """
        # Update belief via particle filter
        belief = self._pf.update(event, self._model)

        # Build a minimal obs vector using the current env state (if available)
        # If the env has been stepped, use live state; otherwise fall back to belief-only
        if self._obs is not None:
            obs = self._obs.copy()
            obs[:4] = belief  # overwrite belief slice with freshly updated belief
        else:
            obs = np.concatenate([belief, np.zeros(5, dtype=np.float32)])

        action_idx, log_prob, value = self._agent.select_action(obs)
        defender_action: DefenderAction = _ACTIONS[action_idx]

        # Confidence: max probability in the actor output (softmax)
        import torch
        obs_t  = torch.as_tensor(obs, dtype=torch.float32)
        with torch.no_grad():
            probs = self._agent.actor(obs_t).cpu().numpy()
        confidence = float(probs[action_idx])

        # Recommend nodes based on current env state
        recommended = self._select_recommended_nodes(defender_action)

        return {
            "action":            defender_action.value,
            "belief":            {
                _ATTACKER_TYPE_NAMES[i]: float(belief[i])
                for i in range(len(_ATTACKER_TYPE_NAMES))
            },
            "confidence":        confidence,
            "recommended_nodes": recommended,
        }

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(
        self,
        n_episodes: int = 1000,
        log_interval: int = 100,
    ) -> Dict:
        """
        Run the PPO training loop over n_episodes full episodes.

        Collects _ROLLOUT_STEPS steps of experience, then runs _UPDATE_EPOCHS
        PPO update epochs. Repeats until n_episodes have been completed.

        Returns:
            metrics dict with episode_rewards, mean_reward, final_loss_info
        """
        episode_rewards: List[float] = []
        episode_count   = 0
        total_steps     = 0
        rollout_buffer: List[Dict] = []

        obs    = self._env.reset()
        ep_ret = 0.0
        t0     = time.time()

        target_total = n_episodes * _ROLLOUT_STEPS  # rough upper bound on steps

        while episode_count < n_episodes:
            # --- Collect rollout ---
            rollout_buffer.clear()
            for _ in range(_ROLLOUT_STEPS):
                action, log_prob, value = self._agent.select_action(obs)
                next_obs, reward, done, info = self._env.step(action)
                rollout_buffer.append({
                    "obs":      obs,
                    "action":   action,
                    "log_prob": log_prob,
                    "reward":   reward,
                    "value":    value,
                    "done":     done,
                })
                ep_ret  += reward
                obs      = next_obs
                total_steps += 1

                if done:
                    episode_rewards.append(ep_ret)
                    episode_count += 1
                    ep_ret = 0.0
                    obs    = self._env.reset()

                    if log_interval > 0 and episode_count % log_interval == 0:
                        elapsed = time.time() - t0
                        mean_r  = float(np.mean(episode_rewards[-log_interval:]))
                        logger.info(
                            "[DeceptiNet] Episode %d/%d | mean_reward=%.3f | steps=%d | %.1fs",
                            episode_count, n_episodes, mean_r, total_steps, elapsed,
                        )

                    if episode_count >= n_episodes:
                        break

            # --- PPO update ---
            loss_info: Dict = {}
            for _ in range(_UPDATE_EPOCHS):
                loss_info = self._agent.update(rollout_buffer)

        # Expose the last-used obs for observe()
        self._obs = obs

        mean_reward = float(np.mean(episode_rewards)) if episode_rewards else 0.0
        return {
            "n_episodes":    episode_count,
            "mean_reward":   mean_reward,
            "total_steps":   total_steps,
            "final_loss":    loss_info,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        """Save PPO agent weights to path."""
        self._agent.save(path)
        logger.info("DeceptiNet checkpoint saved to %s", path)

    def load(self, path: str) -> None:
        """Load PPO agent weights from path."""
        self._agent.load(path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _select_recommended_nodes(self, action: DefenderAction) -> List[str]:
        """
        Return a list of node IDs relevant to the recommended action based on
        the current environment state.
        """
        if self._env._state is None:
            return []

        nodes = self._env._state.nodes

        if action == DefenderAction.DEPLOY_HONEYPOT:
            # Highest-exposure real nodes that are not yet honeypots
            candidates = sorted(
                [n for n in nodes.values() if not n.is_honeypot],
                key=lambda n: n.exposure, reverse=True,
            )
            return [c.node_id for c in candidates[:3]]

        elif action == DefenderAction.REMOVE_HONEYPOT:
            # Honeypots with fewest interactions (least effective decoys)
            candidates = sorted(
                [n for n in nodes.values() if n.is_honeypot],
                key=lambda n: n.interactions,
            )
            return [c.node_id for c in candidates[:2]]

        elif action == DefenderAction.PATCH_REAL_NODE:
            # Unpatched real nodes with highest value
            candidates = sorted(
                [n for n in nodes.values() if not n.is_honeypot and not n.is_patched],
                key=lambda n: n.value, reverse=True,
            )
            return [c.node_id for c in candidates[:3]]

        elif action in (DefenderAction.ALERT_SOC, DefenderAction.TARPIT):
            # Compromised real nodes or most-interacted honeypots
            compromised = [n.node_id for n in nodes.values() if n.compromised]
            return compromised[:5]

        return []
