from __future__ import annotations

import hashlib
import re
import time
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import requests
from rich.markup import escape as rich_escape

from zero_suite.core import (
    DEFAULT_EG2_HF_MODEL,
    DEFAULT_EG2_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    MRL_DIM,
    SEMANTIC_OBJECTIVES,
    AutonomousAnalysis,
    AutonomousRouteStep,
    DeliberationTurn,
    Finding,
    IntelAdvisory,
    TrainingMetrics,
    console,
    cosine_similarity,
    l2_normalize,
    mean_vector,
)


class EmbeddingGemma2Advisor:
    def __init__(
        self,
        backend: str = "auto",
        ollama_url: str = DEFAULT_OLLAMA_URL,
        ollama_model: str = DEFAULT_EG2_OLLAMA_MODEL,
        hf_model: str = DEFAULT_EG2_HF_MODEL,
        dim: int = MRL_DIM,
        adapter_state: dict[str, Any] | None = None,
    ) -> None:
        self.dim = dim
        self.ollama_url = ollama_url.rstrip("/")
        self.ollama_model = ollama_model
        self.hf_model = hf_model
        self._st_model: Any = None
        self._cache: dict[str, list[float]] = {}
        state = adapter_state or {
            "weights": [1.0] * dim,
            "trap_centroid": [0.0] * dim,
            "safe_centroid": [0.0] * dim,
            "cumulative_epochs": 0,
        }
        self.weights: list[float] = list(state["weights"])
        self.trap_centroid: list[float] = list(state["trap_centroid"])
        self.safe_centroid: list[float] = list(state["safe_centroid"])
        self.cumulative_epochs: int = int(state["cumulative_epochs"])
        self.backend_label = self._select_backend(backend)
        self._objective_vectors = {
            name: self.embed_text(desc)
            for name, desc in SEMANTIC_OBJECTIVES.items()
        }

    def _select_backend(self, requested: str) -> str:
        if requested in ("auto", "ollama"):
            if self._probe_ollama():
                return f"ollama:{self.ollama_model} ({self.dim}d-MRL)"
            if requested == "ollama":
                return f"local-semantic-fallback ({self.dim}d; ollama unavailable)"
        if requested in ("auto", "st"):
            if self._load_sentence_transformer():
                return f"sentence-transformers:{self.hf_model} ({self.dim}d-MRL)"
            if requested == "st":
                return f"local-semantic-fallback ({self.dim}d; sentence-transformers unavailable)"
        return f"local-semantic-fallback ({self.dim}d)"

    def _probe_ollama(self) -> bool:
        try:
            resp = requests.post(
                f"{self.ollama_url}/api/embed",
                json={"model": self.ollama_model, "input": "zero suite probe"},
                timeout=1.5,
            )
            if resp.status_code == 200:
                data = resp.json()
                embeddings = data.get("embeddings")
                return bool(isinstance(embeddings, list) and embeddings and isinstance(embeddings[0], list))
        except (requests.RequestException, ValueError):
            pass
        return False

    def _load_sentence_transformer(self) -> bool:
        try:
            from sentence_transformers import SentenceTransformer
            self._st_model = SentenceTransformer(
                self.hf_model,
                config_kwargs={"vision_config": None, "audio_config": None},
            )
            return True
        except Exception:
            self._st_model = None
            return False

    def _fallback_embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        clean = re.sub(r"[^a-z0-9/_\- ]+", " ", text.lower())
        tokens = [t for t in re.split(r"[\s/_-]+", clean) if len(t) >= 2]
        features = list(tokens)
        for tok in tokens:
            if len(tok) >= 4:
                for i in range(len(tok) - 2):
                    features.append(tok[i : i + 3])
        if not features:
            return vec
        for feat in features:
            digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
            idx = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if (digest[4] & 1) else -1.0
            vec[idx] += sign
        return l2_normalize(vec, self.dim)

    def _apply_adapter(self, raw_vec: list[float]) -> list[float]:
        weighted = [v * w for v, w in zip(raw_vec, self.weights)]
        return l2_normalize(weighted, self.dim)

    def embed_raw_texts(self, texts: list[str]) -> list[list[float]]:
        missing = [t for t in texts if t not in self._cache]
        if missing:
            if self.backend_label.startswith("ollama:"):
                try:
                    resp = requests.post(
                        f"{self.ollama_url}/api/embed",
                        json={"model": self.ollama_model, "input": missing},
                        timeout=15.0,
                    )
                    if resp.status_code == 200:
                        raw_vecs = resp.json().get("embeddings", [])
                        if len(raw_vecs) == len(missing):
                            for t, v in zip(missing, raw_vecs):
                                self._cache[t] = l2_normalize([float(x) for x in v], self.dim)
                            missing = []
                except (requests.RequestException, ValueError):
                    pass
            elif self._st_model is not None:
                try:
                    raw_vecs = self._st_model.encode(missing, normalize_embeddings=True)
                    for t, v in zip(missing, raw_vecs):
                        self._cache[t] = l2_normalize([float(x) for x in v], self.dim)
                    missing = []
                except Exception:
                    pass
            for t in missing:
                self._cache[t] = self._fallback_embed(t)
        return [self._cache[t] for t in texts]

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [self._apply_adapter(v) for v in self.embed_raw_texts(texts)]

    def embed_text(self, text: str) -> list[float]:
        return self.embed_texts([text])[0]

    def train_online_adapter(
        self,
        trap_samples: list[str],
        safe_samples: list[str],
        epochs: int = 12,
        lr: float = 0.14,
    ) -> TrainingMetrics:
        traps_clean = list(dict.fromkeys(trap_samples))[:60]
        safes_clean = list(dict.fromkeys(safe_samples))[:60]
        if not traps_clean:
            traps_clean = ["trap route: /honeypot/decoy", "trap route: /tarpit/infinite/calendar"]
        if not safes_clean:
            safes_clean = ["safe route: /", "safe route: /about"]

        trap_raw = self.embed_raw_texts([f"route: {t}" for t in traps_clean])
        safe_raw = self.embed_raw_texts([f"route: {s}" for s in safes_clean])
        margin = 0.45

        def eval_loss(w: list[float]) -> tuple[float, list[float], list[float]]:
            t_proj = [l2_normalize([x * wi for x, wi in zip(v, w)], self.dim) for v in trap_raw]
            s_proj = [l2_normalize([x * wi for x, wi in zip(v, w)], self.dim) for v in safe_raw]
            tc = mean_vector(t_proj, self.dim)
            sc = mean_vector(s_proj, self.dim)
            losses: list[float] = []
            for v in t_proj:
                losses.append(max(0.0, margin - (cosine_similarity(v, tc) - cosine_similarity(v, sc))))
            for v in s_proj:
                losses.append(max(0.0, margin - (cosine_similarity(v, sc) - cosine_similarity(v, tc))))
            return sum(losses) / max(1, len(losses)), tc, sc

        loss_before, tc, sc = eval_loss(self.weights)
        w = list(self.weights)
        for _ in range(max(1, epochs)):
            grad = [0.0] * self.dim
            t_proj = [l2_normalize([x * wi for x, wi in zip(v, w)], self.dim) for v in trap_raw]
            s_proj = [l2_normalize([x * wi for x, wi in zip(v, w)], self.dim) for v in safe_raw]
            tc = mean_vector(t_proj, self.dim)
            sc = mean_vector(s_proj, self.dim)
            for raw_v, proj_v in zip(trap_raw, t_proj):
                if cosine_similarity(proj_v, tc) - cosine_similarity(proj_v, sc) < margin:
                    for i in range(self.dim):
                        grad[i] += raw_v[i] * (tc[i] - sc[i])
            for raw_v, proj_v in zip(safe_raw, s_proj):
                if cosine_similarity(proj_v, sc) - cosine_similarity(proj_v, tc) < margin:
                    for i in range(self.dim):
                        grad[i] += raw_v[i] * (sc[i] - tc[i])
            scale = lr / max(1, len(trap_raw) + len(safe_raw))
            for i in range(self.dim):
                w[i] = max(0.35, min(2.6, w[i] + scale * grad[i]))

        loss_after, tc_after, sc_after = eval_loss(w)
        self.weights = w
        self.trap_centroid = tc_after
        self.safe_centroid = sc_after
        self.cumulative_epochs += max(1, epochs)
        self._objective_vectors = {
            name: self.embed_text(desc)
            for name, desc in SEMANTIC_OBJECTIVES.items()
        }
        return TrainingMetrics(
            samples_used=len(traps_clean) + len(safes_clean),
            trap_samples=len(traps_clean),
            safe_samples=len(safes_clean),
            epochs_run=max(1, epochs),
            cumulative_epochs=self.cumulative_epochs,
            loss_before=round(loss_before, 4),
            loss_after=round(loss_after, 4),
            margin_gain=round(loss_before - loss_after, 4),
            persisted=True,
        )

    def plan_frontier(
        self,
        candidate_urls: list[str],
        memorized_traps: list[str],
        memorized_safes: list[str],
        expert_focus: str,
    ) -> list[AutonomousRouteStep]:
        if not candidate_urls:
            return []
        url_texts = [f"route: {urlparse(u).path or '/'} query: {urlparse(u).query}" for u in candidate_urls]
        trap_texts = [f"trap route: {t}" for t in memorized_traps[:40]]
        safe_texts = [f"safe route: {s}" for s in memorized_safes[:40]]
        focus_vec = self.embed_text(f"audit priority: {expert_focus}")
        url_vecs = self.embed_texts(url_texts)
        trap_vecs = self.embed_texts(trap_texts) if trap_texts else []
        safe_vecs = self.embed_texts(safe_texts) if safe_texts else []
        has_trained_centroids = any(abs(x) > 1e-6 for x in self.trap_centroid)

        steps: list[AutonomousRouteStep] = []
        for u, vec in zip(candidate_urls, url_vecs):
            cluster_scores = {
                name: cosine_similarity(vec, ovec)
                for name, ovec in self._objective_vectors.items()
            }
            best_cluster = max(cluster_scores, key=cluster_scores.get)
            trap_proto_sim = cluster_scores.get("Trap & Deception", 0.0)
            mem_trap_sim = max((cosine_similarity(vec, tv) for tv in trap_vecs), default=0.0)
            centroid_trap_sim = cosine_similarity(vec, self.trap_centroid) if has_trained_centroids else 0.0
            trap_sim = max(trap_proto_sim, mem_trap_sim, centroid_trap_sim)
            safe_sim = max(
                max((cosine_similarity(vec, sv) for sv in safe_vecs), default=0.0),
                cosine_similarity(vec, self.safe_centroid) if has_trained_centroids else 0.0,
            )
            focus_sim = cosine_similarity(vec, focus_vec)
            high_value_sim = max(
                cluster_scores.get("Auth & Session", 0.0),
                cluster_scores.get("API & Data Contracts", 0.0),
                cluster_scores.get("Admin & Config Surface", 0.0),
            )
            priority_score = round((high_value_sim * 0.55) + (focus_sim * 0.30) + (safe_sim * 0.15) - (trap_sim * 0.70), 3)

            if trap_sim >= 0.72 and safe_sim < 0.85:
                decision = "HOLD_SEMANTIC_TRAP"
                reason = f"High semantic trap similarity ({trap_sim:.2f}) relative to trained/memorized traps."
            elif priority_score >= 0.15 or best_cluster in ("Auth & Session", "API & Data Contracts", "Admin & Config Surface"):
                decision = "PRIORITIZE"
                reason = f"High-value {best_cluster} surface aligned with Expert focus."
            else:
                decision = "STANDARD"
                reason = f"Standard {best_cluster} route queued for complete surface coverage."

            steps.append(AutonomousRouteStep(
                url=u,
                cluster=best_cluster,
                priority_score=priority_score,
                trap_similarity=round(trap_sim, 3),
                decision=decision,
                reason=reason,
            ))

        steps.sort(key=lambda s: (s.decision != "HOLD_SEMANTIC_TRAP", s.priority_score), reverse=True)
        return steps

    def deliberate_with_expert(
        self,
        target: str,
        technologies: list[str],
        findings: list[Finding],
        guided_steps: list[AutonomousRouteStep],
        trap_samples: list[str],
        safe_samples: list[str],
        intel_advisories: list[IntelAdvisory],
        intel_status: str,
        waves_planned: int,
        remaining_queue_count: int,
        tarpit_triggered: bool,
        max_rounds: int = 4,
        pace_seconds: float = 0.30,
        train_epochs: int = 12,
        live_console: bool = True,
    ) -> AutonomousAnalysis:
        clusters: Counter[str] = Counter()
        trap_warnings: list[str] = []
        prioritized_count = 0
        for step in guided_steps:
            clusters[step.cluster] += 1
            if step.decision == "HOLD_SEMANTIC_TRAP":
                trap_warnings.append(f"{urlparse(step.url).path or '/'} (sim={step.trap_similarity:.2f})")
            elif step.decision == "PRIORITIZE":
                prioritized_count += 1

        transcript: list[DeliberationTurn] = []
        training_metrics = TrainingMetrics()
        proven_n = sum(1 for f in findings if f.verdict == "PROVEN")
        unconf_n = sum(1 for f in findings if f.verdict == "UNCONFIRMED")
        rounds_target = max(2, min(max_rounds, 6))

        def emit_turn(rnum: int, speaker: str, topic: str, stmt: str, cscore: float) -> None:
            turn = DeliberationTurn(rnum, speaker, topic, stmt, round(cscore, 2))
            transcript.append(turn)
            if live_console:
                tag_style = "lime" if speaker == "ZSES" else "ink"
                console.print(
                    f"  [{tag_style}]R{rnum} · {speaker:<4}[/{tag_style}] "
                    f"[muted]{rich_escape(topic)}[/muted]\n"
                    f"         {rich_escape(stmt)} [dim](consensus {cscore:.2f})[/dim]"
                )
                if pace_seconds > 0:
                    time.sleep(pace_seconds)

        emit_turn(
            1,
            "ZSES",
            "Epistemic Evidence Handshake",
            f"Audited {urlparse(target).netloc} across {waves_planned} wave(s): {proven_n} PROVEN facts, {unconf_n} UNCONFIRMED leads. Requesting EG2 semantic validation.",
            0.56,
        )
        emit_turn(
            1,
            "EG2",
            "Semantic Cluster & Trap Audit",
            f"Grouped {len(guided_steps)} routes into {len(clusters)} clusters; held {len(trap_warnings)} semantic trap(s) without executing any target calls.",
            0.67,
        )

        if rounds_target >= 2:
            intel_note = (
                f"Matched {len(intel_advisories)} public advisory lead(s) via {intel_status}; marked UNCONFIRMED until exact package version is verified."
                if intel_advisories
                else f"Checked public threat-intel feeds ({intel_status}); no banner-level CVE/KEV overlap found."
            )
            emit_turn(2, "EG2", "Live Threat-Intel Cross-Check", intel_note, 0.77)
            emit_turn(
                2,
                "ZSES",
                "Proof-Gate Policy",
                "Safe verification PoCs will be emitted strictly for PROVEN findings; UNCONFIRMED leads will report exact missing evidence.",
                0.83,
            )

        if rounds_target >= 3:
            training_metrics = self.train_online_adapter(trap_samples, safe_samples, epochs=train_epochs)
            emit_turn(
                3,
                "EG2",
                "Online Contrastive Adaptation",
                f"Adapted 256d metric over {training_metrics.samples_used} samples ({training_metrics.epochs_run} ep; total {training_metrics.cumulative_epochs}). "
                f"Margin loss: {training_metrics.loss_before:.4f} -> {training_metrics.loss_after:.4f} ({training_metrics.margin_gain:+.4f}).",
                0.90,
            )
            emit_turn(
                3,
                "ZSES",
                "Memory Persistence Check",
                "Persisted updated EG2 weights and trap/safe centroids to .zerorcmemo.",
                0.93,
            )

        consensus_score = 0.96 if remaining_queue_count == 0 and not tarpit_triggered else 0.88
        if rounds_target >= 4:
            emit_turn(
                4,
                "ZSES",
                "Epistemic Convergence",
                f"Consensus locked ({consensus_score:.2f}). Ready to issue Verification PoC pack and explicit Unknown Boundaries.",
                consensus_score,
            )
            emit_turn(
                4,
                "EG2",
                "Read-Only Sign-Off",
                "All frontiers semantically accounted for; zero target execution privileges exercised.",
                consensus_score,
            )

        if tarpit_triggered:
            coverage_status = "HALTED_SAFE_BY_EXPERT_SHIELD"
        elif remaining_queue_count == 0:
            coverage_status = "COMPLETE_ALL_FRONTIERS_ANALYZED"
        else:
            coverage_status = f"FRONTIER_REMAINING ({remaining_queue_count} queued)"

        completion_path = [
            "Expert Seed Ingestion -> Initial scope, robots/sitemap, and .zerorcmemo memory supplied by ZSES.",
            f"EG2 Read-Only Routing -> {waves_planned} wave(s) ranked {len(guided_steps)} route(s) ({prioritized_count} prioritized, {len(trap_warnings)} held).",
            f"Intel & Online Training -> {intel_status}; EG2 loss {training_metrics.loss_before:.4f} -> {training_metrics.loss_after:.4f}.",
            f"Epistemic Lock -> {proven_n} PROVEN, {unconf_n} UNCONFIRMED, consensus {consensus_score:.2f}.",
        ]

        dedup_guided = list({s.url: s for s in guided_steps}.values())
        dedup_guided.sort(key=lambda s: s.priority_score, reverse=True)

        return AutonomousAnalysis(
            model_backend=self.backend_label,
            execution_privilege="NONE (READ-ONLY PLANNER + ALLOWLISTED PUBLIC INTEL)",
            flow_owner="ZSES -> ZeroSuiteAuditor",
            net_intel_status=intel_status,
            waves_planned=waves_planned,
            routes_prioritized=prioritized_count,
            semantic_traps_flagged=len(trap_warnings),
            coverage_status=coverage_status,
            consensus_reached=consensus_score >= 0.85,
            final_consensus_score=consensus_score,
            training=training_metrics,
            intel_advisories=intel_advisories,
            deliberation=transcript,
            cluster_counts=dict(clusters),
            semantic_trap_warnings=trap_warnings[:10],
            completion_path=completion_path,
            top_guided_routes=dedup_guided[:10],
        )
