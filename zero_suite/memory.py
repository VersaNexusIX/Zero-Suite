from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from zero_suite.core import (
    DEFAULT_KEV_URL,
    DEFAULT_MEMORY_DIR,
    DEFAULT_OSV_URL,
    FALLBACK_MEMORY_DIR,
    OSV_ECOSYSTEM_MAP,
    AuditReport,
    IntelAdvisory,
)


class PublicIntelFetcher:
    def __init__(self, cache_dir: Path, kev_url: str = DEFAULT_KEV_URL, osv_url: str = DEFAULT_OSV_URL, enabled: bool = True) -> None:
        self.cache_dir = cache_dir
        self.kev_url = kev_url
        self.osv_url = osv_url
        self.enabled = enabled
        self.kev_cache_path = cache_dir / "cisa_kev_cache.json"

    def _load_kev_catalog(self) -> tuple[list[dict[str, Any]], str]:
        if self.kev_cache_path.exists():
            try:
                age = time.time() - self.kev_cache_path.stat().st_mtime
                if age < 86400:
                    data = json.loads(self.kev_cache_path.read_text(encoding="utf-8"))
                    return data.get("vulnerabilities", []), "CACHED_24H"
            except (OSError, json.JSONDecodeError):
                pass
        try:
            resp = requests.get(self.kev_url, timeout=6.0, headers={"User-Agent": "ZeroSuite-Intel/1.0"})
            if resp.status_code == 200:
                payload = resp.json()
                vulns = payload.get("vulnerabilities", [])
                try:
                    self.kev_cache_path.write_text(json.dumps({"vulnerabilities": vulns}), encoding="utf-8")
                except OSError:
                    pass
                return vulns, "LIVE_NETWORK"
        except (requests.RequestException, ValueError):
            pass
        return [], "OFFLINE_UNAVAILABLE"

    def fetch_for_stack(self, technologies: list[str]) -> tuple[list[IntelAdvisory], str]:
        if not self.enabled:
            return [], "DISABLED_BY_FLAG"
        advisories: list[IntelAdvisory] = []
        statuses: list[str] = []

        kev_vulns, kev_status = self._load_kev_catalog()
        statuses.append(f"KEV:{kev_status}")

        keywords: list[str] = []
        for tech in technologies:
            cleaned = tech.lower().replace("server:", "").split("/")[0].strip()
            if cleaned and len(cleaned) >= 3:
                keywords.append(cleaned)
        keywords = list(dict.fromkeys(keywords))

        if kev_vulns and keywords:
            for item in kev_vulns:
                blob = f"{item.get('vendorProject', '')} {item.get('product', '')} {item.get('vulnerabilityName', '')}".lower()
                matched = next((kw for kw in keywords if kw in blob), None)
                if matched:
                    advisories.append(IntelAdvisory(
                        source="CISA_KEV",
                        identifier=str(item.get("cveID", "CVE-UNKNOWN")),
                        component=matched,
                        summary=str(item.get("vulnerabilityName", ""))[:160],
                        published=str(item.get("dateAdded", "unknown")),
                        verdict="UNCONFIRMED",
                        unconfirmed_reason=f"Framework/server token '{matched}' matched KEV catalog, but exact version & patch state are hidden passively.",
                    ))
                    if len(advisories) >= 6:
                        break

        osv_reachable = False
        for kw in keywords[:4]:
            if kw not in OSV_ECOSYSTEM_MAP:
                continue
            eco, pkg = OSV_ECOSYSTEM_MAP[kw]
            try:
                resp = requests.post(
                    self.osv_url,
                    json={"package": {"name": pkg, "ecosystem": eco}},
                    timeout=5.0,
                    headers={"User-Agent": "ZeroSuite-Intel/1.0"},
                )
                if resp.status_code == 200:
                    osv_reachable = True
                    vulns = resp.json().get("vulns", [])
                    for v in vulns[:2]:
                        advisories.append(IntelAdvisory(
                            source="OSV_DEV",
                            identifier=str(v.get("id", "OSV-UNKNOWN")),
                            component=pkg,
                            summary=str(v.get("summary") or v.get("details") or "Advisory recorded")[:160],
                            published=str(v.get("modified") or v.get("published") or "unknown")[:10],
                            verdict="UNCONFIRMED",
                            unconfirmed_reason=f"Package '{pkg}' detected without exact semver lockfile; confirm version in dependency manifest.",
                        ))
            except (requests.RequestException, ValueError):
                continue

        statuses.append(f"OSV:{'LIVE_NETWORK' if osv_reachable else 'OFFLINE_OR_SKIPPED'}")
        dedup = list({(a.source, a.identifier): a for a in advisories}.values())
        return dedup[:10], " · ".join(statuses)


class ZeroMemoryStore:
    def __init__(self, preferred_dir: Path = DEFAULT_MEMORY_DIR) -> None:
        self._lock = threading.Lock()
        self.base_dir = self._resolve_writable_dir(preferred_dir)
        self.db_path = self.base_dir / "zero_memory.sqlite3"
        self._init_db()

    def _resolve_writable_dir(self, preferred: Path) -> Path:
        for candidate in (preferred, FALLBACK_MEMORY_DIR):
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                probe = candidate / ".probe"
                probe.write_text("ok", encoding="utf-8")
                probe.unlink(missing_ok=True)
                return candidate
            except OSError:
                continue
        local_dir = Path.cwd() / ".zerorcmemo"
        local_dir.mkdir(parents=True, exist_ok=True)
        return local_dir

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS trap_memory (
                    host TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    label TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    hits INTEGER NOT NULL DEFAULT 1,
                    confidence REAL NOT NULL DEFAULT 0.75,
                    manual INTEGER NOT NULL DEFAULT 0,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (host, kind, signature)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    grade TEXT NOT NULL,
                    maturity_tier TEXT NOT NULL,
                    archetype TEXT NOT NULL,
                    pages_crawled INTEGER NOT NULL,
                    traps_blocked INTEGER NOT NULL,
                    findings_json TEXT NOT NULL,
                    tech_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS eg2_adapter_state (
                    key TEXT PRIMARY KEY,
                    dim INTEGER NOT NULL,
                    weights_json TEXT NOT NULL,
                    trap_centroid_json TEXT NOT NULL,
                    safe_centroid_json TEXT NOT NULL,
                    cumulative_epochs INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def load_adapter_state(self, dim: int) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT dim, weights_json, trap_centroid_json, safe_centroid_json, cumulative_epochs FROM eg2_adapter_state WHERE key = 'global'"
            ).fetchone()
        if row and int(row["dim"]) == dim:
            return {
                "weights": json.loads(row["weights_json"]),
                "trap_centroid": json.loads(row["trap_centroid_json"]),
                "safe_centroid": json.loads(row["safe_centroid_json"]),
                "cumulative_epochs": int(row["cumulative_epochs"]),
            }
        return {
            "weights": [1.0] * dim,
            "trap_centroid": [0.0] * dim,
            "safe_centroid": [0.0] * dim,
            "cumulative_epochs": 0,
        }

    def save_adapter_state(
        self,
        dim: int,
        weights: list[float],
        trap_centroid: list[float],
        safe_centroid: list[float],
        cumulative_epochs: int,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO eg2_adapter_state (key, dim, weights_json, trap_centroid_json, safe_centroid_json, cumulative_epochs, updated_at)
                VALUES ('global', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    dim = excluded.dim,
                    weights_json = excluded.weights_json,
                    trap_centroid_json = excluded.trap_centroid_json,
                    safe_centroid_json = excluded.safe_centroid_json,
                    cumulative_epochs = excluded.cumulative_epochs,
                    updated_at = excluded.updated_at
                """,
                (dim, json.dumps(weights), json.dumps(trap_centroid), json.dumps(safe_centroid), cumulative_epochs, now),
            )

    def load_host_knowledge(self, host: str) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT host, kind, signature, label, reason, hits, confidence, manual
                FROM trap_memory
                WHERE host = ? OR (host = '*' AND label = 'TRAP' AND confidence >= 0.85)
                """,
                (host,),
            ).fetchall()
        trap_templates: dict[str, tuple[str, float]] = {}
        safe_templates: set[str] = set()
        trap_simhashes: list[tuple[int, str]] = []
        blocked_redirects: set[str] = set()
        for r in rows:
            kind = r["kind"]
            sig = r["signature"]
            label = r["label"]
            conf = float(r["confidence"])
            if label == "SAFE" and kind == "url_template":
                safe_templates.add(sig)
            elif label == "TRAP" and conf >= 0.70:
                if kind == "url_template":
                    trap_templates[sig] = (r["reason"], conf)
                elif kind == "simhash":
                    try:
                        trap_simhashes.append((int(sig, 16), r["reason"]))
                    except ValueError:
                        pass
                elif kind == "redirect_target":
                    blocked_redirects.add(sig)
        for safe_tpl in safe_templates:
            trap_templates.pop(safe_tpl, None)
        return {
            "trap_templates": trap_templates,
            "safe_templates": safe_templates,
            "trap_simhashes": trap_simhashes,
            "blocked_redirects": blocked_redirects,
        }

    def record_observation(
        self,
        host: str,
        kind: str,
        signature: str,
        label: str,
        reason: str,
        confidence: float = 0.78,
        manual: bool = False,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT label, hits, confidence, manual FROM trap_memory WHERE host = ? AND kind = ? AND signature = ?",
                (host, kind, signature),
            ).fetchone()
            if existing:
                if existing["manual"] and not manual:
                    return
                if existing["label"] == label:
                    new_hits = int(existing["hits"]) + 1
                    new_conf = min(0.99, max(float(existing["confidence"]), confidence) + 0.05)
                else:
                    new_hits = 1 if manual else max(1, int(existing["hits"]))
                    new_conf = 0.99 if manual else max(0.60, confidence)
                conn.execute(
                    """
                    UPDATE trap_memory
                    SET label = ?, reason = ?, hits = ?, confidence = ?, manual = ?, last_seen = ?
                    WHERE host = ? AND kind = ? AND signature = ?
                    """,
                    (label, reason, new_hits, new_conf, 1 if manual else int(existing["manual"]), now, host, kind, signature),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO trap_memory (host, kind, signature, label, reason, hits, confidence, manual, last_seen)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                    """,
                    (host, kind, signature, label, reason, 0.99 if manual else confidence, 1 if manual else 0, now),
                )

    def get_prior_scans(self, host: str, limit: int = 5) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT scanned_at, score, grade, maturity_tier, archetype, pages_crawled, traps_blocked, findings_json, tech_json
                FROM scan_history
                WHERE host = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (host, limit),
            ).fetchall()
        return [
            {
                "scanned_at": r["scanned_at"],
                "score": int(r["score"]),
                "grade": r["grade"],
                "maturity_tier": r["maturity_tier"],
                "archetype": r["archetype"],
                "pages_crawled": int(r["pages_crawled"]),
                "traps_blocked": int(r["traps_blocked"]),
                "findings": json.loads(r["findings_json"]),
                "technologies": json.loads(r["tech_json"]),
            }
            for r in rows
        ]

    def save_scan_snapshot(self, report: AuditReport) -> None:
        host = urlparse(report.target).netloc
        fingerprints = [
            f"{f.severity}|{f.category}|{f.title}|{urlparse(f.surface).path or '/'}"
            for f in report.findings
        ]
        traps_total = (
            report.shield.hidden_traps_skipped
            + report.shield.url_traps_skipped
            + report.shield.duplicate_traps_capped
            + report.shield.memory_traps_recalled
            + report.shield.semantic_traps_held
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_history (
                    host, scanned_at, score, grade, maturity_tier, archetype,
                    pages_crawled, traps_blocked, findings_json, tech_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host,
                    report.scanned_at,
                    report.score,
                    report.grade,
                    report.expert.maturity_tier,
                    report.expert.archetype,
                    report.pages_crawled,
                    traps_total,
                    json.dumps(fingerprints),
                    json.dumps(report.technologies),
                ),
            )

    def stats(self, host: str | None = None) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            if host:
                traps = conn.execute("SELECT COUNT(*) FROM trap_memory WHERE host = ? AND label = 'TRAP'", (host,)).fetchone()[0]
                safes = conn.execute("SELECT COUNT(*) FROM trap_memory WHERE host = ? AND label = 'SAFE'", (host,)).fetchone()[0]
                scans = conn.execute("SELECT COUNT(*) FROM scan_history WHERE host = ?", (host,)).fetchone()[0]
                entries = conn.execute(
                    "SELECT host, kind, signature, label, reason, hits, confidence, last_seen FROM trap_memory WHERE host = ? ORDER BY hits DESC, last_seen DESC LIMIT 25",
                    (host,),
                ).fetchall()
            else:
                traps = conn.execute("SELECT COUNT(*) FROM trap_memory WHERE label = 'TRAP'").fetchone()[0]
                safes = conn.execute("SELECT COUNT(*) FROM trap_memory WHERE label = 'SAFE'").fetchone()[0]
                scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
                entries = conn.execute(
                    "SELECT host, kind, signature, label, reason, hits, confidence, last_seen FROM trap_memory ORDER BY hits DESC, last_seen DESC LIMIT 25"
                ).fetchall()
            adapter_row = conn.execute("SELECT cumulative_epochs FROM eg2_adapter_state WHERE key = 'global'").fetchone()
            cum_epochs = int(adapter_row["cumulative_epochs"]) if adapter_row else 0
        return {
            "memory_dir": str(self.base_dir),
            "db_path": str(self.db_path),
            "traps_memorized": int(traps),
            "safe_memorized": int(safes),
            "scans_recorded": int(scans),
            "adapter_epochs": cum_epochs,
            "entries": [dict(r) for r in entries],
        }

    def clear_host(self, host: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM trap_memory WHERE host = ?", (host,))
            conn.execute("DELETE FROM scan_history WHERE host = ?", (host,))
