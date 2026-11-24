from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import socket
import ssl
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from bs4 import Tag
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.theme import Theme

APP_NAME = "Zero Suite"
APP_VERSION = "1.0"
POLICY_VERSION = "2026.11-ZERO-SUITE"
CONSENT_FILE = Path.home() / ".zero_suite_consent.json"
DEFAULT_MEMORY_DIR = Path("/sdcard/.zerorcmemo")
FALLBACK_MEMORY_DIR = Path.home() / ".zerorcmemo"
DEFAULT_EG2_HF_MODEL = "google/embeddinggemma-2"
DEFAULT_EG2_OLLAMA_MODEL = "embeddinggemma-2:270m"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_OSV_URL = "https://api.osv.dev/v1/query"
MRL_DIM = 256

ZERO_THEME = Theme({
    "lime": "bold #CCFF00",
    "ink": "#F2F2EE",
    "muted": "#8A8A85",
    "dim": "#555550",
    "border": "#242424",
    "crit": "bold #FF3B30",
    "high": "bold #FF9500",
    "med": "bold #FFD60A",
    "low": "#8A8A85",
    "info": "#6E6E6A",
    "ok": "bold #CCFF00",
    "proven": "bold #CCFF00",
    "unconf": "bold #FFD60A",
    "unk": "bold #8A8A85",
})

console = Console(theme=ZERO_THEME)

ZERO_LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 360 92" width="210" height="54" role="img" aria-label="ZERO">
<g fill="#F2F2EE">
<path d="M10 16h62v13L30 65h43v13H9V65l42-36H10V16z"/>
<path d="M90 16h58v13h-43v11h38v13h-38v12h44v13H90V16z"/>
<path d="M167 16h38c15 0 24 8 24 20 0 9-5 15-14 18l17 24h-18l-15-22h-17v22h-15V16zm15 12v16h21c7 0 11-3 11-8s-4-8-11-8h-21z"/>
<path fill-rule="evenodd" d="M298 14c25 0 44 13 54 33-10 20-29 33-54 33s-44-13-54-33c10-20 29-33 54-33zm0 11a22 22 0 1 0 0 44 22 22 0 0 0 0-44z"/>
</g>
<circle cx="298" cy="47" r="20" fill="#0D0D0D"/>
<g transform="translate(298 47)" fill="#CCFF00">
<circle r="3.4"/>
<path d="M-2.2-5.4L-8.8-15.6A17.8 17.8 0 0 1 8.8-15.6L2.2-5.4A6.2 6.2 0 0 0-2.2-5.4Z"/>
<path d="M5.6 1.2L17.4 4.2A17.8 17.8 0 0 1 8.6 15.8L2.6 5.6A6.2 6.2 0 0 0 5.6 1.2Z"/>
<path d="M-5.6 1.2L-17.4 4.2A17.8 17.8 0 0 0-8.6 15.8L-2.6 5.6A6.2 6.2 0 0 1-5.6 1.2Z"/>
</g>
</svg>"""

TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source",
})

TRAP_PATH_HINTS = frozenset({
    "honeypot", "honey-pot", "tarpit", "tar-pit", "spider-trap", "spidertrap",
    "bot-trap", "bottrap", "crawler-trap", "blackhole", "trap-link",
})

HIDDEN_STYLE_PATTERNS = (
    re.compile(r"display\s*:\s*none", re.I),
    re.compile(r"visibility\s*:\s*hidden", re.I),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*$)", re.I),
    re.compile(r"font-size\s*:\s*0(?:px|em|rem|%)?(?:\s*;|\s*$)", re.I),
    re.compile(r"(?:width|height)\s*:\s*0(?:px)?(?:\s*;|\s*$)", re.I),
    re.compile(r"(?:left|top|text-indent)\s*:\s*-\d{3,}px", re.I),
    re.compile(r"clip\s*:\s*rect\(\s*0", re.I),
)

WELL_KNOWN_CHECKS = (
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/change-password",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/manifest.json",
)

SEMANTIC_OBJECTIVES: dict[str, str] = {
    "Auth & Session": "login signin oauth sso auth token session password reset account portal",
    "API & Data Contracts": "api v1 v2 graphql rest swagger openapi schema json rpc endpoint",
    "Admin & Config Surface": "admin dashboard settings config console internal status health metrics",
    "Client Assets & Code": "static bundle app javascript sourcemap manifest chunk webpack",
    "Trap & Deception": "honeypot tarpit hidden crawler trap blackhole fake decoy infinite calendar",
}

OSV_ECOSYSTEM_MAP: dict[str, tuple[str, str]] = {
    "next.js": ("npm", "next"),
    "react": ("npm", "react"),
    "vue.js": ("npm", "vue"),
    "laravel": ("Packagist", "laravel/framework"),
    "django": ("PyPI", "Django"),
}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
INT_RE = re.compile(r"^\d+$")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SECRET_CONTEXT_RE = re.compile(
    r"""(?i)(?:api[_-]?key|secret|token|auth|bearer|client[_-]?secret|access[_-]?key|private[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{20,128})["']"""
)
API_HINT_RE = re.compile(r"""["'](/(?:api|v\d+|graphql|rest|swagger|openapi)[^"'\s<>]{0,120})["']""", re.I)
SOURCEMAP_RE = re.compile(r"//#\s*sourceMappingURL=([^\s]+)")
DOM_SINK_RE = re.compile(r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write|eval)\s*(?:=|\()")
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
DEBUG_COMMENT_RE = re.compile(r"\b(?:todo|fixme|debug|staging|internal|secret|password|hack|apikey)\b", re.I)
STACKTRACE_RE = re.compile(
    r"(?:Traceback \(most recent call last\)|Fatal error:.*on line \d+|SQLSTATE\[|NullReferenceException|at [a-zA-Z0-9_.]+\([A-Za-z0-9_.]+\.java:\d+\))"
)

TECH_SIGNATURES: dict[str, tuple[str, ...]] = {
    "WordPress": ("wp-content", "wp-includes"),
    "Next.js": ("_next/static", "__next_data__"),
    "React": ("react-dom", "data-reactroot"),
    "Vue.js": ("__vue__", "vue.runtime"),
    "Laravel": ("laravel_session", "csrf-token"),
    "Django": ("csrfmiddlewaretoken",),
    "Cloudflare": ("cf-ray", "__cf_bm"),
    "Nginx": ("server:nginx",),
    "Apache": ("server:apache",),
}

SECURITY_HEADERS_SPEC: dict[str, tuple[str, str, str, str]] = {
    "content-security-policy": (
        "HIGH",
        "Without CSP, any injected script or compromised third-party asset executes with full DOM and session privileges.",
        "Enforce a strict nonce/hash-based CSP with default-src 'none', object-src 'none', and base-uri 'self'.",
        "Inspect response headers via curl -sSI and confirm Content-Security-Policy is present without unsafe-inline.",
    ),
    "strict-transport-security": (
        "HIGH",
        "Browsers may accept initial plaintext HTTP requests, exposing users to SSL-stripping downgrade attacks.",
        "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
        "Verify Strict-Transport-Security header on HTTPS responses and confirm max-age >= 31536000.",
    ),
    "x-content-type-options": (
        "MEDIUM",
        "Browsers may MIME-sniff non-script responses into executable scripts, enabling stored XSS via uploads.",
        "Set X-Content-Type-Options: nosniff on all HTTP responses.",
        "Check response headers across HTML, API, and static routes for X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        "MEDIUM",
        "Pages can be embedded in hostile iframes to trick authenticated users into unintended clicks (clickjacking).",
        "Set X-Frame-Options: DENY and CSP frame-ancestors 'none'.",
        "Confirm X-Frame-Options or CSP frame-ancestors blocks cross-origin framing in browser DevTools.",
    ),
    "referrer-policy": (
        "LOW",
        "Full URLs containing tokens, IDs, or internal paths can leak via the Referer header to third parties.",
        "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
        "Verify Referrer-Policy header is emitted on document and navigation responses.",
    ),
    "permissions-policy": (
        "LOW",
        "Embedded frames or scripts may request sensitive browser APIs unless explicitly restricted.",
        "Set Permissions-Policy: camera=(), microphone=(), geolocation=().",
        "Inspect Permissions-Policy header in root and subpage responses.",
    ),
    "cross-origin-opener-policy": (
        "LOW",
        "Shared browsing context groups allow cross-origin windows to retain window.opener references.",
        "Set Cross-Origin-Opener-Policy: same-origin for process isolation.",
        "Verify Cross-Origin-Opener-Policy: same-origin on HTML responses.",
    ),
    "cross-origin-resource-policy": (
        "LOW",
        "Cross-origin documents may embed or probe resources via speculative side-channel leaks.",
        "Set Cross-Origin-Resource-Policy: same-origin on sensitive endpoints.",
        "Verify Cross-Origin-Resource-Policy header on authenticated and static endpoints.",
    ),
    "cross-origin-embedder-policy": (
        "LOW",
        "High-value origins lack cross-origin isolation guarantees without explicit embedder policy.",
        "Set Cross-Origin-Embedder-Policy: require-corp when compatible with subresources.",
        "Confirm Cross-Origin-Embedder-Policy header on isolated document routes.",
    ),
}

SEVERITY_WEIGHTS = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 0}
VERDICT_ORDER = {"PROVEN": 3, "UNCONFIRMED": 2, "UNKNOWN": 1}
CSRF_FIELD_HINTS = ("csrf", "xsrf", "_token", "authenticity_token", "antiforgery", "__requestverificationtoken")

TERMS_TEXT = (
    "ZERO SUITE // AUTHORIZED DEFENSIVE AUDIT POLICY (v2026.11)\n\n"
    "1. AUTHORIZED SCOPE ONLY: Operate Zero Suite exclusively on domains, staging servers,\n"
    "   or web assets you own or hold explicit written authorization to audit.\n"
    "2. EPISTEMIC INTEGRITY: Zero Suite separates PROVEN facts, UNCONFIRMED leads (with\n"
    "   explicit reasons why confirmation failed), and UNKNOWN blind spots.\n"
    "3. SAFE VERIFICATION PoCs: ZSES + EmbeddingGemma 2 generate non-destructive reproduction\n"
    "   commands (curl/openssl) strictly for PROVEN defensive posture findings.\n"
    "4. PERSISTENT MEMORY: Learned weights, traps, and intel cache persist in /sdcard/.zerorcmemo.\n"
    "5. FULL RESPONSIBILITY: You assume sole legal and operational responsibility for all audits."
)


@dataclass(slots=True)
class AuditConfig:
    profile: str = "deep"
    memory_dir: Path = DEFAULT_MEMORY_DIR
    embed_backend: str = "auto"
    ollama_url: str = DEFAULT_OLLAMA_URL
    ollama_model: str = DEFAULT_EG2_OLLAMA_MODEL
    hf_model: str = DEFAULT_EG2_HF_MODEL
    embed_dim: int = MRL_DIM
    enable_net_intel: bool = True
    kev_url: str = DEFAULT_KEV_URL
    osv_url: str = DEFAULT_OSV_URL
    deliberation_rounds: int = 4
    deliberation_pace: float = 0.30
    train_epochs: int = 12
    max_pages: int = 150
    max_requests: int = 800
    max_per_template: int = 8
    max_js_files: int = 30
    max_sitemap_urls: int = 80
    max_redirects: int = 3
    allow_cross_host_redirects: bool = False
    allow_private_ips: bool = False
    max_body_bytes: int = 2_097_152
    max_url_length: int = 512
    max_path_depth: int = 8
    max_query_params: int = 10
    max_duplicate_content: int = 4
    tarpit_latency_ms: float = 4000.0
    tarpit_threshold: int = 5
    rps: float = 5.0
    timeout: float = 10.0
    workers: int = 8
    respect_robots: bool = True
    simhash_threshold: int = 8
    entropy_threshold: float = 4.2
    user_agent: str = "ZeroSuite/1.0 (+authorized-epistemic-audit)"


@dataclass(slots=True)
class FetchResult:
    response: Any
    body_text: str
    body_bytes: int
    latency_ms: float
    final_url: str
    redirect_chain: list[str] = field(default_factory=list)
    blocked_reason: str | None = None
    blocked_location: str | None = None


@dataclass(slots=True)
class Finding:
    severity: str
    verdict: str
    category: str
    title: str
    surface: str
    evidence: str
    proof_basis: str
    unconfirmed_reason: str
    missing_evidence: str
    why_it_matters: str
    remediation: str
    verification: str


@dataclass(slots=True)
class VerificationPoC:
    finding_title: str
    category: str
    severity: str
    verdict: str
    surface: str
    safe_repro_command: str
    expected_vulnerable_signal: str
    expected_patched_signal: str
    blue_team_fix_snippet: str
    epistemic_note: str


@dataclass(slots=True)
class UnknownBoundary:
    domain: str
    why_unknown: str
    required_for_proof: str


@dataclass(slots=True)
class AttackChain:
    name: str
    severity: str
    verdict: str
    linked_categories: list[str]
    explanation: str
    priority_fix: str


@dataclass(slots=True)
class NextAction:
    priority: str
    action: str
    rationale: str
    command_hint: str


@dataclass(slots=True)
class DriftSummary:
    has_prior: bool = False
    prior_scans: int = 0
    prior_score: int | None = None
    score_delta: int = 0
    trend: str = "FIRST_BASELINE"
    new_findings: int = 0
    resolved_findings: int = 0
    chronic_findings: int = 0


@dataclass(slots=True)
class AutonomousRouteStep:
    url: str
    cluster: str
    priority_score: float
    trap_similarity: float
    decision: str
    reason: str


@dataclass(slots=True)
class IntelAdvisory:
    source: str
    identifier: str
    component: str
    summary: str
    published: str
    verdict: str = "UNCONFIRMED"
    unconfirmed_reason: str = "Banner/framework keyword matched, but exact patch level cannot be proven passively."


@dataclass(slots=True)
class TrainingMetrics:
    samples_used: int = 0
    trap_samples: int = 0
    safe_samples: int = 0
    epochs_run: int = 0
    cumulative_epochs: int = 0
    loss_before: float = 0.0
    loss_after: float = 0.0
    margin_gain: float = 0.0
    persisted: bool = False


@dataclass(slots=True)
class DeliberationTurn:
    round_num: int
    speaker: str
    topic: str
    statement: str
    consensus_score: float


@dataclass(slots=True)
class AutonomousAnalysis:
    model_backend: str
    execution_privilege: str
    flow_owner: str
    net_intel_status: str
    waves_planned: int
    routes_prioritized: int
    semantic_traps_flagged: int
    coverage_status: str
    consensus_reached: bool
    final_consensus_score: float
    training: TrainingMetrics = field(default_factory=TrainingMetrics)
    intel_advisories: list[IntelAdvisory] = field(default_factory=list)
    deliberation: list[DeliberationTurn] = field(default_factory=list)
    cluster_counts: dict[str, int] = field(default_factory=dict)
    semantic_trap_warnings: list[str] = field(default_factory=list)
    completion_path: list[str] = field(default_factory=list)
    top_guided_routes: list[AutonomousRouteStep] = field(default_factory=list)


@dataclass(slots=True)
class ExpertAssessment:
    archetype: str
    maturity_tier: str
    scan_integrity: str
    deception_posture: str
    trap_risk_index: int
    proven_count: int
    unconfirmed_count: int
    unknown_count: int
    position_summary: str
    memory_summary: str
    drift: DriftSummary
    autonomous: AutonomousAnalysis
    verification_pocs: list[VerificationPoC] = field(default_factory=list)
    unknown_boundaries: list[UnknownBoundary] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    risk_chains: list[AttackChain] = field(default_factory=list)
    next_actions: list[NextAction] = field(default_factory=list)


@dataclass(slots=True)
class PageMetric:
    url: str
    status: int
    content_type: str
    size_bytes: int
    latency_ms: float
    simhash_hex: str


@dataclass(slots=True)
class TlsInfo:
    protocol: str | None = None
    cipher: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    san_hosts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ShieldStats:
    redirects_blocked: int = 0
    private_ip_blocked: int = 0
    hidden_traps_skipped: int = 0
    url_traps_skipped: int = 0
    duplicate_traps_capped: int = 0
    memory_traps_recalled: int = 0
    semantic_traps_held: int = 0
    memory_patterns_learned: int = 0
    oversized_truncated: int = 0
    rate_limited_events: int = 0
    tarpit_triggered: bool = False


@dataclass(slots=True)
class AuditReport:
    target: str
    profile: str
    memory_path: str
    scanned_at: str
    duration_seconds: float
    score: int
    grade: str
    total_requests: int
    pages_crawled: int
    js_bundles_audited: int
    sitemap_entries_loaded: int
    soft_404_filtered: int
    template_capped: int
    shield: ShieldStats
    tls: TlsInfo
    technologies: list[str]
    allowed_methods: list[str]
    well_known_found: list[str]
    findings: list[Finding]
    expert: ExpertAssessment
    page_metrics: list[PageMetric]
    discovered_urls: list[str]
    api_references: list[str]
    emails: list[str]
    robots_disallowed: list[str]
    sitemap_urls: list[str]
    security_txt_present: bool


class TokenBucket:
    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self._rate = max(rate, 0.2)
        self._base_rate = self._rate
        self._capacity = capacity or max(1.0, self._rate)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_time = (1.0 - self._tokens) / self._rate
            time.sleep(min(wait_time, 1.0))

    def throttle(self, retry_after: float | None = None) -> None:
        with self._lock:
            self._rate = max(0.5, self._rate * 0.5)
            if retry_after:
                self._tokens = min(self._tokens, -retry_after * self._rate)

    def recover(self) -> None:
        with self._lock:
            if self._rate < self._base_rate:
                self._rate = min(self._base_rate, self._rate * 1.1)


def l2_normalize(vec: list[float], dim: int) -> list[float]:
    sliced = vec[:dim] if len(vec) >= dim else vec + [0.0] * (dim - len(vec))
    norm = math.sqrt(sum(v * v for v in sliced))
    if norm <= 1e-12:
        return [0.0] * dim
    return [v / norm for v in sliced]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


def mean_vector(vectors: list[list[float]], dim: int) -> list[float]:
    if not vectors:
        return [0.0] * dim
    acc = [0.0] * dim
    for v in vectors:
        for i in range(dim):
            acc[i] += v[i]
    return l2_normalize(acc, dim)


def compute_simhash(text: str) -> int:
    tokens = re.findall(r"[a-z0-9]{2,}", text.lower())
    if not tokens:
        return 0
    shingles = (
        [" ".join(tokens[i : i + 3]) for i in range(max(1, len(tokens) - 2))]
        if len(tokens) >= 3
        else tokens
    )
    weights = Counter(shingles)
    vector = [0] * 64
    for shingle, weight in weights.items():
        digest = int.from_bytes(hashlib.blake2b(shingle.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            if digest & (1 << bit):
                vector[bit] += weight
            else:
                vector[bit] -= weight
    fingerprint = 0
    for bit, score in enumerate(vector):
        if score > 0:
            fingerprint |= 1 << bit
    return fingerprint


def hamming_distance(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def normalize_url(raw_url: str, base_url: str) -> str | None:
    joined = urljoin(base_url, raw_url.strip())
    parsed = urlparse(joined)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    filtered_query = sorted(
        (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if k.lower() not in TRACKING_PARAMS
    )
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    return urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path,
        "",
        urlencode(filtered_query),
        "",
    ))


def structural_template(url: str) -> str:
    parsed = urlparse(url)
    segments: list[str] = []
    for seg in parsed.path.split("/"):
        if not seg:
            continue
        if UUID_RE.match(seg):
            segments.append("{uuid}")
        elif DATE_RE.match(seg):
            segments.append("{date}")
        elif INT_RE.match(seg):
            segments.append("{int}")
        elif HEX_RE.match(seg):
            segments.append("{hex}")
        else:
            segments.append(re.sub(r"\d+", "{n}", seg.lower()))
    query_keys = ",".join(sorted({k for k, _ in parse_qsl(parsed.query)}))
    return f"/{'/'.join(segments)}?{query_keys}"


def is_private_or_restricted_host(hostname: str, allow_private: bool = False) -> bool:
    if allow_private:
        return False
    clean_host = hostname.strip().lower().rstrip(".")
    if not clean_host or clean_host in ("localhost", "localhost.localdomain"):
        return True
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return not ip_obj.is_global
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(clean_host, None, type=socket.SOCK_STREAM)
    except OSError:
        return True
    if not infos:
        return True
    for info in infos:
        addr = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(addr)
        except ValueError:
            return True
        if not ip_obj.is_global:
            return True
    return False


def is_hidden_trap_element(tag: Tag) -> bool:
    node: Tag | None = tag
    for _ in range(4):
        if node is None or not isinstance(node, Tag):
            break
        if node.has_attr("hidden"):
            return True
        if str(node.get("aria-hidden", "")).strip().lower() == "true":
            return True
        style = str(node.get("style", ""))
        if style and any(pat.search(style) for pat in HIDDEN_STYLE_PATTERNS):
            return True
        node = node.parent if isinstance(node.parent, Tag) else None
    if tag.name == "a":
        rel_tokens = {str(r).lower() for r in (tag.get("rel") or [])}
        if "nofollow" in rel_tokens and not tag.get_text(strip=True) and not tag.find("img"):
            return True
        if str(tag.get("tabindex", "")).strip() == "-1" and not tag.get_text(strip=True):
            return True
    return False


def is_trap_url(url: str, config: AuditConfig) -> str | None:
    if len(url) > config.max_url_length:
        return "excessive_url_length"
    parsed = urlparse(url)
    segments = [s.lower() for s in parsed.path.split("/") if s]
    if len(segments) > config.max_path_depth:
        return "excessive_path_depth"
    if any(seg in TRAP_PATH_HINTS for seg in segments):
        return "honeypot_path_keyword"
    seg_counts = Counter(segments)
    if any(count >= 3 for count in seg_counts.values()):
        return "repeating_path_segments"
    if len(segments) >= 4:
        for span in (1, 2):
            for idx in range(len(segments) - (span * 2) + 1):
                if segments[idx : idx + span] == segments[idx + span : idx + (span * 2)]:
                    return "cyclic_path_pattern"
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if len(query_pairs) > config.max_query_params:
        return "query_parameter_explosion"
    return None


def inspect_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> TlsInfo:
    info = TlsInfo()
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                info.protocol = tls_sock.version()
                cipher = tls_sock.cipher()
                info.cipher = cipher[0] if cipher else None
                cert = tls_sock.getpeercert()
                if cert:
                    issuer_parts = [v for rdn in cert.get("issuer", ()) for k, v in rdn if k == "organizationName"]
                    info.issuer = issuer_parts[0] if issuer_parts else None
                    not_after = cert.get("notAfter")
                    if not_after:
                        info.not_after = not_after
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        info.days_remaining = (expiry - datetime.now(timezone.utc)).days
                    info.san_hosts = sorted({
                        val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"
                    })
    except OSError:
        pass
    return info


def compute_grade(findings: list[Finding]) -> tuple[int, str]:
    deductions = sum(
        SEVERITY_WEIGHTS.get(f.severity, 0) if f.verdict == "PROVEN" else max(1, SEVERITY_WEIGHTS.get(f.severity, 0) // 2)
        for f in findings
        if f.severity != "INFO"
    )
    score = max(0, 100 - deductions)
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 45:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def _policy_hash() -> str:
    return hashlib.sha256(f"{POLICY_VERSION}:{TERMS_TEXT}".encode()).hexdigest()[:16]


def ensure_policy_consent(auto_accept: bool = False) -> None:
    expected_hash = _policy_hash()
    if CONSENT_FILE.exists():
        try:
            saved = json.loads(CONSENT_FILE.read_text(encoding="utf-8"))
            if saved.get("version") == POLICY_VERSION and saved.get("hash") == expected_hash:
                return
        except (OSError, json.JSONDecodeError):
            pass

    console.print(
        Panel(
            TERMS_TEXT,
            title="[lime]ZERO SUITE // AUTHORIZATION CONSENT[/lime]",
            border_style="#CCFF00",
            box=box.SQUARE,
            padding=(1, 2),
        )
    )
    if not auto_accept:
        answer = Prompt.ask(
            "[lime]Type[/lime] [ink]AGREE[/ink] [lime]to confirm authorized defensive scope[/lime]"
        ).strip()
        if answer != "AGREE":
            console.print("[crit]Consent declined. Exiting Zero Suite.[/crit]")
            raise SystemExit(1)

    record = {
        "accepted_at": datetime.now(timezone.utc).isoformat(),
        "version": POLICY_VERSION,
        "hash": expected_hash,
    }
    try:
        CONSENT_FILE.write_text(json.dumps(record, indent=2), encoding="utf-8")
    except OSError:
        pass
