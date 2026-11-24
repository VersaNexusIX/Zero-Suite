from __future__ import annotations

import base64
import difflib
import json
import re
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from urllib3.util.retry import Retry

from zero_suite.core import (
    API_HINT_RE,
    COMMENT_RE,
    CSRF_FIELD_HINTS,
    DEBUG_COMMENT_RE,
    DEFAULT_MEMORY_DIR,
    DOM_SINK_RE,
    EMAIL_RE,
    SECRET_CONTEXT_RE,
    SECURITY_HEADERS_SPEC,
    SEVERITY_WEIGHTS,
    SOURCEMAP_RE,
    STACKTRACE_RE,
    TECH_SIGNATURES,
    VERDICT_ORDER,
    WELL_KNOWN_CHECKS,
    AuditConfig,
    AuditReport,
    AutonomousRouteStep,
    FetchResult,
    Finding,
    PageMetric,
    ShieldStats,
    TlsInfo,
    TokenBucket,
    compute_grade,
    compute_simhash,
    console,
    hamming_distance,
    inspect_tls,
    is_hidden_trap_element,
    is_private_or_restricted_host,
    is_trap_url,
    normalize_url,
    shannon_entropy,
    structural_template,
)
from zero_suite.eg2 import EmbeddingGemma2Advisor
from zero_suite.expert import ZeroExpertSystem
from zero_suite.memory import PublicIntelFetcher, ZeroMemoryStore


class ZeroSuiteAuditor:
    def __init__(
        self,
        target_url: str,
        config: AuditConfig | None = None,
        memory: ZeroMemoryStore | None = None,
        advisor: EmbeddingGemma2Advisor | None = None,
    ) -> None:
        normalized = normalize_url(target_url, target_url)
        if not normalized:
            raise ValueError(f"Invalid target URL: {target_url}")
        self.target_url = normalized
        self.parsed_target = urlparse(normalized)
        self.host = self.parsed_target.netloc
        self.config = config or AuditConfig()
        self.memory = memory or ZeroMemoryStore(self.config.memory_dir)
        self.advisor = advisor or EmbeddingGemma2Advisor(
            backend=self.config.embed_backend,
            ollama_url=self.config.ollama_url,
            ollama_model=self.config.ollama_model,
            hf_model=self.config.hf_model,
            dim=self.config.embed_dim,
            adapter_state=self.memory.load_adapter_state(self.config.embed_dim),
        )
        self.intel = PublicIntelFetcher(
            cache_dir=self.memory.base_dir,
            kev_url=self.config.kev_url,
            osv_url=self.config.osv_url,
            enabled=self.config.enable_net_intel,
        )
        self.known = self.memory.load_host_knowledge(self.host)
        self.bucket = TokenBucket(self.config.rps)
        self.session = self._build_session()
        self.request_count = 0
        self.slow_streak = 0
        self.shield = ShieldStats()
        self._lock = threading.Lock()
        self.robots = RobotFileParser()
        self.robots_disallowed: list[str] = []
        self.sitemap_urls: list[str] = []
        self.redirect_findings: list[Finding] = []
        self.session_traps: set[str] = set(self.known["trap_templates"].keys())
        self.session_safes: set[str] = set(self.known["safe_templates"])
        self.has_auth_forms = False
        self.expert_engine = ZeroExpertSystem()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=2,
            backoff_factor=0.4,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=("GET", "HEAD", "OPTIONS"),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=16, pool_maxsize=16)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": self.config.user_agent})
        return session

    def _memorize(self, kind: str, signature: str, label: str, reason: str, confidence: float = 0.80) -> None:
        self.memory.record_observation(self.host, kind, signature, label, reason, confidence=confidence)
        with self._lock:
            self.shield.memory_patterns_learned += 1
            if kind == "url_template":
                if label == "TRAP":
                    self.session_traps.add(signature)
                elif label == "SAFE":
                    self.session_safes.add(signature)

    def _read_bounded_body(self, resp: requests.Response) -> tuple[str, int, bool]:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in resp.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                remaining = self.config.max_body_bytes - total
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    total += remaining
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            resp.close()
        raw = b"".join(chunks)
        encoding = resp.encoding or "utf-8"
        text = raw.decode(encoding, errors="replace")
        return text, total, truncated

    def _validate_redirect_hop(self, current_url: str, location: str, seen_hops: set[str]) -> tuple[str | None, str | None]:
        next_url = normalize_url(location, current_url)
        if not next_url:
            return None, "invalid_or_non_http_redirect_scheme"
        if next_url in seen_hops:
            return None, "redirect_loop_detected"
        if next_url in self.known["blocked_redirects"]:
            with self._lock:
                self.shield.memory_traps_recalled += 1
            return None, "memorized_blocked_redirect"
        cur_p = urlparse(current_url)
        nxt_p = urlparse(next_url)
        if cur_p.scheme == "https" and nxt_p.scheme == "http":
            return None, "https_to_http_downgrade_blocked"
        if not self.config.allow_cross_host_redirects and nxt_p.netloc != self.host:
            return None, "cross_host_redirect_blocked"
        if nxt_p.hostname and is_private_or_restricted_host(nxt_p.hostname, self.config.allow_private_ips):
            with self._lock:
                self.shield.private_ip_blocked += 1
            return None, "private_or_restricted_ip_redirect_blocked"
        trap_reason = is_trap_url(next_url, self.config)
        if trap_reason:
            with self._lock:
                self.shield.url_traps_skipped += 1
            return None, f"redirect_trap_blocked:{trap_reason}"
        return next_url, None

    def fetch(self, url: str, method: str = "GET", headers: dict[str, str] | None = None) -> FetchResult:
        current_url = url
        redirect_chain: list[str] = []
        seen_hops: set[str] = {current_url}
        total_latency = 0.0

        for _ in range(self.config.max_redirects + 1):
            parsed = urlparse(current_url)
            if not parsed.hostname or is_private_or_restricted_host(parsed.hostname, self.config.allow_private_ips):
                with self._lock:
                    self.shield.private_ip_blocked += 1
                return FetchResult(None, "", 0, round(total_latency, 1), current_url, redirect_chain, "private_or_restricted_ip_blocked", current_url)

            with self._lock:
                if self.request_count >= self.config.max_requests:
                    return FetchResult(None, "", 0, round(total_latency, 1), current_url, redirect_chain, "max_requests_reached")
                self.request_count += 1

            self.bucket.acquire()
            t0 = time.monotonic()
            try:
                resp = self.session.request(
                    method,
                    current_url,
                    timeout=self.config.timeout,
                    allow_redirects=False,
                    stream=True,
                    headers=headers,
                )
            except requests.RequestException:
                elapsed = (time.monotonic() - t0) * 1000.0
                return FetchResult(None, "", 0, round(total_latency + elapsed, 1), current_url, redirect_chain, "network_error")

            elapsed = (time.monotonic() - t0) * 1000.0
            total_latency += elapsed

            with self._lock:
                if elapsed >= self.config.tarpit_latency_ms:
                    self.slow_streak += 1
                    self._memorize("url_template", structural_template(current_url), "TRAP", "tarpit_latency", 0.85)
                    if self.slow_streak >= self.config.tarpit_threshold:
                        self.shield.tarpit_triggered = True
                else:
                    self.slow_streak = 0

            if resp.status_code in (429, 503):
                with self._lock:
                    self.shield.rate_limited_events += 1
                retry_raw = resp.headers.get("Retry-After")
                retry_after = float(retry_raw) if retry_raw and retry_raw.isdigit() else None
                self.bucket.throttle(retry_after)
            else:
                self.bucket.recover()

            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                location = resp.headers["Location"]
                resp.close()
                next_url, block_reason = self._validate_redirect_hop(current_url, location, seen_hops)
                if block_reason or not next_url:
                    with self._lock:
                        self.shield.redirects_blocked += 1
                    norm_loc = normalize_url(location, current_url)
                    if norm_loc and block_reason != "memorized_blocked_redirect":
                        self._memorize("redirect_target", norm_loc, "TRAP", block_reason or "blocked_redirect", 0.90)
                        if block_reason == "redirect_loop_detected":
                            self._memorize("url_template", structural_template(current_url), "TRAP", "redirect_loop", 0.90)
                    if block_reason == "https_to_http_downgrade_blocked":
                        with self._lock:
                            self.redirect_findings.append(Finding(
                                severity="HIGH",
                                verdict="PROVEN",
                                category="REDIRECT_GUARD",
                                title="HTTPS-to-HTTP redirect downgrade blocked",
                                surface=current_url,
                                evidence=f"HTTP {resp.status_code} Location: {location}",
                                proof_basis="Direct HTTP 3xx Location header returned plaintext http:// from an https:// route.",
                                unconfirmed_reason="",
                                missing_evidence="",
                                why_it_matters="Redirecting from HTTPS to plaintext HTTP strips transport encryption and exposes cookies or credentials to MitM.",
                                remediation="Rewrite redirect rules to enforce https:// destinations and enable HSTS.",
                                verification=f"Run curl -sSI --max-redirs 0 {current_url} and confirm Location starts with https://.",
                            ))
                    elif block_reason == "cross_host_redirect_blocked":
                        with self._lock:
                            self.redirect_findings.append(Finding(
                                severity="INFO",
                                verdict="UNCONFIRMED",
                                category="REDIRECT_GUARD",
                                title="Cross-host redirect blocked by strict scope lock",
                                surface=current_url,
                                evidence=f"HTTP {resp.status_code} Location: {location}",
                                proof_basis="Direct 3xx Location header points to an external host.",
                                unconfirmed_reason="External redirect may be an intentional partner/SSO link rather than an arbitrary Open Redirect.",
                                missing_evidence="Verify whether redirect destination is controlled by user query parameters or fixed server-side.",
                                why_it_matters="User-controlled cross-host redirects can be abused for phishing or OAuth token redirection.",
                                remediation="Validate redirect destinations against an explicit server-side host allowlist.",
                                verification=f"Inspect {current_url} redirect logic and verify arbitrary external hosts are rejected.",
                            ))
                    return FetchResult(resp, "", 0, round(total_latency, 1), current_url, redirect_chain, block_reason, location)
                redirect_chain.append(current_url)
                seen_hops.add(next_url)
                current_url = next_url
                continue

            if method == "HEAD":
                resp.close()
                return FetchResult(resp, "", 0, round(total_latency, 1), current_url, redirect_chain)

            body_text, body_bytes, truncated = self._read_bounded_body(resp)
            if truncated:
                with self._lock:
                    self.shield.oversized_truncated += 1
            return FetchResult(resp, body_text, body_bytes, round(total_latency, 1), current_url, redirect_chain)

        with self._lock:
            self.shield.redirects_blocked += 1
        return FetchResult(None, "", 0, round(total_latency, 1), current_url, redirect_chain, "max_redirects_exceeded")

    def _visible_text(self, html: str, echoed_path: str = "") -> str:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
        if echoed_path and echoed_path != "/":
            text = text.replace(echoed_path, " ")
        return text

    def _load_robots_and_sitemaps(self) -> list[str]:
        base = f"{self.parsed_target.scheme}://{self.host}"
        robots_url = f"{base}/robots.txt"
        res = self.fetch(robots_url)
        if res.response and res.response.status_code == 200:
            lines = res.body_text.splitlines()
            self.robots.parse(lines)
            for line in lines:
                stripped = line.strip()
                lower = stripped.lower()
                if lower.startswith("disallow:"):
                    path = stripped.split(":", 1)[1].strip()
                    if path:
                        self.robots_disallowed.append(path)
                elif lower.startswith("sitemap:"):
                    sitemap = stripped.split(":", 1)[1].strip()
                    if sitemap:
                        self.sitemap_urls.append(sitemap)

        if self.config.profile != "deep":
            return []

        sitemap_candidates = list(dict.fromkeys(self.sitemap_urls or [f"{base}/sitemap.xml"]))
        extracted_urls: list[str] = []
        visited_sitemaps: set[str] = set()

        while sitemap_candidates and len(extracted_urls) < self.config.max_sitemap_urls:
            sm_url = sitemap_candidates.pop(0)
            norm_sm = normalize_url(sm_url, base)
            if not norm_sm or norm_sm in visited_sitemaps:
                continue
            if urlparse(norm_sm).netloc != self.host:
                continue
            visited_sitemaps.add(norm_sm)
            sm_res = self.fetch(norm_sm)
            if not sm_res.response or sm_res.response.status_code != 200 or not sm_res.body_text.strip():
                continue
            if norm_sm not in self.sitemap_urls:
                self.sitemap_urls.append(norm_sm)
            try:
                root = ET.fromstring(sm_res.body_text)
            except ET.ParseError:
                continue
            for elem in root.iter():
                tag_name = elem.tag.rsplit("}", 1)[-1].lower()
                if tag_name == "loc" and elem.text:
                    loc = normalize_url(elem.text.strip(), base)
                    if not loc or urlparse(loc).netloc != self.host:
                        continue
                    if loc.endswith(".xml") and len(visited_sitemaps) < 5:
                        sitemap_candidates.append(loc)
                    elif not is_trap_url(loc, self.config):
                        extracted_urls.append(loc)
                        if len(extracted_urls) >= self.config.max_sitemap_urls:
                            break
        return list(dict.fromkeys(extracted_urls))

    def _audit_well_known(self, soft_404_hashes: list[int]) -> tuple[list[str], list[Finding], bool]:
        base = f"{self.parsed_target.scheme}://{self.host}"
        found: list[str] = []
        findings: list[Finding] = []
        security_txt = False

        checks = WELL_KNOWN_CHECKS if self.config.profile == "deep" else ("/.well-known/security.txt",)
        for path in checks:
            url = base + path
            res = self.fetch(url)
            if not res.response or res.response.status_code != 200 or res.blocked_reason:
                continue
            if soft_404_hashes and res.body_text:
                h = compute_simhash(self._visible_text(res.body_text, path))
                if any(hamming_distance(h, s404) <= self.config.simhash_threshold for s404 in soft_404_hashes):
                    continue
            found.append(path)
            if path == "/.well-known/security.txt":
                security_txt = True
            elif path in ("/crossdomain.xml", "/clientaccesspolicy.xml") and ('domain="*"' in res.body_text or 'uri="*"' in res.body_text):
                findings.append(Finding(
                    severity="HIGH",
                    verdict="PROVEN",
                    category="CROSS_DOMAIN_POLICY",
                    title=f"Overly permissive wildcard policy in {path}",
                    surface=url,
                    evidence="Wildcard domain/uri='*' detected in XML policy",
                    proof_basis=f"Direct GET {url} returned HTTP 200 containing literal wildcard domain='*'.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Wildcard legacy cross-domain policies authorize arbitrary external origins to read authenticated responses.",
                    remediation=f"Remove {path} or restrict allowed domains to explicitly trusted hosts.",
                    verification=f"Fetch {url} and confirm wildcard entries are removed or return 404.",
                ))
        return found, findings, security_txt

    def _calibrate_soft_404(self) -> list[int]:
        hashes: list[int] = []
        base = f"{self.parsed_target.scheme}://{self.host}"
        for probe in ("/__zero_probe_alpha_9182__", "/__zero_probe_beta_7364__/nested"):
            res = self.fetch(base + probe)
            if res.response and res.response.status_code == 200 and res.body_text:
                sim = compute_simhash(self._visible_text(res.body_text, probe))
                hashes.append(sim)
                self._memorize("simhash", f"{sim:016x}", "TRAP", "soft_404_fingerprint", 0.85)
        return hashes

    def _audit_csp(self, csp_value: str, surface: str) -> list[Finding]:
        findings: list[Finding] = []
        directives: dict[str, list[str]] = {}
        for part in csp_value.split(";"):
            tokens = part.strip().split()
            if tokens:
                directives[tokens[0].lower()] = tokens[1:]

        for required in ("default-src", "object-src", "base-uri", "frame-ancestors"):
            if required not in directives:
                findings.append(Finding(
                    severity="MEDIUM",
                    verdict="PROVEN",
                    category="CSP",
                    title=f"Missing CSP directive: {required}",
                    surface=surface,
                    evidence=csp_value[:140],
                    proof_basis=f"Parsed Content-Security-Policy header on {surface} deterministically omits '{required}'.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters=f"Omitting {required} leaves fallback gaps for plugin execution, base-tag hijacking, or framing.",
                    remediation=f"Add {required} 'none' (or strict allowlist) to Content-Security-Policy.",
                    verification=f"Inspect Content-Security-Policy on {surface} and confirm {required} is explicitly defined.",
                ))

        script_sources = directives.get("script-src", directives.get("default-src", []))
        for risky in ("'unsafe-inline'", "'unsafe-eval'", "*", "http:", "data:"):
            if risky in script_sources:
                findings.append(Finding(
                    severity="HIGH",
                    verdict="PROVEN",
                    category="CSP",
                    title=f"Weak script-src token: {risky}",
                    surface=surface,
                    evidence=f"script-src {' '.join(script_sources)}"[:140],
                    proof_basis=f"Parsed CSP script-src explicitly contains unsafe token {risky}.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters=f"Allowing {risky} in script-src neutralizes CSP protection against inline or dynamic XSS payloads.",
                    remediation="Replace unsafe/wildcard script-src with per-request cryptographic nonces or SHA-256/384 hashes.",
                    verification=f"Verify script-src on {surface} contains only 'self', strict-dynamic, or nonce/hash tokens.",
                ))
        return findings

    def _audit_response_headers(self, resp: requests.Response, surface: str, is_root: bool) -> list[Finding]:
        findings: list[Finding] = []
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        parsed = urlparse(surface)

        if is_root and parsed.scheme == "http":
            findings.append(Finding(
                severity="HIGH",
                verdict="PROVEN",
                category="TRANSPORT",
                title="Unencrypted HTTP target",
                surface=surface,
                evidence="Target served over http://",
                proof_basis="Live GET response succeeded over plaintext http:// without forced HTTPS redirect.",
                unconfirmed_reason="",
                missing_evidence="",
                why_it_matters="Plaintext HTTP allows passive eavesdropping and active content injection across untrusted networks.",
                remediation="Enforce HTTPS with 301/308 redirect from port 80 and enable HSTS.",
                verification=f"Confirm http://{parsed.netloc} returns 301/308 to https://{parsed.netloc}.",
            ))

        checked_headers = SECURITY_HEADERS_SPEC if is_root else {
            k: SECURITY_HEADERS_SPEC[k] for k in ("content-security-policy", "x-frame-options", "x-content-type-options")
        }
        for header, (sev, why, fix, verify) in checked_headers.items():
            if header == "strict-transport-security" and parsed.scheme != "https":
                continue
            if header not in headers_lower:
                findings.append(Finding(
                    severity=sev,
                    verdict="PROVEN",
                    category="HEADERS",
                    title=f"Missing security header: {header}",
                    surface=surface,
                    evidence=f"Header absent in HTTP {resp.status_code} response",
                    proof_basis=f"Direct HTTP response header inspection on {surface} verified '{header}' is absent.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters=why,
                    remediation=fix,
                    verification=verify,
                ))

        if "content-security-policy" in headers_lower:
            findings.extend(self._audit_csp(headers_lower["content-security-policy"], surface))

        if is_root:
            hsts = headers_lower.get("strict-transport-security", "")
            if hsts:
                age_match = re.search(r"max-age=(\d+)", hsts, re.I)
                if not age_match or int(age_match.group(1)) < 15768000:
                    findings.append(Finding(
                        severity="MEDIUM",
                        verdict="PROVEN",
                        category="HEADERS",
                        title="Weak HSTS max-age (< 180 days)",
                        surface=surface,
                        evidence=hsts,
                        proof_basis="Observed Strict-Transport-Security header has max-age below 15768000 seconds.",
                        unconfirmed_reason="",
                        missing_evidence="",
                        why_it_matters="Short HSTS durations allow downgrade windows after cache expiration.",
                        remediation="Set HSTS max-age to at least 31536000 with includeSubDomains.",
                        verification=f"Verify Strict-Transport-Security max-age >= 31536000 on {surface}.",
                    ))

            for leak_hdr in ("server", "x-powered-by", "x-aspnet-version"):
                val = headers_lower.get(leak_hdr)
                if val and re.search(r"\d+\.\d+", val):
                    findings.append(Finding(
                        severity="LOW",
                        verdict="PROVEN",
                        category="FINGERPRINT",
                        title=f"Software version disclosed in {leak_hdr}",
                        surface=surface,
                        evidence=f"{leak_hdr}: {val}",
                        proof_basis=f"Raw response header '{leak_hdr}' explicitly contains numeric version string '{val}'.",
                        unconfirmed_reason="",
                        missing_evidence="",
                        why_it_matters="Exact server/runtime versions accelerate targeted CVE matching by adversaries.",
                        remediation=f"Strip or generalize the {leak_hdr} response header at the reverse proxy.",
                        verification=f"Run HEAD {surface} and confirm {leak_hdr} omits version numbers.",
                    ))

        raw_cookies = (
            resp.raw.headers.getlist("Set-Cookie")
            if getattr(resp.raw, "headers", None) and hasattr(resp.raw.headers, "getlist")
            else []
        )
        if not raw_cookies and "set-cookie" in headers_lower:
            raw_cookies = [headers_lower["set-cookie"]]
        for cookie in raw_cookies:
            name = cookie.split("=", 1)[0].strip()
            cl = cookie.lower()
            missing = [f for f in ("httponly", "secure", "samesite") if f not in cl]
            if missing:
                findings.append(Finding(
                    severity="MEDIUM",
                    verdict="PROVEN",
                    category="COOKIES",
                    title=f"Cookie '{name}' missing defensive attributes",
                    surface=surface,
                    evidence=f"Missing: {', '.join(missing)}",
                    proof_basis=f"Observed Set-Cookie header for '{name}' lacks {', '.join(missing)}.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Missing HttpOnly/Secure/SameSite exposes cookies to JS theft, plaintext transit, or cross-site CSRF.",
                    remediation="Set HttpOnly, Secure, and SameSite=Lax (or Strict) on session cookies.",
                    verification=f"Inspect Set-Cookie for '{name}' on {surface} and confirm all three flags are present.",
                ))
            if "samesite=none" in cl and "secure" not in cl:
                findings.append(Finding(
                    severity="HIGH",
                    verdict="PROVEN",
                    category="COOKIES",
                    title=f"Cookie '{name}' sets SameSite=None without Secure",
                    surface=surface,
                    evidence=cookie[:120],
                    proof_basis="Observed Set-Cookie header pairs SameSite=None without Secure flag.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Cross-site cookies without Secure are rejected by modern browsers or leaked over plaintext HTTP.",
                    remediation="Always pair SameSite=None with the Secure attribute.",
                    verification=f"Confirm Set-Cookie '{name}' includes Secure when SameSite=None is used.",
                ))
            if name.startswith("__Host-") and ("secure" not in cl or "path=/" not in cl or "domain=" in cl):
                findings.append(Finding(
                    severity="MEDIUM",
                    verdict="PROVEN",
                    category="COOKIES",
                    title=f"Cookie '{name}' violates __Host- prefix invariants",
                    surface=surface,
                    evidence=cookie[:120],
                    proof_basis="Observed __Host- cookie violates RFC prefix invariants (Secure, Path=/, no Domain).",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Violating __Host- invariants breaks subdomain cookie-tossing protection.",
                    remediation="__Host- cookies require Secure, Path=/, and no Domain attribute.",
                    verification=f"Inspect Set-Cookie '{name}' and confirm Secure, Path=/, and absence of Domain.",
                ))
        return findings

    def _audit_cors_and_methods_verified(self) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        probe_a = "https://zero-audit-alpha.invalid"
        probe_b = "https://zero-audit-beta.invalid"
        cors_a = self.fetch(self.target_url, method="HEAD", headers={"Origin": probe_a})
        if cors_a.response:
            acao_a = cors_a.response.headers.get("Access-Control-Allow-Origin", "")
            acac_a = cors_a.response.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao_a == probe_a:
                cors_b = self.fetch(self.target_url, method="HEAD", headers={"Origin": probe_b})
                confirmed = bool(cors_b.response and cors_b.response.headers.get("Access-Control-Allow-Origin", "") == probe_b)
                findings.append(Finding(
                    severity="CRITICAL" if acac_a == "true" else "HIGH",
                    verdict="PROVEN" if confirmed else "UNCONFIRMED",
                    category="CORS",
                    title="Reflected arbitrary Origin in CORS policy",
                    surface=self.target_url,
                    evidence=f"Dual-origin check confirmed={confirmed} | ACAO={acao_a} ACAC={acac_a or 'absent'}",
                    proof_basis="Server dynamically echoed two distinct untrusted Origin headers verbatim in Access-Control-Allow-Origin." if confirmed else "",
                    unconfirmed_reason="" if confirmed else "First probe echoed Origin, but second distinct Origin did not repeat reflection.",
                    missing_evidence="" if confirmed else "Re-test with additional Origin values to rule out caching or transient CDN behavior.",
                    why_it_matters="Dynamic Origin reflection lets any malicious website read cross-origin responses; with credentials=true it enables full account data exfiltration.",
                    remediation="Validate Origin against an exact server-side allowlist; never echo arbitrary Origin headers.",
                    verification=f"Send HEAD {self.target_url} with Origin: {probe_a} and confirm ACAO is absent or locked to trusted origin.",
                ))
            elif acao_a == "*" and acac_a == "true":
                findings.append(Finding(
                    severity="HIGH",
                    verdict="PROVEN",
                    category="CORS",
                    title="Wildcard ACAO paired with Allow-Credentials",
                    surface=self.target_url,
                    evidence="ACAO=* with ACAC=true",
                    proof_basis="Raw response emitted Access-Control-Allow-Origin: * simultaneously with Access-Control-Allow-Credentials: true.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Indicates misconfigured CORS middleware attempting to expose credentialed endpoints globally.",
                    remediation="Use explicit trusted origins when Access-Control-Allow-Credentials is enabled.",
                    verification=f"Verify {self.target_url} never returns ACAO=* alongside ACAC=true.",
                ))

        allowed_methods: list[str] = []
        opt_res = self.fetch(self.target_url, method="OPTIONS")
        if opt_res.response:
            allow_hdr = opt_res.response.headers.get("Allow") or opt_res.response.headers.get("Access-Control-Allow-Methods") or ""
            allowed_methods = sorted({m.strip().upper() for m in allow_hdr.split(",") if m.strip()})
            risky_methods = [m for m in allowed_methods if m in ("TRACE", "TRACK", "DEBUG")]
            if risky_methods:
                findings.append(Finding(
                    severity="MEDIUM",
                    verdict="PROVEN",
                    category="HTTP_METHODS",
                    title=f"Diagnostic HTTP methods advertised: {', '.join(risky_methods)}",
                    surface=self.target_url,
                    evidence=f"Allow: {allow_hdr}",
                    proof_basis=f"OPTIONS response Allow header explicitly advertised {', '.join(risky_methods)}.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Diagnostic methods like TRACE can echo request headers including credentials in legacy proxy chains.",
                    remediation="Disable TRACE/TRACK/DEBUG methods at the web server or ingress layer.",
                    verification=f"Send OPTIONS {self.target_url} and confirm TRACE/TRACK/DEBUG are not advertised.",
                ))
        return findings, allowed_methods

    def _audit_html_passive(self, html: str, page_url: str, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        soup = BeautifulSoup(html, "html.parser")
        page_scheme = urlparse(page_url).scheme
        page_host = urlparse(page_url).netloc
        cache_ctrl = headers.get("Cache-Control", "").lower()

        has_password_input = False
        for form in soup.find_all("form"):
            method = str(form.get("method", "get")).lower()
            action = str(form.get("action", "")).strip()
            resolved_action = normalize_url(action, page_url) if action else page_url
            if page_scheme == "https" and resolved_action and resolved_action.startswith("http://"):
                findings.append(Finding(
                    severity="HIGH",
                    verdict="PROVEN",
                    category="FORMS",
                    title="HTTPS form submits over plaintext HTTP",
                    surface=page_url,
                    evidence=f"action={resolved_action}",
                    proof_basis=f"HTML <form action='{resolved_action}'> on HTTPS page targets plaintext http://.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Submitting form data from an HTTPS page to HTTP transmits user inputs and credentials in cleartext.",
                    remediation="Switch form action to an HTTPS endpoint.",
                    verification=f"Inspect <form action> in {page_url} and verify https:// or relative path is used.",
                ))
            inputs = form.find_all("input")
            if any(str(inp.get("type", "")).lower() == "password" for inp in inputs):
                has_password_input = True
                self.has_auth_forms = True
            if method == "post":
                input_names = [str(inp.get("name", "")).lower() for inp in inputs]
                has_csrf = any(any(hint in name for hint in CSRF_FIELD_HINTS) for name in input_names)
                if not has_csrf:
                    findings.append(Finding(
                        severity="MEDIUM",
                        verdict="UNCONFIRMED",
                        category="CSRF",
                        title="POST form lacks recognizable CSRF token field",
                        surface=page_url,
                        evidence=f"action={action or page_url}",
                        proof_basis="HTML form uses method=POST with no hidden input matching standard CSRF token names.",
                        unconfirmed_reason="Server may still enforce CSRF defense via SameSite=Strict cookies, Sec-Fetch-Site, or custom JS request headers.",
                        missing_evidence="Verify on staging whether a cross-origin POST without custom headers is accepted or rejected with 403.",
                        why_it_matters="Without anti-CSRF tokens or strict SameSite/Origin validation, third-party sites can forge state-changing requests.",
                        remediation="Include a synchronizer anti-CSRF token and validate Origin/Sec-Fetch-Site server-side.",
                        verification=f"Verify POST requests to {action or page_url} reject missing or invalid CSRF tokens with 403.",
                    ))

        if has_password_input and "no-store" not in cache_ctrl:
            findings.append(Finding(
                severity="LOW",
                verdict="PROVEN",
                category="CACHING",
                title="Authentication form page missing Cache-Control: no-store",
                surface=page_url,
                evidence=f"Cache-Control: {cache_ctrl or 'absent'}",
                proof_basis="Page contains <input type='password'> and response Cache-Control lacks 'no-store'.",
                unconfirmed_reason="",
                missing_evidence="",
                why_it_matters="Shared proxies or browser history caches may retain sensitive authentication screens.",
                remediation="Set Cache-Control: no-store on pages containing credential inputs.",
                verification=f"Confirm GET {page_url} returns Cache-Control: no-store.",
            ))

        for anchor in soup.find_all("a", target="_blank"):
            rel_vals = {str(r).lower() for r in (anchor.get("rel") or [])}
            if "noopener" not in rel_vals:
                findings.append(Finding(
                    severity="LOW",
                    verdict="PROVEN",
                    category="TABNABBING",
                    title="External target=_blank link missing rel='noopener'",
                    surface=page_url,
                    evidence=str(anchor.get("href", ""))[:120],
                    proof_basis="HTML anchor sets target='_blank' without 'noopener' in rel attribute.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Legacy browsing contexts without noopener allow newly opened tabs to manipulate window.opener.",
                    remediation="Add rel='noopener noreferrer' to links opening in new tabs.",
                    verification=f"Audit target='_blank' anchors on {page_url} for rel='noopener noreferrer'.",
                ))
                break

        for tag in soup.find_all(["script", "link"]):
            attr = "src" if tag.name == "script" else "href"
            if tag.name == "link" and "stylesheet" not in [str(r).lower() for r in (tag.get("rel") or [])]:
                continue
            raw_ref = tag.get(attr)
            if not raw_ref:
                continue
            full_ref = normalize_url(str(raw_ref), page_url)
            if not full_ref:
                continue
            ref_parsed = urlparse(full_ref)
            if page_scheme == "https" and ref_parsed.scheme == "http":
                findings.append(Finding(
                    severity="HIGH",
                    verdict="PROVEN",
                    category="MIXED_CONTENT",
                    title="Active mixed content loaded over HTTP",
                    surface=page_url,
                    evidence=full_ref,
                    proof_basis=f"HTTPS document references active asset over plaintext {full_ref}.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Loading scripts or styles over plaintext HTTP lets network attackers inject arbitrary code into an HTTPS origin.",
                    remediation="Serve all scripts and stylesheets strictly over HTTPS.",
                    verification=f"Verify all <script src> and <link href> assets on {page_url} use https://.",
                ))
            if ref_parsed.netloc != page_host and not tag.get("integrity"):
                findings.append(Finding(
                    severity="MEDIUM",
                    verdict="PROVEN",
                    category="SUPPLY_CHAIN",
                    title="Third-party asset missing Subresource Integrity (SRI)",
                    surface=page_url,
                    evidence=full_ref,
                    proof_basis=f"External tag referencing {full_ref} omits the 'integrity' attribute.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="If the external CDN is compromised, browsers will execute modified scripts without hash verification.",
                    remediation="Add integrity='sha384-...' and crossorigin='anonymous' to third-party scripts/styles.",
                    verification=f"Inspect {full_ref} tag on {page_url} and confirm integrity attribute matches SHA-384 hash.",
                ))

        for comment in COMMENT_RE.findall(html):
            if DEBUG_COMMENT_RE.search(comment):
                findings.append(Finding(
                    severity="LOW",
                    verdict="PROVEN",
                    category="INFO_LEAK",
                    title="Developer/debug note exposed in HTML comment",
                    surface=page_url,
                    evidence=comment.strip()[:100],
                    proof_basis="HTML response body contains verbatim developer/debug comment.",
                    unconfirmed_reason="",
                    missing_evidence="",
                    why_it_matters="Internal comments often reveal staging hosts, auth assumptions, or unfinished security controls.",
                    remediation="Strip HTML/template comments during production build or minification.",
                    verification=f"Search production HTML of {page_url} to confirm debug comments are absent.",
                ))
                break

        if STACKTRACE_RE.search(html):
            findings.append(Finding(
                severity="HIGH",
                verdict="PROVEN",
                category="ERROR_HANDLING",
                title="Verbose stack trace or framework error exposed",
                surface=page_url,
                evidence="Error stack signature matched in HTML body",
                proof_basis="Response body matched deterministic stack trace signature.",
                unconfirmed_reason="",
                missing_evidence="",
                why_it_matters="Stack traces leak internal file paths, SQL dialects, dependency versions, and logic flow.",
                remediation="Disable debug mode in production and return generic error pages with opaque correlation IDs.",
                verification=f"Re-fetch {page_url} after disabling debug mode and confirm no stack frames appear.",
            ))

        findings.extend(self._scan_secrets_and_sinks(html, page_url, is_js=False))
        return findings

    def _scan_secrets_and_sinks(self, content: str, surface: str, is_js: bool) -> list[Finding]:
        findings: list[Finding] = []
        seen_secrets: set[str] = set()
        for match in SECRET_CONTEXT_RE.finditer(content):
            token = match.group(1)
            if token in seen_secrets:
                continue
            entropy = shannon_entropy(token)
            if entropy >= self.config.entropy_threshold:
                seen_secrets.add(token)
                findings.append(Finding(
                    severity="CRITICAL",
                    verdict="UNCONFIRMED",
                    category="SECRET_EXPOSURE",
                    title="High-entropy credential-like string in client response",
                    surface=surface,
                    evidence=f"sample={token[:4]}***{token[-2:]} len={len(token)} entropy={entropy:.2f}",
                    proof_basis=f"High-entropy string ({entropy:.2f} bits/char) matched secret key assignment syntax.",
                    unconfirmed_reason="Zero Suite does not test credentials against third-party APIs; string could be a public publishable key or mock fixture.",
                    missing_evidence="Verify key scope/privileges in your secret manager and rotate immediately if privileged.",
                    why_it_matters="Hardcoded client secrets can be extracted by any user to abuse downstream APIs or impersonate services.",
                    remediation="Rotate the exposed credential immediately and proxy authenticated calls through a backend service.",
                    verification=f"Confirm rotated secret is removed from {surface} and old token returns 401/403.",
                ))

        if is_js:
            sink_match = DOM_SINK_RE.search(content)
            if sink_match:
                findings.append(Finding(
                    severity="LOW",
                    verdict="UNCONFIRMED",
                    category="DOM_SINK",
                    title=f"Unsafe DOM/eval sink pattern in JS bundle: {sink_match.group(0).strip()}",
                    surface=surface,
                    evidence=f"Matched {sink_match.group(0).strip()} in same-origin script",
                    proof_basis=f"Static regex matched sink '{sink_match.group(0).strip()}' in fetched JS bundle.",
                    unconfirmed_reason="Static pattern match cannot prove untrusted user input reaches this sink without sanitization.",
                    missing_evidence="Trace data-flow from URL/storage/postMessage sources to this sink in source code or browser DevTools.",
                    why_it_matters="Unescaped user input reaching innerHTML/eval sinks introduces DOM-based XSS vulnerabilities.",
                    remediation="Use textContent/safe templating, enforce Trusted Types, and sanitize HTML via DOMPurify.",
                    verification=f"Review {surface} around {sink_match.group(0).strip()} and verify inputs are strictly sanitized.",
                ))
        return findings

    def _audit_js_bundles(self, js_urls: set[str]) -> tuple[list[Finding], set[str], int]:
        if self.config.profile != "deep":
            return [], set(), 0
        findings: list[Finding] = []
        apis: set[str] = set()
        audited = 0
        same_host_js = sorted(u for u in js_urls if urlparse(u).netloc == self.host)[: self.config.max_js_files]
        for js_url in same_host_js:
            if self.shield.tarpit_triggered:
                break
            res = self.fetch(js_url)
            if not res.response or res.blocked_reason or res.response.status_code != 200:
                continue
            audited += 1
            for match in API_HINT_RE.findall(res.body_text):
                norm = normalize_url(match, js_url)
                if norm and not is_trap_url(norm, self.config):
                    apis.add(norm)
            findings.extend(self._scan_secrets_and_sinks(res.body_text, js_url, is_js=True))
            sm_match = SOURCEMAP_RE.search(res.body_text)
            if sm_match:
                sm_url = normalize_url(sm_match.group(1), js_url)
                if sm_url and urlparse(sm_url).netloc == self.host:
                    sm_res = self.fetch(sm_url, method="HEAD")
                    if sm_res.response and sm_res.response.status_code == 200:
                        findings.append(Finding(
                            severity="MEDIUM",
                            verdict="PROVEN",
                            category="SOURCE_MAP",
                            title="Accessible production JavaScript source map",
                            surface=sm_url,
                            evidence=f"HEAD {sm_url} returned 200 OK (referenced by {urlparse(js_url).path})",
                            proof_basis=f"Direct HEAD request to {sm_url} returned HTTP 200 OK.",
                            unconfirmed_reason="",
                            missing_evidence="",
                            why_it_matters="Public source maps expose unminified original source code, internal comments, and route structures.",
                            remediation="Upload .map files only to private error-tracking backends and block *.map at CDN/web server.",
                            verification=f"Confirm HEAD {sm_url} returns 404 or 403.",
                        ))
        return findings, apis, audited

    def _detect_technologies(self, html: str, headers: dict[str, str]) -> set[str]:
        haystack = html.lower() + " " + " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        found = {tech for tech, markers in TECH_SIGNATURES.items() if any(m in haystack for m in markers)}
        for k, v in headers.items():
            if k.lower() == "server":
                found.add(f"Server:{v}")
        return found

    def _extract_artifacts(self, html: str, page_url: str) -> tuple[set[str], set[str], set[str], set[str]]:
        links: set[str] = set()
        js_urls: set[str] = set()
        apis: set[str] = set()
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a", "link", "script", "iframe", "form"]):
            raw = tag.get("href") or tag.get("src") or tag.get("action")
            norm = normalize_url(str(raw), page_url) if raw else None
            if is_hidden_trap_element(tag):
                with self._lock:
                    self.shield.hidden_traps_skipped += 1
                if norm and urlparse(norm).netloc == self.host:
                    self._memorize("url_template", structural_template(norm), "TRAP", "hidden_css_or_aria_trap", 0.88)
                continue
            if not norm:
                continue
            tpl = structural_template(norm)
            if urlparse(norm).netloc == self.host and tpl in self.known["trap_templates"]:
                with self._lock:
                    self.shield.memory_traps_recalled += 1
                continue
            trap_reason = is_trap_url(norm, self.config)
            if trap_reason:
                with self._lock:
                    self.shield.url_traps_skipped += 1
                if urlparse(norm).netloc == self.host:
                    self._memorize("url_template", tpl, "TRAP", trap_reason, 0.85)
                continue
            if tag.name == "script" and tag.get("src"):
                js_urls.add(norm)
            else:
                links.add(norm)
        for match in API_HINT_RE.findall(html):
            norm = normalize_url(match, page_url)
            if norm and not is_trap_url(norm, self.config):
                apis.add(norm)
        emails = set(EMAIL_RE.findall(html))
        return links, js_urls, apis, emails

    def run(self, show_progress: bool = True) -> AuditReport:
        start = time.monotonic()
        prior_scans = self.memory.get_prior_scans(self.host, limit=5)
        sitemap_entries = self._load_robots_and_sitemaps()
        soft_404_hashes = self._calibrate_soft_404()
        well_known_found, well_known_findings, security_txt_present = self._audit_well_known(soft_404_hashes)

        tls_info = (
            inspect_tls(self.parsed_target.hostname, self.parsed_target.port or 443, self.config.timeout)
            if self.parsed_target.scheme == "https" and self.parsed_target.hostname
            else TlsInfo()
        )

        root_res = self.fetch(self.target_url)
        if not root_res.response:
            raise RuntimeError(f"Target unreachable or blocked ({root_res.blocked_reason}): {self.target_url}")

        findings: list[Finding] = []
        findings.extend(well_known_findings)
        findings.extend(self._audit_response_headers(root_res.response, self.target_url, is_root=True))
        cors_findings, allowed_methods = self._audit_cors_and_methods_verified()
        findings.extend(cors_findings)

        if tls_info.days_remaining is not None and tls_info.days_remaining < 30:
            findings.append(Finding(
                severity="HIGH" if tls_info.days_remaining < 7 else "MEDIUM",
                verdict="PROVEN",
                category="TLS",
                title=f"TLS certificate expires in {tls_info.days_remaining} days",
                surface=self.target_url,
                evidence=f"notAfter={tls_info.not_after}",
                proof_basis="Live TLS handshake certificate notAfter field parsed directly from peer cert.",
                unconfirmed_reason="",
                missing_evidence="",
                why_it_matters="Expired certificates break HTTPS trust and cause immediate service outages or browser warnings.",
                remediation="Renew certificate immediately and automate ACME renewal.",
                verification=f"Inspect certificate expiry via openssl s_client -connect {self.parsed_target.hostname}:443.",
            ))
        if tls_info.protocol in ("TLSv1", "TLSv1.1"):
            findings.append(Finding(
                severity="HIGH",
                verdict="PROVEN",
                category="TLS",
                title=f"Deprecated TLS protocol negotiated: {tls_info.protocol}",
                surface=self.target_url,
                evidence=f"protocol={tls_info.protocol} cipher={tls_info.cipher}",
                proof_basis=f"Direct TLS socket handshake negotiated deprecated {tls_info.protocol}.",
                unconfirmed_reason="",
                missing_evidence="",
                why_it_matters="TLS 1.0/1.1 suffer from legacy padding and cipher weaknesses deprecated across compliance standards.",
                remediation="Disable TLS 1.0/1.1 and enforce TLS 1.2+ with AEAD ciphers.",
                verification="Verify TLS 1.0/1.1 handshakes are rejected by the edge listener.",
            ))

        technologies = self._detect_technologies(root_res.body_text, dict(root_res.response.headers))
        expert_focus = self.expert_engine.define_initial_focus(sorted(technologies), findings, bool(sitemap_entries))

        visited: set[str] = set()
        discovered: set[str] = {self.target_url, *sitemap_entries}
        js_urls: set[str] = set()
        apis: set[str] = set()
        emails: set[str] = set()
        page_metrics: list[PageMetric] = []
        template_counts: Counter[str] = Counter()
        content_hash_counts: Counter[int] = Counter()
        audited_header_templates: set[str] = set()
        soft_404_filtered = 0
        template_capped = 0
        guided_steps_log: list[AutonomousRouteStep] = []
        waves_planned = 0
        queue: deque[str] = deque([self.target_url, *sitemap_entries])
        prefetched: dict[str, FetchResult] = {self.target_url: root_res}

        progress = Progress(
            SpinnerColumn(style="#CCFF00"),
            TextColumn(f"[lime]ZERO {self.config.profile.upper()}[/lime] {{task.description}}"),
            BarColumn(complete_style="#CCFF00", finished_style="#CCFF00", pulse_style="#242424"),
            TextColumn("[ink]{task.completed}/{task.total}[/ink]"),
            TimeElapsedColumn(),
            console=console,
            disable=not show_progress,
        )

        with progress, ThreadPoolExecutor(max_workers=self.config.workers) as pool:
            task_id = progress.add_task(self.host, total=self.config.max_pages)
            while queue and len(visited) < self.config.max_pages and not self.shield.tarpit_triggered:
                pending_candidates = [u for u in dict.fromkeys(queue) if u not in visited]
                queue.clear()
                if not pending_candidates:
                    break

                non_root = [u for u in pending_candidates if u != self.target_url]
                planned_order: list[str] = [self.target_url] if self.target_url in pending_candidates else []
                if non_root:
                    waves_planned += 1
                    wave_steps = self.advisor.plan_frontier(
                        candidate_urls=non_root,
                        memorized_traps=list(self.session_traps),
                        memorized_safes=list(self.session_safes),
                        expert_focus=expert_focus,
                    )
                    guided_steps_log.extend(wave_steps)
                    for step in wave_steps:
                        if step.decision == "HOLD_SEMANTIC_TRAP":
                            self.shield.semantic_traps_held += 1
                            self._memorize("url_template", structural_template(step.url), "TRAP", "embeddinggemma2_semantic_trap", 0.76)
                        else:
                            planned_order.append(step.url)

                batch: list[str] = []
                for idx, candidate in enumerate(planned_order):
                    if len(batch) >= self.config.workers or len(visited) + len(batch) >= self.config.max_pages:
                        for leftover in planned_order[idx:]:
                            if leftover not in visited:
                                queue.append(leftover)
                        break
                    if candidate in visited:
                        continue
                    tpl = structural_template(candidate)
                    if candidate != self.target_url and tpl in self.known["trap_templates"]:
                        self.shield.memory_traps_recalled += 1
                        continue
                    trap_reason = is_trap_url(candidate, self.config)
                    if trap_reason:
                        self.shield.url_traps_skipped += 1
                        self._memorize("url_template", tpl, "TRAP", trap_reason, 0.85)
                        continue
                    if self.config.respect_robots and self.robots_disallowed and not self.robots.can_fetch(self.config.user_agent, candidate):
                        continue
                    if template_counts[tpl] >= self.config.max_per_template:
                        template_capped += 1
                        continue
                    template_counts[tpl] += 1
                    visited.add(candidate)
                    batch.append(candidate)

                if not batch:
                    break

                futures = {
                    pool.submit(lambda u=url: prefetched.pop(u, None) or self.fetch(u)): url
                    for url in batch
                }
                for future in as_completed(futures):
                    url = futures[future]
                    res = future.result()
                    progress.advance(task_id, 1)
                    if not res.response or res.blocked_reason or res.response.status_code >= 400:
                        continue
                    ctype = res.response.headers.get("Content-Type", "").split(";")[0].strip().lower()
                    if not any(k in ctype for k in ("html", "javascript", "json")):
                        continue

                    page_hash = compute_simhash(self._visible_text(res.body_text, urlparse(url).path))
                    if url != self.target_url and soft_404_hashes:
                        if any(hamming_distance(page_hash, h) <= self.config.simhash_threshold for h in soft_404_hashes):
                            soft_404_filtered += 1
                            continue

                    if url != self.target_url and self.known["trap_simhashes"]:
                        if any(hamming_distance(page_hash, h) <= 6 for h, _ in self.known["trap_simhashes"]):
                            self.shield.memory_traps_recalled += 1
                            continue

                    if url != self.target_url:
                        matched_bucket = next(
                            (existing for existing in content_hash_counts if hamming_distance(page_hash, existing) <= 3),
                            None,
                        )
                        bucket_key = matched_bucket if matched_bucket is not None else page_hash
                        content_hash_counts[bucket_key] += 1
                        if content_hash_counts[bucket_key] > self.config.max_duplicate_content:
                            self.shield.duplicate_traps_capped += 1
                            self._memorize("simhash", f"{page_hash:016x}", "TRAP", "duplicate_content_trap", 0.84)
                            self._memorize("url_template", structural_template(res.final_url), "TRAP", "duplicate_content_trap", 0.80)
                            continue

                    self._memorize("url_template", structural_template(res.final_url), "SAFE", "verified_valid_page", 0.78)
                    page_metrics.append(PageMetric(
                        url=res.final_url,
                        status=res.response.status_code,
                        content_type=ctype or "unknown",
                        size_bytes=res.body_bytes,
                        latency_ms=res.latency_ms,
                        simhash_hex=f"{page_hash:016x}",
                    ))
                    hdrs = dict(res.response.headers)
                    technologies.update(self._detect_technologies(res.body_text, hdrs))

                    tpl = structural_template(res.final_url)
                    if self.config.profile == "deep" and url != self.target_url and tpl not in audited_header_templates:
                        audited_header_templates.add(tpl)
                        findings.extend(self._audit_response_headers(res.response, res.final_url, is_root=False))

                    findings.extend(self._audit_html_passive(res.body_text, res.final_url, hdrs))
                    page_links, page_js, page_apis, page_emails = self._extract_artifacts(res.body_text, res.final_url)
                    js_urls.update(page_js)
                    apis.update(page_apis)
                    emails.update(page_emails)

                    for link in page_links:
                        discovered.add(link)
                        if urlparse(link).netloc == self.host and link not in visited:
                            queue.append(link)

        js_findings, js_apis, js_audited = self._audit_js_bundles(js_urls)
        findings.extend(js_findings)
        apis.update(js_apis)

        if self.shield.tarpit_triggered:
            findings.append(Finding(
                severity="INFO",
                verdict="PROVEN",
                category="TARPIT_SHIELD",
                title="Crawl halted early due to sustained high-latency tarpit pattern",
                surface=self.target_url,
                evidence=f"Consecutive responses >= {self.config.tarpit_latency_ms}ms reached threshold {self.config.tarpit_threshold}",
                proof_basis="Measured consecutive response latencies exceeded configured tarpit threshold.",
                unconfirmed_reason="",
                missing_evidence="",
                why_it_matters="Sustained artificial latency indicates a WAF tarpit or severe backend saturation that degrades scan accuracy.",
                remediation="Verify whether rate-limiting, WAF tarpit, or backend latency spike affected this authorized scan.",
                verification="Re-run with --rps 1.5 --workers 2 and monitor p95 latency.",
            ))

        findings.extend(self.redirect_findings)
        deduped_findings = list({
            (f.severity, f.category, f.title, f.surface, f.evidence): f
            for f in findings
        }.values())
        deduped_findings.sort(
            key=lambda f: (VERDICT_ORDER.get(f.verdict, 0), SEVERITY_WEIGHTS.get(f.severity, 0)),
            reverse=True,
        )

        sorted_techs = sorted(technologies)
        intel_advisories, intel_status = self.intel.fetch_for_stack(sorted_techs)

        if show_progress:
            console.print()
            console.print(Rule("[lime]LIVE DELIBERATION · ZSES <-> EMBEDDINGGEMMA 2[/lime]", style="#242424"))

        autonomous = self.advisor.deliberate_with_expert(
            target=self.target_url,
            technologies=sorted_techs,
            findings=deduped_findings,
            guided_steps=guided_steps_log,
            trap_samples=sorted(self.session_traps),
            safe_samples=sorted(self.session_safes),
            intel_advisories=intel_advisories,
            intel_status=intel_status,
            waves_planned=waves_planned,
            remaining_queue_count=len(queue),
            tarpit_triggered=self.shield.tarpit_triggered,
            max_rounds=self.config.deliberation_rounds,
            pace_seconds=self.config.deliberation_pace if show_progress else 0.0,
            train_epochs=self.config.train_epochs,
            live_console=show_progress,
        )

        self.memory.save_adapter_state(
            dim=self.advisor.dim,
            weights=self.advisor.weights,
            trap_centroid=self.advisor.trap_centroid,
            safe_centroid=self.advisor.safe_centroid,
            cumulative_epochs=self.advisor.cumulative_epochs,
        )

        score, grade = compute_grade(deduped_findings)
        mem_stats = self.memory.stats(self.host)

        expert = self.expert_engine.evaluate(
            target=self.target_url,
            score=score,
            config=self.config,
            findings=deduped_findings,
            shield=self.shield,
            technologies=sorted_techs,
            api_references=sorted(apis),
            pages_crawled=len(visited),
            js_bundles_audited=js_audited,
            robots_disallowed=sorted(set(self.robots_disallowed)),
            has_auth_forms=self.has_auth_forms,
            prior_scans=prior_scans,
            memory_stats=mem_stats,
            autonomous=autonomous,
        )

        report = AuditReport(
            target=self.target_url,
            profile=self.config.profile,
            memory_path=str(self.memory.base_dir),
            scanned_at=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(time.monotonic() - start, 2),
            score=score,
            grade=grade,
            total_requests=self.request_count,
            pages_crawled=len(visited),
            js_bundles_audited=js_audited,
            sitemap_entries_loaded=len(sitemap_entries),
            soft_404_filtered=soft_404_filtered,
            template_capped=template_capped,
            shield=self.shield,
            tls=tls_info,
            technologies=sorted_techs,
            allowed_methods=allowed_methods,
            well_known_found=well_known_found,
            findings=deduped_findings,
            expert=expert,
            page_metrics=page_metrics,
            discovered_urls=sorted(discovered),
            api_references=sorted(apis),
            emails=sorted(emails),
            robots_disallowed=sorted(set(self.robots_disallowed)),
            sitemap_urls=sorted(set(self.sitemap_urls)),
            security_txt_present=security_txt_present,
        )
        self.memory.save_scan_snapshot(report)
        return report


def inspect_jwt(token: str) -> dict[str, Any]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT structure; expected header.payload.signature")

    def decode_part(segment: str) -> dict[str, Any]:
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode()).decode("utf-8"))

    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    issues: list[str] = []
    alg = str(header.get("alg", "")).lower()
    if alg in ("", "none"):
        issues.append("CRITICAL: alg=none or missing algorithm allows signature bypass.")
    elif alg.startswith("hs"):
        issues.append("INFO: Symmetric HMAC algorithm; ensure strong >=256-bit secret and strict alg allowlist.")
    now_ts = int(time.time())
    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is None:
        issues.append("HIGH: Missing exp claim; token never expires.")
    elif isinstance(exp, (int, float)):
        if exp < now_ts:
            issues.append("INFO: Token is already expired.")
        elif iat and isinstance(iat, (int, float)) and (exp - iat) > 86400:
            issues.append("MEDIUM: Token lifetime exceeds 24 hours; prefer short-lived access tokens.")
    if "aud" not in payload:
        issues.append("LOW: Missing aud (audience) claim.")
    return {"header": header, "payload": payload, "issues": issues}


def run_repeater(
    url: str,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    allow_private: bool = False,
    memory_dir: Path = DEFAULT_MEMORY_DIR,
) -> dict[str, Any]:
    allowed = {"GET", "HEAD", "OPTIONS"}
    verb = method.upper()
    if verb not in allowed:
        raise ValueError(f"Diagnostic repeater only permits {', '.join(sorted(allowed))}")
    auditor = ZeroSuiteAuditor(
        url,
        AuditConfig(max_requests=6, allow_private_ips=allow_private, memory_dir=memory_dir, embed_backend="fallback", enable_net_intel=False),
    )
    res = auditor.fetch(auditor.target_url, method=verb, headers=extra_headers)
    if not res.response:
        raise RuntimeError(f"Request blocked or failed ({res.blocked_reason}) for {url}")
    sim = compute_simhash(auditor._visible_text(res.body_text, urlparse(auditor.target_url).path))
    return {
        "url": res.final_url,
        "status": res.response.status_code,
        "latency_ms": res.latency_ms,
        "size_bytes": res.body_bytes,
        "redirects": res.redirect_chain,
        "blocked_reason": res.blocked_reason,
        "blocked_location": res.blocked_location,
        "simhash_hex": f"{sim:016x}",
        "headers": dict(res.response.headers),
        "body_preview": res.body_text[:1200],
    }


def run_comparer(url_a: str, url_b: str, allow_private: bool = False, memory_dir: Path = DEFAULT_MEMORY_DIR) -> dict[str, Any]:
    a = run_repeater(url_a, "GET", allow_private=allow_private, memory_dir=memory_dir)
    b = run_repeater(url_b, "GET", allow_private=allow_private, memory_dir=memory_dir)
    dist = hamming_distance(int(a["simhash_hex"], 16), int(b["simhash_hex"], 16))
    similarity_pct = round((1.0 - dist / 64.0) * 100.0, 1)
    keys = sorted(set(a["headers"]) | set(b["headers"]))
    header_diffs = [
        {"header": k, "a": a["headers"].get(k), "b": b["headers"].get(k)}
        for k in keys
        if a["headers"].get(k) != b["headers"].get(k)
    ]
    body_diff = list(difflib.unified_diff(
        a["body_preview"].splitlines(),
        b["body_preview"].splitlines(),
        fromfile=url_a,
        tofile=url_b,
        lineterm="",
        n=2,
    ))[:60]
    return {
        "url_a": a["url"],
        "url_b": b["url"],
        "status_delta": f"{a['status']} -> {b['status']}",
        "size_delta_bytes": b["size_bytes"] - a["size_bytes"],
        "latency_delta_ms": round(b["latency_ms"] - a["latency_ms"], 1),
        "simhash_hamming_distance": dist,
        "structural_similarity_pct": similarity_pct,
        "header_diffs": header_diffs,
        "body_diff": body_diff,
    }
