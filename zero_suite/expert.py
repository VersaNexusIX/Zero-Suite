from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlparse

from zero_suite.core import (
    AttackChain,
    AuditConfig,
    AutonomousAnalysis,
    DriftSummary,
    ExpertAssessment,
    Finding,
    NextAction,
    ShieldStats,
    UnknownBoundary,
    VerificationPoC,
)


def build_safe_verification_pocs(findings: list[Finding]) -> list[VerificationPoC]:
    pocs: list[VerificationPoC] = []
    seen_keys: set[tuple[str, str]] = set()
    for f in findings:
        if f.verdict != "PROVEN" or f.severity == "INFO":
            continue
        key = (f.category, f.title)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        parsed = urlparse(f.surface)
        host = parsed.hostname or parsed.netloc
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if f.category == "CORS":
            cmd = f'curl -sSI -H "Origin: https://zero-verify-origin.invalid" "{f.surface}" | grep -i "^access-control-"'
            vuln_sig = "Access-Control-Allow-Origin: https://zero-verify-origin.invalid (reflected untrusted origin)"
            fix_sig = "No Access-Control-Allow-Origin header emitted for untrusted Origin."
            snippet = "add_header Access-Control-Allow-Origin $trusted_origin always; add_header Vary Origin always;"
        elif f.category in ("HEADERS", "CSP"):
            hdr = f.title.split(":", 1)[-1].strip() if ":" in f.title else "content-security-policy"
            cmd = f'curl -sSI "{f.surface}" | grep -i "^{hdr}:" || echo "HEADER_ABSENT"'
            vuln_sig = f"HEADER_ABSENT or weak directive observed ({f.evidence[:70]})"
            fix_sig = f"Strict {hdr} header present on every response."
            snippet = f'add_header {hdr.title()} "<strict-policy>" always;'
        elif f.category == "COOKIES":
            cmd = f'curl -sSI "{f.surface}" | grep -i "^set-cookie:"'
            vuln_sig = f"Set-Cookie emitted with {f.evidence}"
            fix_sig = "Set-Cookie includes HttpOnly; Secure; SameSite=Lax (or Strict)."
            snippet = "Set-Cookie: session=<opaque>; Path=/; HttpOnly; Secure; SameSite=Lax"
        elif f.category == "SOURCE_MAP":
            cmd = f'curl -sSI "{f.surface}" | head -n 1'
            vuln_sig = "HTTP/1.1 200 OK (source map publicly downloadable)"
            fix_sig = "HTTP/1.1 404 Not Found or 403 Forbidden."
            snippet = "location ~* \\.map$ { deny all; return 404; }"
        elif f.category == "TLS":
            cmd = f"openssl s_client -connect {host}:{port} -servername {host} </dev/null 2>/dev/null | openssl x509 -noout -dates -issuer"
            vuln_sig = f"Certificate/protocol issue confirmed: {f.evidence}"
            fix_sig = "TLSv1.2+ negotiated with valid certificate >= 30 days remaining."
            snippet = "ssl_protocols TLSv1.2 TLSv1.3; ssl_prefer_server_ciphers off;"
        elif f.category == "HTTP_METHODS":
            cmd = f'curl -sSI -X OPTIONS "{f.surface}" | grep -i "^allow:"'
            vuln_sig = f"Diagnostic verb advertised ({f.evidence})"
            fix_sig = "Allow header restricted to GET, HEAD, OPTIONS (no TRACE/TRACK/DEBUG)."
            snippet = "if ($request_method ~* ^(TRACE|TRACK|DEBUG)$) { return 405; }"
        elif f.category in ("TRANSPORT", "REDIRECT_GUARD"):
            cmd = f'curl -sSI --max-redirs 0 "{f.surface}" | grep -iE "^HTTP/|^location:"'
            vuln_sig = f"Plaintext HTTP or unsafe downgrade redirect ({f.evidence})"
            fix_sig = "HTTP 301/308 redirecting strictly to https:// on the authorized host."
            snippet = "return 308 https://$host$request_uri;"
        else:
            cmd = f'python3 Zero-Suite.py --repeat "{f.surface}" --method GET --accept-policy'
            vuln_sig = f.evidence[:110]
            fix_sig = f.verification[:110]
            snippet = f.remediation[:110]

        pocs.append(VerificationPoC(
            finding_title=f.title,
            category=f.category,
            severity=f.severity,
            verdict=f.verdict,
            surface=f.surface,
            safe_repro_command=cmd,
            expected_vulnerable_signal=vuln_sig,
            expected_patched_signal=fix_sig,
            blue_team_fix_snippet=snippet,
            epistemic_note=f"PROVEN via: {f.proof_basis}",
        ))
        if len(pocs) >= 10:
            break
    return pocs


class ZeroExpertSystem:
    def define_initial_focus(self, technologies: list[str], findings: list[Finding], has_sitemap: bool) -> str:
        focus_tokens = ["auth login portal api graphql admin config"]
        tech_lower = " ".join(technologies).lower()
        if any(t in tech_lower for t in ("next.js", "react", "vue.js")):
            focus_tokens.append("spa javascript bundle api endpoints")
        if any(f.category in ("CORS", "COOKIES", "CSP") for f in findings):
            focus_tokens.append("authenticated session cookies csrf forms")
        if has_sitemap:
            focus_tokens.append("sitemap routes deep coverage")
        return " ".join(focus_tokens)

    def evaluate(
        self,
        target: str,
        score: int,
        config: AuditConfig,
        findings: list[Finding],
        shield: ShieldStats,
        technologies: list[str],
        api_references: list[str],
        pages_crawled: int,
        js_bundles_audited: int,
        robots_disallowed: list[str],
        has_auth_forms: bool,
        prior_scans: list[dict[str, Any]],
        memory_stats: dict[str, Any],
        autonomous: AutonomousAnalysis,
    ) -> ExpertAssessment:
        cats = {f.category for f in findings}
        titles_lower = " ".join(f.title.lower() for f in findings)
        tech_lower = " ".join(technologies).lower()
        sev_counts = Counter(f.severity for f in findings)
        proven_count = sum(1 for f in findings if f.verdict == "PROVEN")
        unconfirmed_count = sum(1 for f in findings if f.verdict == "UNCONFIRMED")
        current_fps = {
            f"{f.severity}|{f.category}|{f.title}|{urlparse(f.surface).path or '/'}"
            for f in findings
        }

        drift = DriftSummary(prior_scans=len(prior_scans))
        if prior_scans:
            latest = prior_scans[0]
            prior_fps = set(latest["findings"])
            drift.has_prior = True
            drift.prior_score = latest["score"]
            drift.score_delta = score - latest["score"]
            drift.new_findings = len(current_fps - prior_fps)
            drift.resolved_findings = len(prior_fps - current_fps)
            chronic_pool = set.intersection(*(set(s["findings"]) for s in prior_scans[:3])) if len(prior_scans) >= 2 else prior_fps
            drift.chronic_findings = len(current_fps & chronic_pool)
            if drift.score_delta > 0 or (drift.resolved_findings > drift.new_findings):
                drift.trend = "IMPROVED"
            elif drift.score_delta < 0 or drift.new_findings > 0:
                drift.trend = "REGRESSED"
            else:
                drift.trend = "STABLE"

        edge_tag = "Edge/CDN-Fronted" if "cloudflare" in tech_lower else "Direct-Origin"
        if has_auth_forms and api_references:
            archetype = f"{edge_tag} Auth + API Web Application"
        elif has_auth_forms:
            archetype = f"{edge_tag} Authenticated Web Application"
        elif any(fw in tech_lower for fw in ("next.js", "react", "vue.js")) or js_bundles_audited >= 3:
            archetype = f"{edge_tag} Modern JS / SPA Frontend"
        elif api_references:
            archetype = f"{edge_tag} API-Backed Service"
        else:
            archetype = f"{edge_tag} Content / Document Surface"

        if sev_counts["CRITICAL"] > 0 or score < 50:
            maturity_tier = "TIER 4 — CRITICAL EXPOSURE"
        elif sev_counts["HIGH"] >= 2 or score < 70:
            maturity_tier = "TIER 3 — EXPOSED PERIMETER"
        elif sev_counts["HIGH"] == 1 or score < 85:
            maturity_tier = "TIER 2 — MODERATE HARDENING"
        else:
            maturity_tier = "TIER 1 — HARDENED POSTURE"

        if shield.tarpit_triggered:
            scan_integrity = "HALTED_BY_TARPIT"
        elif shield.rate_limited_events >= 3:
            scan_integrity = "PARTIAL_RATE_LIMITED"
        elif pages_crawled >= config.max_pages:
            scan_integrity = "BUDGET_CAPPED"
        else:
            scan_integrity = "COMPLETE_DEEP_COVERAGE"

        trap_signals = (
            shield.hidden_traps_skipped * 18
            + shield.url_traps_skipped * 15
            + shield.duplicate_traps_capped * 12
            + shield.memory_traps_recalled * 10
            + shield.semantic_traps_held * 14
            + shield.redirects_blocked * 12
            + (35 if shield.tarpit_triggered else 0)
        )
        trap_risk_index = min(100, trap_signals)
        if trap_risk_index >= 60 or shield.tarpit_triggered:
            deception_posture = "ACTIVE_DECEPTION_OR_HONEYPOT"
        elif trap_risk_index >= 25:
            deception_posture = "GUARDED_ANTI_CRAWLER"
        else:
            deception_posture = "CLEAN_SURFACE"

        unknown_boundaries: list[UnknownBoundary] = [
            UnknownBoundary(
                domain="Authenticated Authorization (IDOR / BOLA / RBAC)",
                why_unknown="Zero Suite runs unauthenticated passive checks and has no user session credentials or role matrix.",
                required_for_proof="Authenticated multi-role staging test comparing cross-account object access.",
            ),
            UnknownBoundary(
                domain="Server-Side Business Logic & Injection Sinks",
                why_unknown="Backend database queries, deserializers, and internal SSRF sinks are invisible to passive HTTP inspection.",
                required_for_proof="SAST/code review or authorized staging integration tests with backend telemetry.",
            ),
        ]
        if autonomous.intel_advisories:
            unknown_boundaries.append(UnknownBoundary(
                domain="Exact Patch Level of Matched Stack Advisories",
                why_unknown="Public headers/HTML reveal framework names, not exact dependency lockfile versions or backported patches.",
                required_for_proof="Inspect package-lock.json / composer.lock / requirements.txt or server package manager.",
            ))
        if robots_disallowed:
            unknown_boundaries.append(UnknownBoundary(
                domain=f"robots.txt Excluded Paths ({len(robots_disallowed)} rule(s))",
                why_unknown="Zero Suite intentionally respects robots.txt Disallow rules and did not request excluded routes.",
                required_for_proof="Authorized internal staging audit with explicit scope clearance.",
            ))
        if shield.redirects_blocked > 0:
            unknown_boundaries.append(UnknownBoundary(
                domain=f"Blocked Redirect Destinations ({shield.redirects_blocked})",
                why_unknown="Strict scope/SSRF/downgrade guards refused to follow out-of-scope or unsafe redirects.",
                required_for_proof="Review redirect allowlist rules on the server or audit the destination domain separately.",
            ))
        if shield.tarpit_triggered or pages_crawled >= config.max_pages:
            unknown_boundaries.append(UnknownBoundary(
                domain="Uncrawled Surface Beyond Cap / Tarpit Halt",
                why_unknown="Crawl stopped early due to tarpit circuit-breaker or max_pages budget.",
                required_for_proof="Re-run on staging allowlist with higher --max-pages and lower --rps.",
            ))

        hypotheses: list[str] = []
        if autonomous.intel_advisories:
            hypotheses.append(
                f"Live threat intel flagged {len(autonomous.intel_advisories)} UNCONFIRMED stack advisory lead(s) ({', '.join(a.identifier for a in autonomous.intel_advisories[:3])}); exact version check required."
            )
        if autonomous.training.samples_used > 0:
            hypotheses.append(
                f"EG2 online adapter trained on {autonomous.training.samples_used} labeled routes (loss {autonomous.training.loss_before:.4f} -> {autonomous.training.loss_after:.4f}, total {autonomous.training.cumulative_epochs} epochs)."
            )
        if unconfirmed_count > 0:
            hypotheses.append(
                f"{unconfirmed_count} finding(s) remain UNCONFIRMED because passive HTTP telemetry alone cannot prove exploitability without runtime/code context."
            )
        header_surfaces = {f.surface for f in findings if f.category == "HEADERS"}
        if len(header_surfaces) > 1:
            hypotheses.append(
                f"Security header gaps span {len(header_surfaces)} route templates, indicating per-route header handling rather than a global reverse-proxy policy."
            )
        if not hypotheses:
            hypotheses.append(
                "No hidden anomalies inferred on the unauthenticated surface; prioritize authenticated staging checks next."
            )

        risk_chains: list[AttackChain] = []
        weak_csp = "CSP" in cats or "missing security header: content-security-policy" in titles_lower
        if weak_csp and ("COOKIES" in cats or "DOM_SINK" in cats or "SUPPLY_CHAIN" in cats):
            risk_chains.append(AttackChain(
                name="Client-Side Session Hijack Surface",
                severity="CRITICAL" if "COOKIES" in cats else "HIGH",
                verdict="PROVEN" if "COOKIES" in cats else "UNCONFIRMED",
                linked_categories=sorted(cats & {"CSP", "HEADERS", "COOKIES", "DOM_SINK", "SUPPLY_CHAIN"}),
                explanation=(
                    "Missing/permissive CSP paired with unverified third-party scripts, DOM sinks, or cookies missing HttpOnly "
                    "amplifies any script injection directly into session compromise."
                ),
                priority_fix="Deploy nonce-based CSP, enforce HttpOnly/Secure/SameSite on cookies, and pin SRI hashes.",
            ))

        if "CORS" in cats and (api_references or "COOKIES" in cats):
            risk_chains.append(AttackChain(
                name="Cross-Origin Authenticated Data Exfiltration",
                severity="CRITICAL",
                verdict="PROVEN",
                linked_categories=["CORS", "API_SURFACE"],
                explanation="Dual-origin verified arbitrary Origin reflection paired with credentials/API routes enables cross-origin response reads.",
                priority_fix="Replace Origin reflection with an exact server-side allowlist and disable wildcard credentials.",
            ))

        if has_auth_forms and ("TRANSPORT" in cats or "FORMS" in cats or "CACHING" in cats or "strict-transport-security" in titles_lower):
            risk_chains.append(AttackChain(
                name="Credential Interception & Cache Exposure",
                severity="HIGH",
                verdict="PROVEN",
                linked_categories=sorted(cats & {"TRANSPORT", "FORMS", "HEADERS", "CACHING", "REDIRECT_GUARD"}),
                explanation="Password forms exist on routes missing strict HTTPS, HSTS, or Cache-Control: no-store.",
                priority_fix="Enforce HTTPS-only form actions, HSTS preload (>= 1 year), and Cache-Control: no-store.",
            ))

        if "CSRF" in cats and "COOKIES" in cats:
            risk_chains.append(AttackChain(
                name="Cross-Site State-Changing Request Forgery",
                severity="HIGH",
                verdict="UNCONFIRMED",
                linked_categories=["CSRF", "COOKIES"],
                explanation="POST form lacks a visible CSRF input and cookie lacks SameSite, but server-side Origin/header checks were not tested actively.",
                priority_fix="Enforce SameSite=Lax/Strict cookies plus server-verified synchronizer CSRF tokens and Sec-Fetch-Site validation.",
            ))

        verification_pocs = build_safe_verification_pocs(findings)

        next_actions: list[NextAction] = []
        if verification_pocs:
            next_actions.append(NextAction(
                priority="P0 · VERIFY PROOF",
                action=f"Run {len(verification_pocs)} non-destructive Verification PoC(s) and attach dossier to remediation ticket",
                rationale="Every PROVEN finding includes a safe curl/openssl check to confirm current state and post-fix closure.",
                command_hint=verification_pocs[0].safe_repro_command,
            ))
        if autonomous.intel_advisories:
            ids = ", ".join(a.identifier for a in autonomous.intel_advisories[:3])
            next_actions.append(NextAction(
                priority="P0 · CHECK VERSION",
                action=f"Confirm exact dependency versions against UNCONFIRMED advisories ({ids})",
                rationale="Passive scanning matched framework names but cannot read internal lockfiles.",
                command_hint="Inspect package-lock.json / requirements.txt / server -v on staging host",
            ))
        if drift.has_prior and drift.new_findings > 0:
            next_actions.append(NextAction(
                priority="P0 · REGRESSION",
                action=f"Triage {drift.new_findings} newly introduced finding(s) since prior scan",
                rationale=f"Score shifted {drift.score_delta:+d} pts from {drift.prior_score} to {score}.",
                command_hint=f"python3 Zero-Suite.py {target} --profile deep --html-report regression_diff.html --accept-policy",
            ))
        if weak_csp or "COOKIES" in cats or "TRANSPORT" in cats:
            next_actions.append(NextAction(
                priority="P1 · HARDENING",
                action="Apply global reverse-proxy security headers (CSP, HSTS, XFO, nosniff) and cookie flags",
                rationale="Closes the highest-weight PROVEN posture gaps in a single edge deployment.",
                command_hint=f"python3 Zero-Suite.py {target} --profile deep --html-report post_fix.html --accept-policy",
            ))
        if unconfirmed_count > 0:
            next_actions.append(NextAction(
                priority="P2 · RESOLVE UNCONFIRMED",
                action=f"Perform targeted staging/code review on {unconfirmed_count} UNCONFIRMED lead(s)",
                rationale="Passive telemetry identified risk indicators that need runtime or source confirmation.",
                command_hint="Review Section 2 of zero_suite_verification_poc.md for exact missing evidence",
            ))

        position_summary = (
            f"Target classified as {archetype} ({maturity_tier}, score {score}/100, trend {drift.trend}). "
            f"Epistemic ledger: {proven_count} PROVEN with reproducible evidence, {unconfirmed_count} UNCONFIRMED with stated gaps, "
            f"and {len(unknown_boundaries)} explicit UNKNOWN boundaries."
        )
        memory_summary = (
            f"Vault {memory_stats['memory_dir']} holds {memory_stats['traps_memorized']} trap(s), "
            f"{memory_stats['safe_memorized']} safe template(s), {memory_stats['scans_recorded'] + 1} scan(s), "
            f"and {autonomous.training.cumulative_epochs} EG2 trained epoch(s)."
        )

        return ExpertAssessment(
            archetype=archetype,
            maturity_tier=maturity_tier,
            scan_integrity=scan_integrity,
            deception_posture=deception_posture,
            trap_risk_index=trap_risk_index,
            proven_count=proven_count,
            unconfirmed_count=unconfirmed_count,
            unknown_count=len(unknown_boundaries),
            position_summary=position_summary,
            memory_summary=memory_summary,
            drift=drift,
            autonomous=autonomous,
            verification_pocs=verification_pocs,
            unknown_boundaries=unknown_boundaries,
            hypotheses=hypotheses,
            risk_chains=risk_chains,
            next_actions=next_actions,
        )
