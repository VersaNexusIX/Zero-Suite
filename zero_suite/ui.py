from __future__ import annotations

import html as html_lib
from pathlib import Path
from urllib.parse import urlparse

from rich import box
from rich.align import Align
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from zero_suite.core import (
    APP_VERSION,
    ZERO_LOGO_SVG,
    AuditReport,
    ExpertAssessment,
    Finding,
    PageMetric,
    console,
    structural_template,
)
from zero_suite.memory import ZeroMemoryStore


def render_zero_banner(memory_path: str | None = None, embed_backend: str | None = None) -> None:
    lines = [
        ("███████╗ ███████╗ ██████╗   ", " ▄▄███████▄▄ "),
        ("╚══███╔╝ ██╔════╝ ██╔══██╗ ", "▄██▀▀     ▀▀██▄"),
        ("  ███╔╝  █████╗   ██████╔╝ ", "███   ", " ☢ ", "   ███"),
        (" ███╔╝   ██╔══╝   ██╔══██╗ ", "▀██▄▄     ▄▄██▀"),
        ("███████╗ ███████╗ ██║  ██║ ", " ▀▀███████▀▀ "),
        ("╚══════╝ ╚══════╝ ╚═╝  ╚═╝ ", "             "),
    ]
    art = Text(justify="center")
    for idx, parts in enumerate(lines):
        if len(parts) == 2:
            art.append(parts[0], style="bold #F2F2EE")
            art.append(parts[1], style="bold #F2F2EE")
        else:
            art.append(parts[0], style="bold #F2F2EE")
            art.append(parts[1], style="bold #F2F2EE")
            art.append(parts[2], style="bold #CCFF00")
            art.append(parts[3], style="bold #F2F2EE")
        if idx < len(lines) - 1:
            art.append("\n")

    meta_lines = [f"ZERO SUITE v{APP_VERSION}  ·  VERSANEXUSIX EPISTEMIC ZSES + EG2"]
    if memory_path:
        meta_lines.append(f"MEMORY  {memory_path}")
    if embed_backend:
        meta_lines.append(f"PLANNER {embed_backend}  ·  TARGET EXEC: NONE")
    console.print(
        Panel(
            Align.center(Text.assemble(art, "\n\n", Text("\n".join(meta_lines), style="muted"))),
            border_style="#242424",
            box=box.SQUARE,
            padding=(1, 2),
        )
    )


def render_memory_panel(memory: ZeroMemoryStore, host: str | None = None) -> None:
    st = memory.stats(host)
    console.print()
    console.print(Rule("[lime]ZERO MEMORY VAULT (.zerorcmemo)[/lime]", style="#242424"))
    summary = (
        f"[lime]PATH[/lime]       {rich_escape(str(st['memory_dir']))}\n"
        f"[lime]RECORDS[/lime]    {st['traps_memorized']} TRAP  ·  {st['safe_memorized']} SAFE  ·  {st['scans_recorded']} SCANS  ·  {st['adapter_epochs']} EG2 EPOCHS"
    )
    console.print(Panel(summary, border_style="#242424", box=box.SQUARE, padding=(1, 2)))
    if st["entries"]:
        tbl = Table(box=box.SIMPLE_HEAD, header_style="lime", expand=True, padding=(0, 1))
        tbl.add_column("LABEL", width=7)
        tbl.add_column("HOST", ratio=2)
        tbl.add_column("SIGNATURE", ratio=3)
        tbl.add_column("META", ratio=2)
        for e in st["entries"][:18]:
            lbl_st = "crit" if e["label"] == "TRAP" else "ok"
            tbl.add_row(
                f"[{lbl_st}]{rich_escape(str(e['label']))}[/{lbl_st}]",
                rich_escape(str(e["host"])),
                rich_escape(str(e["signature"])),
                rich_escape(f"{e['reason']} (h={e['hits']}, c={e['confidence']:.2f})"),
            )
        console.print(tbl)


def render_poc_panel(expert: ExpertAssessment) -> None:
    console.print()
    console.print(Rule("[lime]SAFE VERIFICATION PoC PACK (PROVEN FINDINGS ONLY)[/lime]", style="#242424"))
    if not expert.verification_pocs:
        console.print(Panel("[muted]No PROVEN posture findings required a verification PoC.[/muted]", border_style="#242424", box=box.SQUARE))
        return
    for idx, poc in enumerate(expert.verification_pocs[:8], 1):
        body = (
            f"[lime]SURFACE[/lime]   {rich_escape(poc.surface)}\n"
            f"[lime]PROOF[/lime]     {rich_escape(poc.epistemic_note)}\n"
            f"[lime]REPRO[/lime]     [ink]{rich_escape(poc.safe_repro_command)}[/ink]\n"
            f"[lime]VULN SIG[/lime]  [muted]{rich_escape(poc.expected_vulnerable_signal)}[/muted]\n"
            f"[lime]FIX SIG[/lime]   [muted]{rich_escape(poc.expected_patched_signal)}[/muted]\n"
            f"[lime]HARDEN[/lime]    {rich_escape(poc.blue_team_fix_snippet)}"
        )
        console.print(
            Panel(
                body,
                title=f"[lime]PoC #{idx} · [{poc.severity}] {rich_escape(poc.finding_title)}[/lime]",
                border_style="#242424",
                box=box.SQUARE,
                padding=(0, 2),
            )
        )


def render_expert_panel(expert: ExpertAssessment) -> None:
    drift = expert.drift
    auto = expert.autonomous
    tr = auto.training
    drift_str = (
        f"{drift.trend} ({drift.score_delta:+d} pts vs {drift.prior_score} · +{drift.new_findings} new · -{drift.resolved_findings} fixed)"
        if drift.has_prior
        else "FIRST_BASELINE (saved to .zerorcmemo)"
    )

    console.print()
    console.print(Rule("[lime]01 · SITUATIONAL POSITION & EPISTEMIC LEDGER[/lime]", style="#242424"))
    pos_text = (
        f"[lime]ARCHETYPE[/lime]   {rich_escape(expert.archetype)}\n"
        f"[lime]MATURITY[/lime]    {rich_escape(expert.maturity_tier)}\n"
        f"[lime]EPISTEMIC[/lime]   [proven]{expert.proven_count} PROVEN[/proven]  ·  [unconf]{expert.unconfirmed_count} UNCONFIRMED[/unconf]  ·  [unk]{expert.unknown_count} UNKNOWN BOUNDARIES[/unk]\n"
        f"[lime]DRIFT[/lime]       {rich_escape(drift_str)}\n"
        f"[lime]EG2 MODEL[/lime]   {rich_escape(auto.model_backend)}  ·  consensus {auto.final_consensus_score:.2f}\n"
        f"[lime]TRAINING[/lime]    {tr.samples_used} samples · {tr.epochs_run} ep (total {tr.cumulative_epochs}) · loss {tr.loss_before:.4f} -> {tr.loss_after:.4f}\n"
        f"[lime]NET INTEL[/lime]   {rich_escape(auto.net_intel_status)} ({len(auto.intel_advisories)} lead(s))\n"
        f"[lime]MEMORY[/lime]      {rich_escape(expert.memory_summary)}"
    )
    console.print(Panel(pos_text, border_style="#CCFF00", box=box.SQUARE, padding=(1, 2)))

    if auto.intel_advisories:
        console.print()
        console.print(Rule("[lime]02 · PUBLIC THREAT INTEL LEADS (UNCONFIRMED UNTIL VERSION CHECK)[/lime]", style="#242424"))
        intel_tbl = Table(box=box.SIMPLE_HEAD, header_style="lime", expand=True, padding=(0, 1))
        intel_tbl.add_column("ID", width=18)
        intel_tbl.add_column("STACK", width=12)
        intel_tbl.add_column("WHY UNCONFIRMED & SUMMARY", ratio=3)
        for adv in auto.intel_advisories[:8]:
            intel_tbl.add_row(
                f"[unconf]{rich_escape(adv.identifier)}[/unconf]\n[dim]{rich_escape(adv.source)}[/dim]",
                rich_escape(adv.component),
                f"{rich_escape(adv.summary)}\n[muted]Unconfirmed: {rich_escape(adv.unconfirmed_reason)}[/muted]",
            )
        console.print(intel_tbl)

    if expert.risk_chains:
        console.print()
        console.print(Rule("[lime]03 · COMPOUND RISK CHAINS[/lime]", style="#242424"))
        for chain in expert.risk_chains:
            vst = "proven" if chain.verdict == "PROVEN" else "unconf"
            console.print(
                Panel(
                    f"[ink]{rich_escape(chain.explanation)}[/ink]\n[lime]FIX[/lime]  {rich_escape(chain.priority_fix)}",
                    title=f"[{vst}]{chain.verdict}[/{vst}] · [high]{rich_escape(chain.severity)}[/high] · {rich_escape(chain.name)}",
                    border_style="#242424",
                    box=box.SQUARE,
                    padding=(0, 2),
                )
            )

    console.print()
    console.print(Rule("[lime]04 · PRIORITIZED NEXT ACTIONS[/lime]", style="#242424"))
    act_tbl = Table(box=box.SIMPLE_HEAD, header_style="lime", expand=True, padding=(0, 1))
    act_tbl.add_column("PRIORITY", width=18)
    act_tbl.add_column("ACTION & COMMAND", ratio=3)
    for act in expert.next_actions:
        act_tbl.add_row(
            f"[lime]{rich_escape(act.priority)}[/lime]",
            f"[ink]{rich_escape(act.action)}[/ink]\n[muted]{rich_escape(act.rationale)}[/muted]\n[dim]$ {rich_escape(act.command_hint)}[/dim]",
        )
    console.print(act_tbl)

    console.print()
    console.print(Rule("[muted]05 · EXPLICIT UNKNOWN BOUNDARIES (WHAT ZERO SUITE CANNOT KNOW)[/muted]", style="#242424"))
    unk_lines = [
        f"[unk]• {rich_escape(u.domain)}[/unk]\n  [muted]{rich_escape(u.why_unknown)}[/muted]\n  [dim]Needed: {rich_escape(u.required_for_proof)}[/dim]"
        for u in expert.unknown_boundaries
    ]
    console.print(Panel("\n\n".join(unk_lines), border_style="#242424", box=box.SQUARE, padding=(1, 2)))


def render_report(report: AuditReport) -> None:
    grade_style = "ok" if report.score >= 80 else ("med" if report.score >= 60 else "crit")
    traps_total = (
        report.shield.hidden_traps_skipped
        + report.shield.url_traps_skipped
        + report.shield.duplicate_traps_capped
        + report.shield.memory_traps_recalled
        + report.shield.semantic_traps_held
    )
    tr = report.expert.autonomous.training

    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(
        Panel(
            f"[{grade_style}]{report.score}/100 ({rich_escape(report.grade)})[/{grade_style}]  [muted]{rich_escape(report.expert.drift.trend)}[/muted]\n"
            f"[proven]{report.expert.proven_count} PROVEN[/proven] · [unconf]{report.expert.unconfirmed_count} UNCONF[/unconf] · [unk]{report.expert.unknown_count} UNK[/unk]",
            title="[muted]POSTURE & EPISTEMIC[/muted]",
            border_style="#242424",
            box=box.SQUARE,
        ),
        Panel(
            f"[ink]{report.pages_crawled} pages · {report.js_bundles_audited} js · {report.total_requests} req[/ink]\n"
            f"[lime]{traps_total} traps bypassed[/lime] [muted]· {report.shield.redirects_blocked} redir blocked[/muted]",
            title="[muted]DEEP COVERAGE & SHIELD[/muted]",
            border_style="#242424",
            box=box.SQUARE,
        ),
    )
    grid.add_row(
        Panel(
            f"[lime]{tr.loss_before:.4f} -> {tr.loss_after:.4f}[/lime] [muted](gain {tr.margin_gain:+.4f})[/muted]\n"
            f"[muted]{tr.cumulative_epochs} cumulative epochs · {len(report.expert.autonomous.intel_advisories)} intel leads[/muted]",
            title="[muted]EG2 ONLINE TRAINING[/muted]",
            border_style="#242424",
            box=box.SQUARE,
        ),
        Panel(
            f"[lime]{len(report.expert.verification_pocs)} Safe PoCs[/lime] [muted](PROVEN only)[/muted]\n"
            f"[muted]Consensus {report.expert.autonomous.final_consensus_score:.2f} · Target Exec: NONE[/muted]",
            title="[muted]VERIFICATION PoC PACK[/muted]",
            border_style="#242424",
            box=box.SQUARE,
        ),
    )
    console.print(grid)

    render_expert_panel(report.expert)

    console.print()
    console.print(Rule("[lime]06 · VERIFIED FINDINGS LEDGER[/lime]", style="#242424"))
    tbl = Table(box=box.SIMPLE_HEAD, header_style="lime", expand=True, padding=(0, 1))
    tbl.add_column("VERDICT", width=13)
    tbl.add_column("FINDING & EVIDENCE", ratio=3)
    tbl.add_column("PROOF BASIS / WHY UNCONFIRMED", ratio=3)
    sev_styles = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info"}
    for f in report.findings[:30]:
        st = sev_styles.get(f.severity, "ink")
        vst = "proven" if f.verdict == "PROVEN" else "unconf"
        ep_col = (
            f"[proven]PROVEN:[/proven] {rich_escape(f.proof_basis)}\n[dim]Fix: {rich_escape(f.remediation)}[/dim]"
            if f.verdict == "PROVEN"
            else f"[unconf]WHY UNCONFIRMED:[/unconf] {rich_escape(f.unconfirmed_reason)}\n[dim]Missing: {rich_escape(f.missing_evidence)}[/dim]"
        )
        tbl.add_row(
            f"[{vst}]{rich_escape(f.verdict)}[/{vst}]\n[{st}]{rich_escape(f.severity)}[/{st}]\n[dim]{rich_escape(f.category)}[/dim]",
            f"[ink]{rich_escape(f.title)}[/ink]\n[muted]{rich_escape(f.surface)}[/muted]\n[dim]{rich_escape(f.evidence)}[/dim]",
            ep_col,
        )
    console.print(tbl)

    render_poc_panel(report.expert)

    console.print()
    tree = Tree(f"[lime]☢ {rich_escape(urlparse(report.target).netloc)}[/lime]")
    buckets: dict[str, list[PageMetric]] = {}
    for pm in report.page_metrics:
        tpl = structural_template(pm.url)
        buckets.setdefault(tpl, []).append(pm)
    for tpl, items in sorted(buckets.items())[:18]:
        branch = tree.add(f"[ink]{rich_escape(tpl)}[/ink] [muted]({len(items)} sampled)[/muted]")
        for pm in items[:3]:
            branch.add(f"[muted]{pm.status}[/muted] {rich_escape(urlparse(pm.url).path or '/')} [dim]({pm.size_bytes}B, {pm.latency_ms}ms)[/dim]")
    console.print(Panel(tree, title="[lime]07 · SURFACE MAP[/lime]", border_style="#242424", box=box.SQUARE, padding=(1, 2)))


def export_poc_dossier_md(report: AuditReport, output_path: Path) -> None:
    lines = [
        "# Zero Suite — Epistemic Proof & Safe Verification PoC Dossier",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Scanned At:** `{report.scanned_at}`",
        f"- **Score:** `{report.score}/100 ({report.grade})`",
        f"- **Epistemic Breakdown:** `{report.expert.proven_count} PROVEN` · `{report.expert.unconfirmed_count} UNCONFIRMED` · `{report.expert.unknown_count} UNKNOWN BOUNDARIES`",
        "",
        "## 1. PROVEN Findings — Non-Destructive Verification PoCs",
        "",
    ]
    if report.expert.verification_pocs:
        for idx, poc in enumerate(report.expert.verification_pocs, 1):
            lines.extend([
                f"### {idx}. [{poc.severity}] {poc.finding_title}",
                f"- **Surface:** `{poc.surface}`",
                f"- **Proof Basis:** {poc.epistemic_note}",
                "- **Safe Verification Command:**",
                "```bash",
                poc.safe_repro_command,
                "```",
                f"- **Observed Vulnerable Signal:** `{poc.expected_vulnerable_signal}`",
                f"- **Expected Patched Signal:** `{poc.expected_patched_signal}`",
                f"- **Blue Team Config Snippet:** `{poc.blue_team_fix_snippet}`",
                "",
            ])
    else:
        lines.append("No PROVEN high/medium posture findings required a verification PoC.\n")

    lines.extend([
        "## 2. UNCONFIRMED Leads — Why Not Confirmed Yet (No PoC Issued)",
        "",
    ])
    unconfirmed = [f for f in report.findings if f.verdict == "UNCONFIRMED"]
    if unconfirmed:
        for f in unconfirmed:
            lines.extend([
                f"- **[{f.severity}] {f.title}** (`{f.surface}`)",
                f"  - **Why Unconfirmed:** {f.unconfirmed_reason}",
                f"  - **Evidence Required to Confirm/Refute:** {f.missing_evidence}",
            ])
    else:
        lines.append("- None in this scan.\n")

    lines.extend([
        "",
        "## 3. Explicit UNKNOWN Boundaries (What Passive Scanning Cannot Know)",
        "",
    ])
    for u in report.expert.unknown_boundaries:
        lines.append(f"- **{u.domain}:** {u.why_unknown} *(Needed: {u.required_for_proof})*")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_html_report(report: AuditReport, output_path: Path) -> None:
    auto = report.expert.autonomous
    tr = auto.training
    delib_rows = "".join(
        f"<tr><td class='acid-mono'>R{t.round_num} · {html_lib.escape(t.speaker)}</td>"
        f"<td><strong>{html_lib.escape(t.topic)}</strong><div class='ev'>{html_lib.escape(t.statement)}</div></td>"
        f"<td class='acid-mono'>{t.consensus_score:.2f}</td></tr>"
        for t in auto.deliberation
    )
    poc_cards = "".join(
        f"<article class='poc-card pixel-frame pixel-reticle'>"
        f"<h3 class='font-pixel'>{html_lib.escape(p.finding_title)}</h3>"
        f"<div class='pill-row'><span class='badge-proven font-pixel'>PROVEN</span>"
        f"<span class='sev sev-{p.severity.lower()} font-mono'>{html_lib.escape(p.severity)}</span>"
        f"<span class='ev font-mono'>{html_lib.escape(p.surface)}</span></div>"
        f"<div class='ev font-mono'>{html_lib.escape(p.epistemic_note)}</div>"
        f"<pre class='code font-mono'>{html_lib.escape(p.safe_repro_command)}</pre>"
        f"<div class='fix'><strong>Vulnerable Signal:</strong> <span class='font-mono'>{html_lib.escape(p.expected_vulnerable_signal)}</span></div>"
        f"<div class='fix'><strong>Patched Signal:</strong> <span class='font-mono'>{html_lib.escape(p.expected_patched_signal)}</span></div>"
        f"<div class='fix'><strong>Blue Team Config:</strong> <code class='font-mono'>{html_lib.escape(p.blue_team_fix_snippet)}</code></div>"
        f"</article>"
        for p in report.expert.verification_pocs
    ) or "<div class='poc-card pixel-frame'><p>No PROVEN posture findings required a verification PoC.</p></div>"

    unknown_rows = "".join(
        f"<tr><td><strong>{html_lib.escape(u.domain)}</strong></td>"
        f"<td>{html_lib.escape(u.why_unknown)}</td>"
        f"<td class='ev font-mono'>{html_lib.escape(u.required_for_proof)}</td></tr>"
        for u in report.expert.unknown_boundaries
    )

    def format_epistemic(f: Finding) -> str:
        if f.verdict == "PROVEN":
            return "<strong>Proof:</strong> " + html_lib.escape(f.proof_basis)
        return (
            "<strong>Why Unconfirmed:</strong> "
            + html_lib.escape(f.unconfirmed_reason)
            + "<div class='verify'><strong>Missing Evidence:</strong> "
            + html_lib.escape(f.missing_evidence)
            + "</div>"
        )

    finding_rows = "".join(
        f"<tr><td><span class='badge-{'proven' if f.verdict == 'PROVEN' else 'unconf'} font-pixel'>{html_lib.escape(f.verdict)}</span>"
        f"<div class='sev sev-{f.severity.lower()} font-mono' style='margin-top:8px'>{html_lib.escape(f.severity)}</div>"
        f"<div class='conf font-mono'>{html_lib.escape(f.category)}</div></td>"
        f"<td><strong>{html_lib.escape(f.title)}</strong><div class='ev font-mono'>{html_lib.escape(f.surface)}</div>"
        f"<div class='ev font-mono'>{html_lib.escape(f.evidence)}</div></td>"
        f"<td>{format_epistemic(f)}</td>"
        f"<td>{html_lib.escape(f.remediation)}</td></tr>"
        for f in report.findings
    ) or "<tr><td colspan='4'>No findings detected.</td></tr>"

    doc = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0D0D0D">
<meta name="color-scheme" content="dark">
<title>Zero Suite v{APP_VERSION} Epistemic Audit | VersaNexusIX</title>
<style>
@import url("https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Silkscreen:wght@400;700&display=swap");
:root{{--bg:#0D0D0D;--surface:#111111;--panel:#141414;--paper:#F2F2EE;--steel:#8A8A85;--rule:#242424;--acid:#CCFF00;--critical:#FF3B30;--high:#FF9500;--med:#FFD60A;--ease:cubic-bezier(0.16,1,0.3,1)}}
*{{box-sizing:border-box}}
*:not(.status-dot){{border-radius:0 !important}}
*,*::before,*::after{{box-shadow:none !important;text-shadow:none !important}}
html,body{{margin:0;background:var(--bg);color:var(--paper);font-family:"Plus Jakarta Sans",Arial,sans-serif;font-size:15px;line-height:1.65;overflow-x:clip}}
::selection{{background:var(--acid);color:var(--bg)}}
:focus-visible{{outline:1px solid var(--acid);outline-offset:3px}}
.font-pixel{{font-family:"Silkscreen","IBM Plex Mono",monospace}}
.font-mono{{font-family:"IBM Plex Mono",ui-monospace,monospace;font-variant-numeric:tabular-nums}}
.status-dot{{width:6px;height:6px;border-radius:50% !important;background:var(--acid);display:inline-block;vertical-align:middle;margin-right:8px}}
.site-frame{{max-width:1400px;margin:0 auto;border-left:1px solid var(--rule);border-right:1px solid var(--rule);min-height:100vh}}
.section{{padding:32px 24px;border-bottom:1px solid var(--rule)}}
@media (min-width:1024px){{.section{{padding:40px}}}}
.brand{{display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap}}
.brand-right{{text-align:right;font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:var(--steel)}}
.status-pill{{display:inline-flex;align-items:center;padding:6px 12px;background:var(--surface);border:1px solid var(--rule);color:var(--paper);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;margin-top:8px}}
h1{{font-family:"Silkscreen","IBM Plex Mono",monospace;font-size:32px;line-height:1.12;letter-spacing:0.04em;margin:0 0 12px;color:var(--paper)}}
@media (min-width:768px){{h1{{font-size:44px}}}}
h2{{font-family:"Silkscreen","IBM Plex Mono",monospace;font-size:20px;line-height:1.15;letter-spacing:0.04em;margin:0 0 20px;color:var(--paper)}}
@media (min-width:1024px){{h2{{font-size:26px}}}}
h3{{font-family:"Silkscreen","IBM Plex Mono",monospace;font-size:15px;line-height:1.3;margin:0 0 10px;color:var(--paper)}}
.meta{{color:var(--steel);font-size:12px;letter-spacing:0.06em;text-transform:uppercase;margin-bottom:28px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}}
.card{{background:var(--surface);border:1px solid var(--rule);padding:24px;transition:border-color 180ms var(--ease),background 180ms var(--ease)}}
.card:hover{{border-color:var(--acid);background:var(--panel)}}
.label{{font-size:11px;letter-spacing:0.1em;color:var(--steel);text-transform:uppercase}}
.val{{font-size:28px;font-weight:700;margin-top:10px;letter-spacing:-0.01em}}.sub{{font-size:12px;color:var(--steel);margin-top:6px}}.acid{{color:var(--acid)}}
.expert-box{{background:var(--surface);border:1px solid var(--acid);padding:28px;max-width:100%}}
.expert-box p{{max-width:65ch;margin:0 0 12px}}
.poc-card{{background:var(--surface);border:1px solid var(--rule);padding:24px;margin-bottom:16px;transition:border-color 180ms var(--ease),background 180ms var(--ease)}}
.poc-card:hover{{border-color:var(--acid);background:var(--panel)}}
.pill-row{{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px}}
.badge-proven{{background:var(--acid);color:var(--bg);border:1px solid var(--acid);padding:3px 8px;font-size:10px;letter-spacing:0.08em}}
.badge-unconf{{background:var(--bg);color:var(--med);border:1px solid var(--med);padding:3px 8px;font-size:10px;letter-spacing:0.08em}}
pre.code{{background:var(--bg);border:1px solid var(--rule);padding:14px 16px;overflow-x:auto;font-size:12px;line-height:1.55;color:var(--acid);margin:12px 0}}
.fix,.verify{{margin-top:8px;font-size:13px;color:var(--paper)}}
table{{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--rule)}}
th,td{{text-align:left;padding:14px 16px;border-bottom:1px solid var(--rule);vertical-align:top}}
th{{font-family:"Silkscreen","IBM Plex Mono",monospace;font-size:11px;letter-spacing:0.08em;color:var(--acid);text-transform:uppercase;background:var(--panel)}}
tr:hover td{{background:var(--panel)}}
.ev,.conf{{font-size:12px;color:var(--steel);margin-top:5px;word-break:break-word}}
.acid-mono{{font-family:"IBM Plex Mono",ui-monospace,monospace;font-variant-numeric:tabular-nums;font-weight:500;color:var(--acid);white-space:nowrap}}
.sev{{font-weight:700;white-space:nowrap}}
.sev-critical{{color:var(--critical)}}.sev-high{{color:var(--high)}}.sev-medium{{color:var(--med)}}.sev-low,.sev-info{{color:var(--steel)}}
.pixel-frame{{clip-path:polygon(0 4px,4px 4px,4px 0,calc(100% - 4px) 0,calc(100% - 4px) 4px,100% 4px,100% calc(100% - 4px),calc(100% - 4px) calc(100% - 4px),calc(100% - 4px) 100%,4px 100%,4px calc(100% - 4px),0 calc(100% - 4px))}}
.pixel-reticle{{position:relative}}
.pixel-reticle::before,.pixel-reticle::after{{content:"";position:absolute;width:8px;height:8px;pointer-events:none;opacity:0;transition:opacity 180ms steps(3,end),transform 180ms steps(3,end)}}
.pixel-reticle::before{{top:6px;left:6px;border-top:2px solid var(--acid);border-left:2px solid var(--acid);transform:translate3d(4px,4px,0)}}
.pixel-reticle::after{{right:6px;bottom:6px;border-right:2px solid var(--acid);border-bottom:2px solid var(--acid);transform:translate3d(-4px,-4px,0)}}
.pixel-reticle:hover::before,.pixel-reticle:hover::after{{opacity:1;transform:translate3d(0,0,0)}}
.pixel-flame{{position:relative;overflow:hidden;isolation:isolate}}
.pixel-flame::before{{content:"";position:absolute;inset:auto 0 0 0;height:100%;pointer-events:none;opacity:0;z-index:-1;background-image:linear-gradient(0deg,rgba(204,255,0,0.34) 0%,rgba(164,255,0,0.14) 44%,transparent 82%),repeating-linear-gradient(90deg,rgba(204,255,0,0.55) 0 4px,transparent 4px 10px,rgba(242,242,238,0.35) 10px 14px,transparent 14px 20px);background-size:100% 100%,40px 10px;background-position:0 100%,0 100%;background-repeat:no-repeat,repeat-x;transition:opacity 160ms steps(3,end)}}
.pixel-flame:hover::before,.pixel-flame:focus-visible::before{{opacity:1;animation:pixel-flame-rise 420ms steps(4,end) infinite}}
@keyframes pixel-flame-rise{{0%{{background-position:0 100%,0 100%;transform:translate3d(0,2px,0)}}33%{{background-position:0 92%,10px 84%;transform:translate3d(0,0,0)}}66%{{background-position:0 96%,20px 72%;transform:translate3d(0,-1px,0)}}100%{{background-position:0 100%,40px 100%;transform:translate3d(0,2px,0)}}}}
@media (prefers-reduced-motion:reduce){{*,*::before,*::after{{animation-duration:0.01ms !important;animation-iteration-count:1 !important;transition-duration:0.01ms !important}}}}
</style></head><body>
<div class="site-frame">
<header class="section brand">
<div>{ZERO_LOGO_SVG}</div>
<div class="brand-right font-mono">
<div>ZERO SUITE v{APP_VERSION} // VERSANEXUSIX DESIGN</div>
<div>VAULT: {html_lib.escape(report.memory_path)}</div>
<div class="status-pill pixel-frame pixel-flame"><span class="status-dot"></span>CONSENSUS {auto.final_consensus_score:.2f} · TARGET EXEC NONE</div>
</div>
</header>
<section class="section">
<h1>Epistemic Audit &amp; Proof Report</h1>
<div class="meta font-mono">TARGET: {html_lib.escape(report.target)} · SCANNED: {html_lib.escape(report.scanned_at)} · DURATION: {report.duration_seconds}s</div>
<div class="grid">
<div class="card pixel-frame pixel-reticle"><div class="label font-mono">Posture Score</div><div class="val acid font-mono">{report.score}/100 ({report.grade})</div><div class="sub font-mono">{report.expert.proven_count} PROVEN · {report.expert.unconfirmed_count} UNCONFIRMED</div></div>
<div class="card pixel-frame pixel-reticle"><div class="label font-mono">Safe Verification PoCs</div><div class="val acid font-mono">{len(report.expert.verification_pocs)}</div><div class="sub font-mono">Issued strictly for PROVEN facts</div></div>
<div class="card pixel-frame pixel-reticle"><div class="label font-mono">EG2 Online Training</div><div class="val font-mono">{tr.loss_before:.3f} → {tr.loss_after:.3f}</div><div class="sub font-mono">{tr.cumulative_epochs} cumulative epochs</div></div>
<div class="card pixel-frame pixel-reticle"><div class="label font-mono">Unknown Boundaries</div><div class="val font-mono">{report.expert.unknown_count}</div><div class="sub font-mono">Explicit passive blind spots</div></div>
</div>
</section>
<section class="section">
<h2>Situational Position &amp; Epistemic Summary</h2>
<div class="expert-box pixel-frame">
<p><strong>{html_lib.escape(report.expert.archetype)}</strong> — <span class="acid font-pixel">{html_lib.escape(report.expert.maturity_tier)}</span></p>
<p>{html_lib.escape(report.expert.position_summary)}</p>
<p style="margin-bottom:0;color:var(--steel)" class="font-mono">{html_lib.escape(report.expert.memory_summary)}</p>
</div>
</section>
<section class="section">
<h2>Safe Verification PoC Pack</h2>
{poc_cards}
</section>
<section class="section">
<h2>Findings Ledger (Proven vs. Unconfirmed)</h2>
<table><thead><tr><th>Verdict &amp; Sev</th><th>Finding &amp; Evidence</th><th>Proof Basis / Why Unconfirmed</th><th>Remediation</th></tr></thead><tbody>{finding_rows}</tbody></table>
</section>
<section class="section">
<h2>Explicit Unknown Boundaries</h2>
<table><thead><tr><th>Domain</th><th>Why Unknown</th><th>Required to Confirm</th></tr></thead><tbody>{unknown_rows}</tbody></table>
</section>
<section class="section">
<h2>ZSES ↔ EmbeddingGemma 2 Deliberation</h2>
<table><thead><tr><th>Round &amp; Speaker</th><th>Analysis &amp; Reasoning</th><th>Consensus</th></tr></thead><tbody>{delib_rows}</tbody></table>
</section>
</div></body></html>"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(doc, encoding="utf-8")
