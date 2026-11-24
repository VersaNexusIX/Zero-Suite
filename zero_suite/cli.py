from __future__ import annotations

import argparse
import base64
import json
from dataclasses import asdict
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

from rich import box
from rich.markup import escape as rich_escape
from rich.prompt import Prompt
from rich.table import Table

from zero_suite.auditor import ZeroSuiteAuditor, inspect_jwt, run_comparer, run_repeater
from zero_suite.core import (
    DEFAULT_EG2_HF_MODEL,
    DEFAULT_EG2_OLLAMA_MODEL,
    DEFAULT_MEMORY_DIR,
    DEFAULT_OLLAMA_URL,
    MRL_DIM,
    AuditConfig,
    AuditReport,
    console,
    ensure_policy_consent,
    structural_template,
)
from zero_suite.eg2 import EmbeddingGemma2Advisor
from zero_suite.memory import ZeroMemoryStore
from zero_suite.ui import (
    export_html_report,
    export_poc_dossier_md,
    render_expert_panel,
    render_memory_panel,
    render_poc_panel,
    render_report,
    render_zero_banner,
)


def interactive_workbench(config: AuditConfig) -> None:
    memory = ZeroMemoryStore(config.memory_dir)
    advisor = EmbeddingGemma2Advisor(
        backend=config.embed_backend,
        ollama_url=config.ollama_url,
        ollama_model=config.ollama_model,
        hf_model=config.hf_model,
        dim=config.embed_dim,
        adapter_state=memory.load_adapter_state(config.embed_dim),
    )
    render_zero_banner(str(memory.base_dir), advisor.backend_label)
    last_report: AuditReport | None = None
    while True:
        mem_st = memory.stats()
        status_hint = (
            f"Target: {urlparse(last_report.target).netloc} ({last_report.score}/100 · {last_report.expert.proven_count} PROVEN / {last_report.expert.unconfirmed_count} UNCONF)"
            if last_report
            else f"Vault ready · {mem_st['traps_memorized']} traps · {mem_st['safe_memorized']} safe · {mem_st['adapter_epochs']} EG2 epochs"
        )
        console.print(f"\n[muted]STATE  {rich_escape(status_hint)}[/muted]")
        menu = Table(box=box.SIMPLE_HEAD, header_style="lime", expand=True, padding=(0, 1))
        menu.add_column("KEY", style="lime", width=5)
        menu.add_column("MODULE", style="bold #F2F2EE", width=26)
        menu.add_column("CAPABILITY", style="muted")
        menu.add_row("01", "DEEP EPISTEMIC AUDIT", "ZSES + EG2 deliberation, online training, live intel & epistemic ledger")
        menu.add_row("02", "SAFE HTTP REPEATER", "Single diagnostic GET/HEAD/OPTIONS request with strict redirect & SSRF lock")
        menu.add_row("03", "RESPONSE COMPARER", "Structural diff of two authorized URLs (headers, latency, SimHash)")
        menu.add_row("04", "DECODER & JWT AUDIT", "Offline Base64/URL/Hex codec + passive JWT posture check")
        menu.add_row("05", "EXPERT & EPISTEMIC VIEW", "Inspect Proven/Unconfirmed/Unknown breakdown & deliberation state")
        menu.add_row("06", "MEMORY VAULT", "Inspect .zerorcmemo traps/safe routes, EG2 epochs, or teach AI manually")
        menu.add_row("07", "SAFE PoC DOSSIER", "View & export non-destructive Verification PoCs for PROVEN findings")
        menu.add_row("00", "EXIT", "Close Zero Suite (memory & trained EG2 weights remain saved)")
        console.print(menu)

        choice = Prompt.ask(
            "[lime]ZERO >[/lime]",
            choices=["1", "01", "2", "02", "3", "03", "4", "04", "5", "05", "6", "06", "7", "07", "0", "00"],
            default="01",
        )
        norm_choice = choice.lstrip("0") or "0"
        if norm_choice == "0":
            break
        if norm_choice == "1":
            raw_url = Prompt.ask("[lime]AUTHORIZED TARGET URL[/lime]").strip()
            target = raw_url if raw_url.startswith(("http://", "https://")) else f"https://{raw_url}"
            last_report = ZeroSuiteAuditor(target, config, memory=memory, advisor=advisor).run(show_progress=True)
            render_report(last_report)
            out_json = Path("zero_suite_report.json")
            out_html = Path("zero_suite_report.html")
            out_poc = Path("zero_suite_verification_poc.md")
            out_json.write_text(json.dumps(asdict(last_report), indent=2), encoding="utf-8")
            export_html_report(last_report, out_html)
            export_poc_dossier_md(last_report, out_poc)
            console.print(f"\n[ok]Saved -> {out_json} | {out_html} | {out_poc}[/ok]")
        elif norm_choice == "2":
            raw_url = Prompt.ask("[lime]URL[/lime]").strip()
            method = Prompt.ask("[lime]METHOD[/lime]", choices=["GET", "HEAD", "OPTIONS"], default="GET")
            res = run_repeater(
                raw_url if raw_url.startswith(("http://", "https://")) else f"https://{raw_url}",
                method,
                allow_private=config.allow_private_ips,
                memory_dir=memory.base_dir,
            )
            console.print_json(json.dumps(res, indent=2))
        elif norm_choice == "3":
            url_a = Prompt.ask("[lime]URL A[/lime]").strip()
            url_b = Prompt.ask("[lime]URL B[/lime]").strip()
            res = run_comparer(
                url_a if url_a.startswith(("http://", "https://")) else f"https://{url_a}",
                url_b if url_b.startswith(("http://", "https://")) else f"https://{url_b}",
                allow_private=config.allow_private_ips,
                memory_dir=memory.base_dir,
            )
            console.print_json(json.dumps(res, indent=2))
        elif norm_choice == "4":
            mode = Prompt.ask("[lime]CODEC[/lime]", choices=["b64e", "b64d", "urle", "urld", "hexe", "hexd", "jwt"], default="jwt")
            data = Prompt.ask("[lime]INPUT[/lime]").strip()
            if mode == "b64e":
                console.print(base64.b64encode(data.encode()).decode())
            elif mode == "b64d":
                console.print(base64.b64decode(data.encode()).decode("utf-8", errors="replace"))
            elif mode == "urle":
                console.print(quote(data, safe=""))
            elif mode == "urld":
                console.print(unquote(data))
            elif mode == "hexe":
                console.print(data.encode().hex())
            elif mode == "hexd":
                console.print(bytes.fromhex(data).decode("utf-8", errors="replace"))
            elif mode == "jwt":
                console.print_json(json.dumps(inspect_jwt(data), indent=2))
        elif norm_choice == "5":
            if last_report:
                render_expert_panel(last_report.expert)
            else:
                console.print("[med]Run Module 01 first to populate Epistemic Ledger.[/med]")
        elif norm_choice == "6":
            render_memory_panel(memory)
            mem_act = Prompt.ask("[lime]MEMORY ACTION[/lime]", choices=["back", "teach", "clear"], default="back")
            if mem_act == "teach":
                host_in = Prompt.ask("[lime]HOST (e.g. example.com)[/lime]").strip().lower()
                url_in = Prompt.ask("[lime]PATH OR URL TO CLASSIFY[/lime]").strip()
                lbl_in = Prompt.ask("[lime]LABEL[/lime]", choices=["TRAP", "SAFE"], default="TRAP")
                full_u = url_in if url_in.startswith(("http://", "https://")) else f"https://{host_in}/{url_in.lstrip('/')}"
                memory.record_observation(host_in, "url_template", structural_template(full_u), lbl_in, "operator_manual_label", 0.99, manual=True)
                console.print(f"[ok]Memorized {rich_escape(structural_template(full_u))} as {lbl_in} for {rich_escape(host_in)}[/ok]")
            elif mem_act == "clear":
                host_in = Prompt.ask("[lime]HOST TO CLEAR[/lime]").strip().lower()
                memory.clear_host(host_in)
                console.print(f"[ok]Cleared memory for {rich_escape(host_in)}[/ok]")
        elif norm_choice == "7":
            if last_report:
                render_poc_panel(last_report.expert)
                out_poc = Path("zero_suite_verification_poc.md")
                export_poc_dossier_md(last_report, out_poc)
                console.print(f"[ok]Exported Verification PoC Dossier -> {out_poc}[/ok]")
            else:
                console.print("[med]Run Module 01 first to generate Safe Verification PoCs.[/med]")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Zero Suite v1.0 — Epistemic ZSES + EmbeddingGemma 2 Defensive Workbench")
    parser.add_argument("target", nargs="?", help="Authorized target URL")
    parser.add_argument("--profile", default="deep", choices=["deep", "light"])
    parser.add_argument("--memory-dir", type=Path, default=DEFAULT_MEMORY_DIR)
    parser.add_argument("--memory-status", action="store_true")
    parser.add_argument("--embed-backend", default="auto", choices=["auto", "ollama", "st", "fallback"])
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--ollama-model", default=DEFAULT_EG2_OLLAMA_MODEL)
    parser.add_argument("--hf-model", default=DEFAULT_EG2_HF_MODEL)
    parser.add_argument("--embed-dim", type=int, default=MRL_DIM, choices=[128, 256, 512, 768])
    parser.add_argument("--no-net-intel", action="store_true")
    parser.add_argument("--deliberation-rounds", type=int, default=4)
    parser.add_argument("--deliberation-pace", type=float, default=0.30)
    parser.add_argument("--train-epochs", type=int, default=12)
    parser.add_argument("--compare", nargs=2, metavar=("URL_A", "URL_B"), help="Diff two authorized URLs")
    parser.add_argument("--repeat", metavar="URL", help="Send a single diagnostic GET/HEAD/OPTIONS request")
    parser.add_argument("--method", default="GET", choices=["GET", "HEAD", "OPTIONS"])
    parser.add_argument("--jwt", metavar="TOKEN", help="Inspect JWT structure and posture offline")
    parser.add_argument("--max-pages", type=int, default=150)
    parser.add_argument("--max-requests", type=int, default=800)
    parser.add_argument("--max-per-template", type=int, default=8)
    parser.add_argument("--max-js-files", type=int, default=30)
    parser.add_argument("--max-redirects", type=int, default=3)
    parser.add_argument("--allow-cross-host-redirects", action="store_true")
    parser.add_argument("--allow-private", action="store_true")
    parser.add_argument("--max-body-bytes", type=int, default=2_097_152)
    parser.add_argument("--max-path-depth", type=int, default=8)
    parser.add_argument("--tarpit-ms", type=float, default=4000.0)
    parser.add_argument("--rps", type=float, default=5.0)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--ignore-robots", action="store_true")
    parser.add_argument("--accept-policy", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("zero_suite_report.json"))
    parser.add_argument("--html-report", type=Path)
    parser.add_argument("--poc-dossier", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_policy_consent(auto_accept=args.accept_policy)

    if args.memory_status:
        mem = ZeroMemoryStore(args.memory_dir)
        adv = EmbeddingGemma2Advisor(
            backend=args.embed_backend,
            ollama_url=args.ollama_url,
            ollama_model=args.ollama_model,
            hf_model=args.hf_model,
            dim=args.embed_dim,
            adapter_state=mem.load_adapter_state(args.embed_dim),
        )
        render_zero_banner(str(mem.base_dir), adv.backend_label)
        render_memory_panel(mem)
        return
    if args.jwt:
        console.print_json(json.dumps(inspect_jwt(args.jwt), indent=2))
        return
    if args.repeat:
        url = args.repeat if args.repeat.startswith(("http://", "https://")) else f"https://{args.repeat}"
        console.print_json(json.dumps(run_repeater(url, args.method, allow_private=args.allow_private, memory_dir=args.memory_dir), indent=2))
        return
    if args.compare:
        a, b = args.compare
        url_a = a if a.startswith(("http://", "https://")) else f"https://{a}"
        url_b = b if b.startswith(("http://", "https://")) else f"https://{b}"
        console.print_json(json.dumps(run_comparer(url_a, url_b, allow_private=args.allow_private, memory_dir=args.memory_dir), indent=2))
        return

    config = AuditConfig(
        profile=args.profile,
        memory_dir=args.memory_dir,
        embed_backend=args.embed_backend,
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
        hf_model=args.hf_model,
        embed_dim=args.embed_dim,
        enable_net_intel=not args.no_net_intel,
        deliberation_rounds=args.deliberation_rounds,
        deliberation_pace=args.deliberation_pace,
        train_epochs=args.train_epochs,
        max_pages=40 if args.profile == "light" and args.max_pages == 150 else args.max_pages,
        max_requests=250 if args.profile == "light" and args.max_requests == 800 else args.max_requests,
        max_per_template=args.max_per_template,
        max_js_files=0 if args.profile == "light" else args.max_js_files,
        max_redirects=args.max_redirects,
        allow_cross_host_redirects=args.allow_cross_host_redirects,
        allow_private_ips=args.allow_private,
        max_body_bytes=args.max_body_bytes,
        max_path_depth=args.max_path_depth,
        tarpit_latency_ms=args.tarpit_ms,
        rps=args.rps,
        workers=args.workers,
        timeout=args.timeout,
        respect_robots=not args.ignore_robots,
    )

    if args.target:
        mem = ZeroMemoryStore(config.memory_dir)
        adv = EmbeddingGemma2Advisor(
            backend=config.embed_backend,
            ollama_url=config.ollama_url,
            ollama_model=config.ollama_model,
            hf_model=config.hf_model,
            dim=config.embed_dim,
            adapter_state=mem.load_adapter_state(config.embed_dim),
        )
        render_zero_banner(str(mem.base_dir), adv.backend_label)
        url = args.target if args.target.startswith(("http://", "https://")) else f"https://{args.target}"
        report = ZeroSuiteAuditor(url, config, memory=mem, advisor=adv).run(show_progress=True)
        render_report(report)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
        console.print(f"[ok]JSON report saved -> {args.output}[/ok]")
        if args.html_report:
            export_html_report(report, args.html_report)
            console.print(f"[ok]HTML report saved -> {args.html_report}[/ok]")
        if args.poc_dossier:
            export_poc_dossier_md(report, args.poc_dossier)
            console.print(f"[ok]PoC dossier saved -> {args.poc_dossier}[/ok]")
        return

    interactive_workbench(config)
