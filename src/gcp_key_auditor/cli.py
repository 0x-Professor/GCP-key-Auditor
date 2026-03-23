from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from rich.console import Console
from rich.table import Table

from gcp_key_auditor import __version__
from gcp_key_auditor.config import AuditorConfig, load_config
from gcp_key_auditor.models import AuditReport, KeyAudit, now_utc_iso
from gcp_key_auditor.probes import RateLimiter, run_probes
from gcp_key_auditor.reporting import print_console_summary, write_json, write_markdown
from gcp_key_auditor.scanner import GOOGLE_API_KEY_PATTERN, scan_path_for_keys
from gcp_key_auditor.scoring import score_key


def _validate_key(key: str) -> bool:
    return bool(GOOGLE_API_KEY_PATTERN.fullmatch(key))


def _audit_single_key(
    key: str,
    source_paths: list[str] | None,
    timeout: float,
    probe_workers: int,
    rate_limit_per_sec: float | None,
    android_package: str | None,
    android_cert_sha1: str | None,
    ios_bundle_id: str | None,
    config: AuditorConfig,
    limiter: RateLimiter | None,
) -> KeyAudit:
    audit = KeyAudit(key=key, source_paths=source_paths or [])
    audit.probe_results = run_probes(
        key,
        timeout_seconds=timeout,
        probe_workers=probe_workers,
        rate_limit_per_sec=rate_limit_per_sec,
        service_weight_overrides=config.service_weights,
        limiter=limiter,
        android_package=android_package,
        android_cert_sha1=android_cert_sha1,
        ios_bundle_id=ios_bundle_id,
    )
    return score_key(audit, config)


def _render_table(console: Console, findings: list[KeyAudit]) -> None:
    table = Table(title="gcp-key-auditor results")
    table.add_column("Key", overflow="fold")
    table.add_column("Severity")
    table.add_column("Score", justify="right")
    table.add_column("Accepted Probes", justify="right")
    table.add_column("Summary", overflow="fold")

    for finding in findings:
        accepted = sum(1 for r in finding.probe_results if r.auth_signal == "accepted")
        key_preview = f"{finding.key[:6]}...{finding.key[-4:]}"
        table.add_row(key_preview, finding.severity.upper(), str(finding.score), str(accepted), finding.summary)

    console.print(table)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gcp-key-auditor",
        description="Analyze exposed Google API keys and estimate real-world impact.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan files and audit discovered keys")
    scan.add_argument("--path", default=".", help="Path to scan")
    scan.add_argument("--timeout", type=float, default=7.0, help="HTTP timeout per probe")
    scan.add_argument("--config", default="gcp-key-auditor.toml", help="Path to TOML config")
    scan.add_argument("--key-workers", type=int, default=1, help="Concurrent keys to audit")
    scan.add_argument("--probe-workers", type=int, default=1, help="Concurrent probes per key")
    scan.add_argument(
        "--rate-limit-per-sec",
        type=float,
        default=None,
        help="Global max requests per second across all probes",
    )
    scan.add_argument("--output-json", dest="output_json", help="Write JSON report")
    scan.add_argument("--output-md", dest="output_md", help="Write Markdown report")
    scan.add_argument("--android-package", help="Android package for restricted key probing")
    scan.add_argument("--android-cert-sha1", help="Android SHA1 certificate fingerprint")
    scan.add_argument("--ios-bundle-id", help="iOS bundle ID for restricted key probing")

    audit = subparsers.add_parser("audit", help="Audit one explicit key")
    audit.add_argument("--key", required=True, help="Google API key string")
    audit.add_argument("--timeout", type=float, default=7.0, help="HTTP timeout per probe")
    audit.add_argument("--config", default="gcp-key-auditor.toml", help="Path to TOML config")
    audit.add_argument("--probe-workers", type=int, default=1, help="Concurrent probes per key")
    audit.add_argument(
        "--rate-limit-per-sec",
        type=float,
        default=None,
        help="Global max requests per second",
    )
    audit.add_argument("--output-json", dest="output_json", help="Write JSON report")
    audit.add_argument("--output-md", dest="output_md", help="Write Markdown report")
    audit.add_argument("--android-package", help="Android package for restricted key probing")
    audit.add_argument("--android-cert-sha1", help="Android SHA1 certificate fingerprint")
    audit.add_argument("--ios-bundle-id", help="iOS bundle ID for restricted key probing")

    return parser


def _emit_report(
    report: AuditReport,
    output_json: str | None,
    output_md: str | None,
    console: Console,
) -> None:
    if output_json:
        write_json(report, Path(output_json))
        console.print(f"[green]Wrote JSON report:[/green] {output_json}")

    if output_md:
        write_markdown(report, Path(output_md))
        console.print(f"[green]Wrote Markdown report:[/green] {output_md}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    console = Console()
    config = load_config(Path(args.config) if getattr(args, "config", None) else None)

    findings: list[KeyAudit] = []
    target = ""
    limiter = RateLimiter(args.rate_limit_per_sec)

    if args.command == "scan":
        target_path = Path(args.path).resolve()
        target = str(target_path)

        if not target_path.exists():
            console.print(f"[red]Path not found:[/red] {target_path}")
            return 2

        found = scan_path_for_keys(target_path)

        key_items = list(found.items())
        worker_count = max(1, args.key_workers)
        if worker_count == 1:
            for key, source_paths in key_items:
                findings.append(
                    _audit_single_key(
                        key=key,
                        source_paths=source_paths,
                        timeout=args.timeout,
                        probe_workers=args.probe_workers,
                        rate_limit_per_sec=args.rate_limit_per_sec,
                        android_package=args.android_package,
                        android_cert_sha1=args.android_cert_sha1,
                        ios_bundle_id=args.ios_bundle_id,
                        config=config,
                        limiter=limiter,
                    )
                )
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = [
                    executor.submit(
                        _audit_single_key,
                        key,
                        source_paths,
                        args.timeout,
                        args.probe_workers,
                        args.rate_limit_per_sec,
                        args.android_package,
                        args.android_cert_sha1,
                        args.ios_bundle_id,
                        config,
                        limiter,
                    )
                    for key, source_paths in key_items
                ]
                for future in futures:
                    findings.append(future.result())

    elif args.command == "audit":
        target = "direct-key"
        key = args.key.strip()
        if not _validate_key(key):
            console.print("[red]The provided key does not match Google API key format.[/red]")
            return 2

        findings.append(
            _audit_single_key(
                key=key,
                source_paths=[],
                timeout=args.timeout,
                probe_workers=args.probe_workers,
                rate_limit_per_sec=args.rate_limit_per_sec,
                android_package=args.android_package,
                android_cert_sha1=args.android_cert_sha1,
                ios_bundle_id=args.ios_bundle_id,
                config=config,
                limiter=limiter,
            )
        )

    findings.sort(key=lambda x: x.score, reverse=True)
    report = AuditReport(
        target=target,
        created_at=now_utc_iso(),
        version=__version__,
        findings=findings,
        total_keys=len(findings),
    )

    _emit_report(report, getattr(args, "output_json", None), getattr(args, "output_md", None), console)

    if findings:
        _render_table(console, findings)
    else:
        console.print(print_console_summary(findings))

    max_sev = next((f.severity for f in findings), "info")
    if max_sev in {"critical", "high"}:
        return 1
    return 0
