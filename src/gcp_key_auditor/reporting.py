from __future__ import annotations

import json
from pathlib import Path

from gcp_key_auditor.models import AuditReport, KeyAudit


def _mask_key(key: str) -> str:
    if len(key) < 10:
        return "***"
    return f"{key[:6]}...{key[-4:]}"


def _evidence_line(result) -> str:
    status = str(result.http_status) if result.http_status is not None else "n/a"
    svc = result.service_status or "n/a"
    return (
        f"- {result.service}: auth={result.auth_signal}, http={status}, "
        f"service_status={svc}, evidence={result.evidence}"
    )


def to_markdown(report: AuditReport) -> str:
    lines: list[str] = []
    lines.append("# gcp-key-auditor report")
    lines.append("")
    lines.append(f"- target: {report.target}")
    lines.append(f"- created_at: {report.created_at}")
    lines.append(f"- total_keys: {report.total_keys}")
    lines.append("")

    if not report.findings:
        lines.append("No API keys discovered.")
        return "\n".join(lines)

    for idx, finding in enumerate(report.findings, start=1):
        lines.append(f"## {idx}. {_mask_key(finding.key)}")
        lines.append("")
        lines.append(f"- severity: {finding.severity}")
        lines.append(f"- score: {finding.score}")
        lines.append(f"- summary: {finding.summary}")
        if finding.source_paths:
            lines.append("- sources:")
            for src in finding.source_paths:
                lines.append(f"  - {src}")
        lines.append("- probe evidence:")
        for result in finding.probe_results:
            lines.append(_evidence_line(result))
        lines.append("")

    return "\n".join(lines)


def write_json(report: AuditReport, output_path: Path) -> None:
    output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")


def write_markdown(report: AuditReport, output_path: Path) -> None:
    output_path.write_text(to_markdown(report), encoding="utf-8")


def print_console_summary(findings: list[KeyAudit]) -> str:
    if not findings:
        return "No Google API keys found."

    parts = []
    for finding in findings:
        parts.append(
            f"{_mask_key(finding.key)} => {finding.severity.upper()} ({finding.score})"
        )
    return "\n".join(parts)
