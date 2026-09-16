"""Markdown / HTML report exporter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_redteamer.evaluator import SEVERITIES

_REMEDIATION = {
    "mock_flag_leak": "Never return file contents verbatim; filter sensitive markers before responding.",
    "passwd_content_leak": "Constrain file reads to an allowlisted sandbox directory; reject path traversal patterns.",
    "path_traversal_escape": "Canonicalize and validate all paths against a sandbox root.",
    "crash_exception": "Catch exceptions at the tool boundary and return sanitized errors.",
    "shadow_instruction_echo": "Treat tool output as data, not instructions; strip prompt-like content.",
    "secret_keyword_leak": "Redact secret-looking patterns from tool responses.",
}


def export_markdown(findings: list[dict[str, Any]], out: Path) -> Path:
    lines = [
        "# MCP Red-Team Security Report",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1
    lines += [f"| {s} | {counts[s]} |" for s in SEVERITIES]
    lines += ["", "## Findings", ""]
    for f in findings:
        lines += [
            f"### [{f['severity']}] {f['rule']} — tool `{f['tool']}`",
            "",
            f"- Attack type: {f['attack_type']}",
            f"- Evidence: `{f['evidence']}`",
            f"- Payload: `{json.dumps(f['payload'])}`",
            f"- Remediation: {_REMEDIATION.get(f['rule'], 'Review and harden the affected tool handler.')}",
            "",
        ]
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def export_html(findings: list[dict[str, Any]], out: Path) -> Path:
    """Lazy HTML: wrap the markdown in <pre>. ponytail: full HTML templating when reports need styling."""
    md = export_markdown(findings, out.with_suffix(".md"))
    out.write_text(f"<html><body><pre>{md.read_text(encoding='utf-8')}</pre></body></html>", encoding="utf-8")
    return out
