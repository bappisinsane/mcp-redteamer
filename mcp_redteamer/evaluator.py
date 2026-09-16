"""Heuristic response evaluator with severity scoring."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# (rule_name, severity, compiled regex, description)
RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "mock_flag_leak",
        "CRITICAL",
        re.compile(r"MOCK_FLAG\{[^}]*\}"),
        "Sensitive mock flag leaked in tool response",
    ),
    (
        "passwd_content_leak",
        "HIGH",
        re.compile(r"root:x:0:0|daemon:x:1:1|/bin/(ba)?sh", re.I),
        "Host /etc/passwd content leaked (path traversal succeeded)",
    ),
    (
        "path_traversal_escape",
        "HIGH",
        re.compile(r"(\.\./|\.\.\\|/etc/passwd|/root/|C:\\Windows)", re.I),
        "Path traversal or host path referenced in output",
    ),
    (
        "crash_exception",
        "MEDIUM",
        re.compile(r"Traceback|Segmentation fault|core dumped|panic", re.I),
        "Unexpected exception or crash in target",
    ),
    (
        "shadow_instruction_echo",
        "MEDIUM",
        re.compile(r"ignore (all )?(previous|above) instructions|system prompt", re.I),
        "Injected instruction echoed back (possible indirect prompt injection)",
    ),
    (
        "secret_keyword_leak",
        "LOW",
        re.compile(r"(api[_-]?key|password|token|secret)\s*[:=]", re.I),
        "Potential secret material in response",
    ),
]


@dataclass
class Finding:
    rule: str
    severity: str
    tool: str
    attack_type: str
    payload: dict[str, Any]
    evidence: str
    description: str


@dataclass
class EvalResult:
    breached: bool
    findings: list[Finding] = field(default_factory=list)


class Evaluator:
    """Match tool responses against heuristic breach rules."""

    def evaluate(
        self, tool: str, attack_type: str, payload: dict[str, Any], response: list[dict[str, Any]]
    ) -> EvalResult:
        text = "\n".join(str(c.get("text", "")) for c in response)
        findings = [
            Finding(rule, sev, tool, attack_type, payload, m.group(0), desc)
            for rule, sev, pat, desc in RULES
            if (m := pat.search(text))
        ]
        return EvalResult(breached=bool(findings), findings=findings)

    def score(self, results: list[EvalResult]) -> dict[str, int]:
        """Count findings per severity."""
        counts = {s: 0 for s in SEVERITIES}
        for r in results:
            for f in r.findings:
                counts[f.severity] += 1
        return counts
