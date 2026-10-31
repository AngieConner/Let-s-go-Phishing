"""
phishing_detector - the engine of "Let's Go Phishing".

This file makes the folder a Python "package" and offers one main function,
analyze_email(), that runs the full pipeline:

    .eml file -> load & sort -> header checks -> link checks
              -> content checks -> score -> verdict (red / green)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .content_checks import check_content
from .email_loader import ParsedEmail, load_email, parse_email_bytes
from .header_checks import check_headers
from .link_checks import check_links
from .scoring import Finding, Verdict, score_findings


@dataclass
class AnalysisResult:
    email: ParsedEmail
    findings: list[Finding]
    verdict: Verdict

    @property
    def red_flags(self) -> list[Finding]:
        """Warning signs, biggest first."""
        return sorted((f for f in self.findings if not f.good_sign), key=lambda f: -f.points)

    @property
    def good_signs(self) -> list[Finding]:
        return [f for f in self.findings if f.good_sign]


def analyze_parsed(email: ParsedEmail) -> AnalysisResult:
    findings = check_headers(email) + check_links(email) + check_content(email)
    return AnalysisResult(email=email, findings=findings, verdict=score_findings(findings))


def analyze_email(path: str | Path) -> AnalysisResult:
    """Analyze one saved email file (.eml)."""
    return analyze_parsed(load_email(path))


def analyze_bytes(data: bytes, source: str = "(email)") -> AnalysisResult:
    """Analyze raw email data that is already in memory."""
    return analyze_parsed(parse_email_bytes(data, source))


__all__ = ["AnalysisResult", "Finding", "Verdict", "analyze_email", "analyze_bytes"]
