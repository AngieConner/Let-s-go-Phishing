"""
scoring.py - turns a list of red flags into a risk score and a verdict.

How it works (on purpose, it is simple enough to explain in an interview):

  1. Every check reports "findings". Each red flag carries points.
     Bigger, more reliable warning signs carry more points.
  2. We add up the points. The total is capped at 100.
  3. The score decides the verdict and its color:

        0 - 14   LIKELY SAFE                 (green)
       15 - 39   PROBABLY SAFE - stay alert  (green)
       40 - 69   LIKELY MALICIOUS            (red)
       70 - 100  HIGHLY LIKELY MALICIOUS     (red)

This "add up the warning signs" approach is called a heuristic or
rule-based scoring model. Real email security products combine rules like
these with machine learning and reputation data.
"""

from __future__ import annotations

from dataclasses import dataclass

# The line between green and red. Change this to make the tool stricter
# (lower number) or more relaxed (higher number).
MALICIOUS_THRESHOLD = 40
HIGH_CONFIDENCE_THRESHOLD = 70
MINOR_FLAGS_THRESHOLD = 15


@dataclass
class Finding:
    """One thing the detector noticed about an email."""
    category: str        # "Headers", "Links", "Content" or "Attachments"
    title: str           # short name of the issue
    detail: str          # plain-English explanation for the reader
    points: int = 0      # how much this adds to the risk score
    good_sign: bool = False  # True = a reassuring finding (adds 0 points)


@dataclass
class Verdict:
    score: int           # 0 to 100
    is_malicious: bool   # True -> show in RED, False -> show in GREEN
    label: str           # e.g. "LIKELY MALICIOUS"
    advice: str          # what the reader should do


def score_findings(findings: list[Finding]) -> Verdict:
    total = sum(f.points for f in findings if not f.good_sign)
    score = min(total, 100)

    if score >= HIGH_CONFIDENCE_THRESHOLD:
        return Verdict(score, True, "HIGHLY LIKELY MALICIOUS",
                       "Do not click links, open attachments, or reply. Report it as phishing and delete it.")
    if score >= MALICIOUS_THRESHOLD:
        return Verdict(score, True, "LIKELY MALICIOUS",
                       "Treat this email as phishing. Verify with the sender through a phone number or website you already trust.")
    if score >= MINOR_FLAGS_THRESHOLD:
        return Verdict(score, False, "PROBABLY SAFE - STAY ALERT",
                       "Only minor warning signs were found. Double-check anything that asks for money or logins.")
    return Verdict(score, False, "LIKELY SAFE",
                   "No significant warning signs were found. Still use common sense.")
