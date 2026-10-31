"""
report.py - shows the results in color.

  * RED   = likely malicious
  * GREEN = likely safe

Two outputs:
  1. print_report()      -> colored text in the terminal
  2. write_html_report() -> a web page you can open in any browser or share
"""

from __future__ import annotations

import html
import os
import textwrap
from datetime import datetime
from pathlib import Path

from . import AnalysisResult

# ANSI color codes: invisible instructions that tell the terminal to change color.
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED_TEXT = "\033[31m"
GREEN_TEXT = "\033[32m"
RED_BANNER = "\033[1;97;41m"    # bold white text on a red background
GREEN_BANNER = "\033[1;30;42m"  # bold black text on a green background

if os.name == "nt":
    os.system("")  # small trick that switches on color support in older Windows terminals


def _paint(text: str, code: str, use_color: bool) -> str:
    return f"{code}{text}{RESET}" if use_color else text


def print_report(result: AnalysisResult, use_color: bool = True) -> None:
    email, verdict = result.email, result.verdict
    banner_color = RED_BANNER if verdict.is_malicious else GREEN_BANNER
    text_color = RED_TEXT if verdict.is_malicious else GREEN_TEXT
    indent = " " * 10

    print("=" * 72)
    print(f"File:    {email.source}")
    print(f"From:    {email.from_name} <{email.from_address}>" if email.from_name else f"From:    {email.from_address}")
    print(f"Subject: {email.subject}")
    print()
    print(_paint(f"  {verdict.label}  |  risk score {verdict.score}/100  ", banner_color, use_color))
    print(_paint(textwrap.fill(verdict.advice, 72), text_color, use_color))
    print()

    red_flags = result.red_flags
    print(_paint(f"Red flags found: {len(red_flags)}", BOLD, use_color))
    if not red_flags:
        print("  (none)")
    for finding in red_flags:
        print(_paint(f"  +{finding.points:<3} [{finding.category}] {finding.title}", RED_TEXT, use_color))
        wrapped = textwrap.fill(finding.detail, 72, initial_indent=indent,
                                subsequent_indent=indent, break_on_hyphens=False)
        print(_paint(wrapped, DIM, use_color))

    if result.good_signs:
        print()
        print(_paint(f"Good signs: {len(result.good_signs)}", BOLD, use_color))
        for finding in result.good_signs:
            print(_paint(f"  [OK] [{finding.category}] {finding.title}", GREEN_TEXT, use_color))
    print()


def print_summary(results: list[AnalysisResult], use_color: bool = True) -> None:
    """One line per email - handy when scanning a whole folder."""
    print("=" * 72)
    print(_paint("SUMMARY", BOLD, use_color))
    for result in results:
        color = RED_TEXT if result.verdict.is_malicious else GREEN_TEXT
        status = _paint(f"{result.verdict.label:<27}", color, use_color)
        print(f"  {status} {result.verdict.score:>3}/100  {Path(result.email.source).name}")
    print()


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
_CSS = """
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #f4f5f7;
       color: #1d1f23; margin: 0; padding: 24px 16px; }
main { max-width: 860px; margin: 0 auto; }
h1 { margin: 0 0 4px; font-size: 1.6rem; }
.sub { color: #5c6370; margin: 0 0 24px; }
.card { background: #fff; border-radius: 10px; margin-bottom: 24px; overflow: hidden;
        box-shadow: 0 1px 3px rgba(0,0,0,.12); border-left: 8px solid var(--c); }
.red   { --c: #c62828; --bg: #fdecea; }
.green { --c: #2e7d32; --bg: #e8f5e9; }
.banner { background: var(--c); color: #fff; padding: 14px 20px; display: flex;
          justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
.banner strong { font-size: 1.15rem; letter-spacing: .03em; }
.score { font-size: 1.1rem; font-weight: 700; }
.body { padding: 16px 20px; }
.meta { margin: 0 0 12px; word-break: break-word; }
.meta dt { font-weight: 600; float: left; width: 72px; }
.meta dd { margin: 0 0 4px 80px; }
.advice { background: var(--bg); border-radius: 6px; padding: 10px 12px; margin: 0 0 16px; }
.bar { height: 10px; background: #e3e5e8; border-radius: 5px; overflow: hidden; margin: 0 0 16px; }
.bar span { display: block; height: 100%; background: var(--c); }
h3 { font-size: 1rem; margin: 16px 0 8px; }
ul { list-style: none; padding: 0; margin: 0; }
li { padding: 8px 0; border-top: 1px solid #eceef1; word-break: break-word; }
.pts { display: inline-block; min-width: 42px; font-weight: 700; color: #c62828; }
.ok { color: #2e7d32; font-weight: 700; }
.cat { font-size: .78rem; background: #eceef1; border-radius: 4px; padding: 1px 6px; margin-right: 6px; }
.detail { color: #5c6370; font-size: .9rem; margin: 4px 0 0 48px; }
footer { color: #5c6370; font-size: .85rem; text-align: center; }
"""


def _card(result: AnalysisResult) -> str:
    e, v = result.email, result.verdict
    color = "red" if v.is_malicious else "green"
    esc = html.escape

    flags = "".join(
        f'<li><span class="pts">+{f.points}</span><span class="cat">{esc(f.category)}</span>'
        f'{esc(f.title)}<div class="detail">{esc(f.detail)}</div></li>'
        for f in result.red_flags
    ) or "<li>None found.</li>"
    goods = "".join(
        f'<li><span class="ok">&#10003;</span> <span class="cat">{esc(f.category)}</span>{esc(f.title)}</li>'
        for f in result.good_signs
    )
    sender = f"{e.from_name} <{e.from_address}>" if e.from_name else e.from_address
    return f"""
<section class="card {color}">
  <div class="banner"><strong>{esc(v.label)}</strong><span class="score">Risk score: {v.score}/100</span></div>
  <div class="body">
    <div class="bar"><span style="width:{v.score}%"></span></div>
    <dl class="meta">
      <dt>File</dt><dd>{esc(Path(e.source).name)}</dd>
      <dt>From</dt><dd>{esc(sender)}</dd>
      <dt>Subject</dt><dd>{esc(e.subject)}</dd>
    </dl>
    <p class="advice">{esc(v.advice)}</p>
    <h3>Red flags ({len(result.red_flags)})</h3>
    <ul>{flags}</ul>
    {f'<h3>Good signs ({len(result.good_signs)})</h3><ul>{goods}</ul>' if goods else ''}
  </div>
</section>"""


def write_html_report(results: list[AnalysisResult], output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cards = "".join(_card(r) for r in results)
    malicious = sum(r.verdict.is_malicious for r in results)
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing Analysis Report</title><style>{_CSS}</style></head>
<body><main>
<h1>Let's Go Phishing - Analysis Report</h1>
<p class="sub">{len(results)} email(s) analyzed &middot; {malicious} likely malicious &middot;
generated {datetime.now():%Y-%m-%d %H:%M}. Links are shown "defanged" (hxxp, [.]) so they cannot be clicked.</p>
{cards}
<footer>Rule-based analysis for education. Always verify suspicious messages through a trusted channel.</footer>
</main></body></html>"""
    output_path.write_text(page, encoding="utf-8")
    return output_path
