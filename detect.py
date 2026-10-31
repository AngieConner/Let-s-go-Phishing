"""
detect.py - run this file to analyze emails.

Examples:
    python detect.py samples/phishing_lookalike_paypal.eml
    python detect.py samples/                       # every .eml in a folder
    python detect.py samples/ --html reports/report.html
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from phishing_detector import analyze_email
from phishing_detector.report import print_report, print_summary, write_html_report


def find_email_files(paths: list[str]) -> list[Path]:
    """Accept a mix of files and folders; return every .eml file found."""
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(path.glob("*.eml")))
        elif path.is_file():
            files.append(path)
        else:
            print(f"Warning: '{raw}' was not found, skipping it.", file=sys.stderr)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Let's Go Phishing - analyze saved emails (.eml) for phishing red flags.")
    parser.add_argument("paths", nargs="+", help="one or more .eml files or folders containing them")
    parser.add_argument("--html", metavar="FILE", help="also save a color-coded HTML report to FILE")
    parser.add_argument("--no-color", action="store_true", help="print plain text without colors")
    args = parser.parse_args()

    files = find_email_files(args.paths)
    if not files:
        print("No .eml files found. Try: python detect.py samples/", file=sys.stderr)
        return 1

    # Only use color when printing to a real terminal (not into a file).
    use_color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ

    results = []
    for file in files:
        try:
            results.append(analyze_email(file))
        except OSError as error:
            print(f"Could not read {file}: {error}", file=sys.stderr)

    for result in results:
        print_report(result, use_color)
    if len(results) > 1:
        print_summary(results, use_color)
    if args.html and results:
        saved = write_html_report(results, args.html)
        print(f"HTML report saved to: {saved}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
