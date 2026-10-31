"""
content_checks.py - reads the words of the email and its attachment names.

Phishing works on emotions: fear, urgency, greed, and trust in authority.
These checks look for the phrases scammers use to trigger those emotions.

The phrases below are "regular expressions" (regex): a mini-language for
describing text patterns. A few symbols you'll see:
    \\b    = edge of a word (so "won" doesn't match inside "wonder")
    s?    = the letter s is optional (card / cards)
    (a|b) = either a or b
"""

from __future__ import annotations

import re

from .email_loader import ParsedEmail
from .scoring import Finding

# (title, explanation, points, list of patterns)
PHRASE_GROUPS = [
    ("Pressure to act fast",
     "Scammers create urgency so you act before you think.", 10,
     [r"urgent(ly)?", r"immediately", r"within \d+ (hours?|days?)", r"act now", r"right (now|away)",
      r"as soon as possible", r"asap", r"final (notice|warning)", r"expires? today", r"limited time",
      r"action required", r"respond (now|today)"]),
    ("Threats or alarming account problems",
     "Fear of losing access or getting in trouble makes people click without checking.", 15,
     [r"suspended", r"will be (closed|deleted|terminated|disabled|locked)", r"(account|access) (has been )?(locked|limited|restricted)",
      r"unusual (sign-?in )?activity", r"suspicious activity", r"unauthori[sz]ed", r"legal action",
      r"(arrest|warrant|lawsuit)", r"permanently (closed|deleted)"]),
    ("Asks for passwords, payment, or personal details",
     "Legitimate companies do not ask you to confirm passwords or card numbers by email.", 20,
     [r"verify your (account|identity|information|details)", r"confirm your (password|identity|account|details|payment)",
      r"update your (payment|billing|account) (information|details|method)", r"enter your (password|pin|credentials)",
      r"social security( number)?", r"\bssn\b", r"credit card (number|details)", r"bank (account )?details",
      r"(login|log in|sign in) (credentials|details)"]),
    ("Generic greeting",
     "Real companies you do business with usually use your name. Mass phishing uses generic greetings.", 10,
     [r"dear (customer|user|client|member|account holder|valued (customer|member))", r"hello (user|customer)",
      r"dear sir(/| or )madam"]),
    ("Money, prizes, or gift cards",
     "Unexpected winnings, refunds, or requests to buy gift cards are classic scams.", 15,
     [r"you('ve| have) won", r"winner", r"gift ?cards?", r"wire transfer", r"bitcoin", r"crypto(currency)?",
      r"claim your (prize|reward|refund)", r"lottery", r"inheritance", r"\bprize\b", r"refund (is )?pending"]),
    ("Requests secrecy or avoids verification",
     "Asking you to keep quiet or saying they can't take a call stops you from verifying the request.", 10,
     [r"confidential", r"keep this (between us|quiet|private)", r"(don't|do not) (tell|share|discuss)",
      r"can'?t take (calls|a call|phone calls)", r"in (a )?meetings? all day"]),
]

# Attachment types that can run code or hide malicious content.
EXECUTABLE_EXTENSIONS = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "jar",
                         "msi", "hta", "lnk", "com", "pif", "wsf", "cpl", "reg"}
DISK_IMAGE_EXTENSIONS = {"iso", "img", "vhd", "vhdx"}
MACRO_DOCUMENT_EXTENSIONS = {"docm", "xlsm", "pptm", "xlam", "dotm"}
WEB_PAGE_EXTENSIONS = {"html", "htm", "shtml", "svg"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "ace", "cab"}
HARMLESS_LOOKING = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}


def _check_phrases(email: ParsedEmail) -> list[Finding]:
    findings = []
    for title, explanation, points, patterns in PHRASE_GROUPS:
        matches = []
        for pattern in patterns:
            found = re.search(r"\b" + pattern + r"\b", email.text, re.IGNORECASE)
            if found and found.group(0).lower() not in (m.lower() for m in matches):
                matches.append(found.group(0))
        if matches:
            quoted = ", ".join(f'"{m}"' for m in matches[:5])
            findings.append(Finding("Content", title, f"{explanation} Found: {quoted}", points))
    return findings


def _check_attachments(email: ParsedEmail) -> list[Finding]:
    findings = []
    for name in email.attachments:
        pieces = name.lower().rsplit(".", 2)
        extension = pieces[-1] if len(pieces) > 1 else ""
        risky = (EXECUTABLE_EXTENSIONS | DISK_IMAGE_EXTENSIONS | MACRO_DOCUMENT_EXTENSIONS
                 | WEB_PAGE_EXTENSIONS | ARCHIVE_EXTENSIONS)

        if len(pieces) == 3 and pieces[1] in HARMLESS_LOOKING and extension in risky:
            findings.append(Finding("Attachments", f"Disguised file: {name}",
                f"The name pretends to be a .{pieces[1]} file but it is really a .{extension} file. "
                "Windows often hides the last ending, so people only see the harmless-looking part.", 35))
        elif extension in EXECUTABLE_EXTENSIONS or extension in DISK_IMAGE_EXTENSIONS:
            findings.append(Finding("Attachments", f"Program or disk-image attachment: {name}",
                "This type of file can run code on your computer as soon as it is opened.", 30))
        elif extension in MACRO_DOCUMENT_EXTENSIONS:
            findings.append(Finding("Attachments", f"Document with macros: {name}",
                "Macro-enabled Office files can contain hidden programs. Attackers use them to install malware.", 25))
        elif extension in WEB_PAGE_EXTENSIONS:
            findings.append(Finding("Attachments", f"Web-page attachment: {name}",
                "HTML/SVG attachments often open a fake login page stored on your own computer, "
                "which helps them slip past link scanners.", 25))
        elif extension in ARCHIVE_EXTENSIONS:
            findings.append(Finding("Attachments", f"Compressed archive: {name}",
                "Zip and similar files can hide dangerous files from email scanners.", 15))
    return findings


def check_content(email: ParsedEmail) -> list[Finding]:
    findings = _check_phrases(email) + _check_attachments(email)
    if email.has_form:
        findings.append(Finding("Content", "Fill-in form inside the email",
            "The email contains a form for typing information directly into it. Legitimate "
            "companies send you to their website instead.", 20))
    return findings
