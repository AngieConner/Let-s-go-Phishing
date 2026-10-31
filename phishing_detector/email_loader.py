"""
email_loader.py - opens a saved email (.eml file) and sorts it into pieces.

A raw email is not friendly to read: it contains technical headers, the
message body in several formats (plain text AND HTML), and attachments
encoded as long strings of gibberish. This file untangles all of that into
one tidy "ParsedEmail" object that the checks can easily inspect.

IMPORTANT: nothing here opens links or runs attachments. We only READ text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path


@dataclass
class Link:
    """One link found in the email.

    url  = where the link really goes (what a click would open)
    text = the words a person sees on screen (empty for plain-text links)
    """
    url: str
    text: str = ""


@dataclass
class ParsedEmail:
    """Everything the checks need, already pulled out of the raw email."""
    source: str                      # file name, for the report
    subject: str = ""
    from_name: str = ""              # the friendly name, e.g. "PayPal Security"
    from_address: str = ""           # the real address, e.g. security@paypa1-support.com
    reply_to: str = ""               # where replies would go
    return_path: str = ""            # where bounced mail goes (set by the sending server)
    auth_results: list[str] = field(default_factory=list)  # SPF/DKIM/DMARC results
    text: str = ""                   # all human-readable words in the message
    links: list[Link] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)   # file names
    has_form: bool = False           # does the HTML contain a fill-in form?


class _HTMLScanner(HTMLParser):
    """Reads the HTML version of an email and collects:
    the visible words, every <a> link (and the words shown on it), and forms.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.visible_text: list[str] = []
        self.has_form = False
        self._current_href: str | None = None
        self._current_link_words: list[str] = []
        self._inside_hidden_tag = 0  # inside <script> or <style>: not visible

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "a":
            self._current_href = (attributes.get("href") or "").strip()
            self._current_link_words = []
        elif tag == "form":
            self.has_form = True
        elif tag in ("script", "style"):
            self._inside_hidden_tag += 1

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            shown = " ".join("".join(self._current_link_words).split())
            self.links.append(Link(url=self._current_href, text=shown))
            self._current_href = None
        elif tag in ("script", "style") and self._inside_hidden_tag:
            self._inside_hidden_tag -= 1

    def handle_data(self, data):
        if self._inside_hidden_tag:
            return
        self.visible_text.append(data)
        if self._current_href is not None:
            self._current_link_words.append(data)


# Finds web addresses written directly in plain text.
_PLAIN_TEXT_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]]+", re.IGNORECASE)


def _is_web_link(url: str) -> bool:
    """Keep real web links; skip mailto:, tel:, and in-page '#' jumps."""
    return url.lower().startswith(("http://", "https://", "www."))


def _read_part_text(part: EmailMessage) -> str:
    """Decode one section of the email into normal text."""
    try:
        return part.get_content()
    except Exception:  # odd/broken encodings: fall back to a forgiving decode
        raw = part.get_payload(decode=True) or b""
        return raw.decode("utf-8", errors="replace")


def parse_email_bytes(data: bytes, source: str = "(email)") -> ParsedEmail:
    """Turn the raw bytes of an email into a ParsedEmail."""
    msg = BytesParser(policy=policy.default).parsebytes(data)
    parsed = ParsedEmail(source=source)

    # --- Headers: the "envelope" information -------------------------------
    parsed.subject = str(msg.get("Subject", "") or "")
    parsed.from_name, parsed.from_address = parseaddr(str(msg.get("From", "") or ""))
    parsed.reply_to = parseaddr(str(msg.get("Reply-To", "") or ""))[1]
    parsed.return_path = parseaddr(str(msg.get("Return-Path", "") or ""))[1]

    for header in msg.get_all("Authentication-Results") or []:
        parsed.auth_results.append(str(header))
    for header in msg.get_all("Received-SPF") or []:
        # "Received-SPF: fail (...)" -> treat it like "spf=fail"
        first_word = str(header).strip().split(" ", 1)[0]
        parsed.auth_results.append(f"spf={first_word}")

    # --- Body and attachments ----------------------------------------------
    text_pieces: list[str] = [parsed.subject]
    found_links: dict[tuple[str, str], Link] = {}  # used to skip duplicates

    for part in msg.walk():
        if part.is_multipart():
            continue  # just a container holding other parts

        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            parsed.attachments.append(filename or "(unnamed attachment)")
            continue  # we only look at the NAME of attachments, never open them

        content_type = part.get_content_type()
        if content_type == "text/plain":
            body = _read_part_text(part)
            text_pieces.append(body)
            for match in _PLAIN_TEXT_URL.findall(body):
                url = match.rstrip(".,;:!?")
                found_links.setdefault((url, ""), Link(url=url))
        elif content_type == "text/html":
            scanner = _HTMLScanner()
            scanner.feed(_read_part_text(part))
            text_pieces.append(" ".join(scanner.visible_text))
            parsed.has_form = parsed.has_form or scanner.has_form
            for link in scanner.links:
                if _is_web_link(link.url):
                    found_links.setdefault((link.url, link.text), link)

    # Squash all whitespace so phrases split across lines still match.
    parsed.text = " ".join(" ".join(text_pieces).split())
    parsed.links = list(found_links.values())
    return parsed


def load_email(path: str | Path) -> ParsedEmail:
    """Open a .eml file from disk and parse it."""
    path = Path(path)
    return parse_email_bytes(path.read_bytes(), source=str(path))
