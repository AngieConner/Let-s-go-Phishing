"""
link_checks.py - inspects every link in the email WITHOUT visiting it.

Visiting a phishing link can be dangerous (and alerts the attacker that your
address is active), so we only study the text of each link.
"""

from __future__ import annotations

import re

from .domain_tools import (
    defang,
    host_from_url,
    impersonated_brand,
    is_ip_address,
    registered_domain,
    url_has_hidden_username,
)
from .email_loader import ParsedEmail
from .scoring import Finding

# Services that shorten links. They are not evil, but they HIDE the real destination.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
}

# Domain endings that are cheap/free and very common in phishing campaigns.
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "kim", "work", "rest", "cam", "icu", "buzz", "monster", "sbs", "cfd", "lol",
}

# Each rule: (title, plain-English explanation, points)
RULES = {
    "mismatch": ("Link text shows one address but goes to another",
                 "The words on the link look like one website, but clicking it opens a different one. "
                 "This is one of the strongest signs of phishing.", 30),
    "lookalike": ("Look-alike domain imitating a brand",
                  "The link uses swapped characters (like the number 1 for the letter l) to imitate a well-known company.", 30),
    "brand_misuse": ("Brand name used on an unrelated website",
                     "A famous brand's name appears in the link, but the website is owned by someone else "
                     "(only the last part before .com/.net etc. shows the real owner).", 25),
    "ip": ("Link points to a raw IP address",
           "Real companies use website names, not raw number addresses like 203.0.113.9.", 25),
    "at_sign": ("Link uses the '@' trick",
                "Everything before an '@' in a link is ignored by the browser, so the real destination is hidden after it.", 20),
    "punycode": ("Link uses disguised international characters",
                 "'xn--' means the address contains foreign letters that can look identical to English ones (e.g. Cyrillic 'а').", 20),
    "shortener": ("Shortened link hides the real destination",
                  "Link shorteners hide where a link really goes. Legitimate companies rarely use them in account emails.", 10),
    "tld": ("Risky domain ending",
            "This domain ending is cheap or free to register and is frequently abused by phishers.", 10),
    "subdomains": ("Unusually long website name",
                   "Long chains of words separated by dots are often used to bury the real owner at the end.", 10),
    "no_https": ("Link is not encrypted (http instead of https)",
                 "Login and payment pages from real companies use https. This is a weak signal on its own.", 5),
    "unreadable": ("Broken or unreadable link",
                   "The link is malformed, which can be an attempt to confuse filters.", 5),
}

_LOOKS_LIKE_ADDRESS = re.compile(r"^(https?://|www\.)\S+$|^[a-z0-9.-]+\.[a-z]{2,}(/\S*)?$", re.IGNORECASE)


def check_links(email: ParsedEmail) -> list[Finding]:
    problems: dict[str, list[str]] = {}

    def flag(rule: str, example: str) -> None:
        problems.setdefault(rule, [])
        if example not in problems[rule]:
            problems[rule].append(example)

    for link in email.links:
        url = link.url
        host = host_from_url(url)
        if not host:
            flag("unreadable", url)
            continue
        owner = registered_domain(host)

        # Does the visible text look like an address that differs from the real one?
        shown = link.text.strip()
        if shown and _LOOKS_LIKE_ADDRESS.match(shown):
            shown_host = host_from_url(shown)
            if shown_host and registered_domain(shown_host) != owner:
                flag("mismatch", f"shows '{defang(shown)}' -> really goes to {defang(url)}")

        if is_ip_address(host):
            flag("ip", defang(url))

        impersonation = impersonated_brand(host)
        if impersonation:
            flag("lookalike" if impersonation[1] else "brand_misuse", defang(url))

        if owner in URL_SHORTENERS:
            flag("shortener", defang(url))
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            flag("tld", defang(url))
        if url_has_hidden_username(url):
            flag("at_sign", defang(url))
        if "xn--" in host:
            flag("punycode", defang(url))
        if host.count(".") >= 4:
            flag("subdomains", defang(url))
        if url.lower().startswith("http://"):
            flag("no_https", defang(url))

    # One finding per type of problem (so 10 bad links don't count 10 times).
    findings = []
    for rule, examples in problems.items():
        title, explanation, points = RULES[rule]
        shown_examples = "; ".join(examples[:3])
        more = f" (+{len(examples) - 3} more)" if len(examples) > 3 else ""
        findings.append(Finding("Links", title, f"{explanation} Example: {shown_examples}{more}", points))
    return findings
