"""
header_checks.py - inspects the email's "envelope" (its headers).

Headers are hidden by most email apps, but they hold the best evidence of
who REALLY sent a message. Quick glossary:

  * From          - the sender shown to you. Easy to fake!
  * Reply-To      - where your reply goes. Scammers set this to their own inbox.
  * Return-Path   - where bounced mail goes; set by the sending server.
  * SPF           - "Is this server allowed to send mail for this domain?"
  * DKIM          - "Was the message digitally signed and left unchanged?"
  * DMARC         - "Does the domain owner's policy agree SPF/DKIM passed for
                     the address shown in From?"
"""

from __future__ import annotations

import re

from .domain_tools import (
    BRANDS,
    brand_in_display_name,
    domain_of_email,
    impersonated_brand,
    registered_domain,
)
from .email_loader import ParsedEmail
from .scoring import Finding

# Free, personal email services. Anyone can create an account on these.
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "proton.me", "protonmail.com",
    "gmx.com", "mail.com", "yandex.com", "zoho.com",
}

# Words that make a display name sound like an organization or a boss.
ORGANIZATION_WORDS = re.compile(
    r"\b(support|security|billing|admin|administrator|helpdesk|help desk|"
    r"service|team|department|bank|payroll|hr|ceo|cfo|president|director|"
    r"manager|accounts?)\b",
    re.IGNORECASE,
)

# Points for each authentication result. "fail" is far worse than "none".
AUTH_POINTS = {
    ("spf", "fail"): 20,
    ("spf", "softfail"): 10,
    ("spf", "permerror"): 5,
    ("dkim", "fail"): 15,
    ("dkim", "none"): 5,
    ("dkim", "permerror"): 5,
    ("dmarc", "fail"): 25,
    ("dmarc", "none"): 5,
}

AUTH_EXPLANATIONS = {
    "spf": "SPF checks whether the sending server is allowed to send mail for that domain.",
    "dkim": "DKIM checks for a digital signature proving the message was not altered.",
    "dmarc": "DMARC checks whether the address shown in 'From' is backed by SPF or DKIM.",
}


def _check_authentication(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    combined = " ".join(email.auth_results)

    if not combined.strip():
        findings.append(Finding(
            "Headers", "No sender authentication results",
            "The email has no SPF/DKIM/DMARC results, so we cannot confirm who sent it. "
            "(This can also happen if the email was saved or forwarded in a way that removed them.)",
            points=5,
        ))
        return findings

    # Collect every result, e.g. {"spf": ["fail"], "dkim": ["none"], ...}
    results: dict[str, list[str]] = {}
    for mechanism, outcome in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", combined, re.IGNORECASE):
        results.setdefault(mechanism.lower(), []).append(outcome.lower())

    for mechanism in ("spf", "dkim", "dmarc"):
        outcomes = results.get(mechanism)
        if not outcomes:
            continue
        # If any check passed (e.g. one of two DKIM signatures), count it as passed.
        outcome = "pass" if "pass" in outcomes else outcomes[0]
        if outcome == "pass":
            findings.append(Finding(
                "Headers", f"{mechanism.upper()} passed",
                AUTH_EXPLANATIONS[mechanism] + " Note: this only proves the email came from the "
                "domain it claims - scammers can pass these checks using their OWN domains.",
                good_sign=True,
            ))
        elif (mechanism, outcome) in AUTH_POINTS:
            findings.append(Finding(
                "Headers", f"{mechanism.upper()} result: {outcome}",
                AUTH_EXPLANATIONS[mechanism] + f" This email's result was '{outcome}'.",
                points=AUTH_POINTS[(mechanism, outcome)],
            ))
    return findings


def check_headers(email: ParsedEmail) -> list[Finding]:
    findings = _check_authentication(email)

    from_domain = domain_of_email(email.from_address)
    from_owner = registered_domain(from_domain)

    if not email.from_address:
        findings.append(Finding(
            "Headers", "Missing sender address",
            "The 'From' line has no valid email address, which legitimate senders almost always include.",
            points=15,
        ))

    # 1. Display name claims to be a brand, but the address is not the brand's.
    brand = brand_in_display_name(email.from_name)
    if brand and from_owner not in BRANDS[brand]:
        findings.append(Finding(
            "Headers", f"Sender name pretends to be {brand}",
            f"The name shown is '{email.from_name}', but the message actually came from "
            f"'{from_domain or 'an unknown domain'}', which is not an official {brand} domain.",
            points=25,
        ))

    # 2. An email address is hidden INSIDE the display name.
    hidden = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", email.from_name)
    if hidden and hidden.group(0).lower() != email.from_address.lower():
        findings.append(Finding(
            "Headers", "Fake address placed in the sender name",
            f"The display name shows '{hidden.group(0)}' but the real address is "
            f"'{email.from_address}'. Many phones only show the name, hiding the real address.",
            points=20,
        ))

    # 3. Sender's domain is a look-alike of a famous brand (e.g. paypa1.com).
    impersonation = impersonated_brand(from_domain)
    if impersonation:
        imitated, is_lookalike = impersonation
        how = "swaps letters to look like" if is_lookalike else "borrows the name of"
        findings.append(Finding(
            "Headers", f"Sender domain imitates {imitated}",
            f"'{from_domain}' {how} {imitated}, but it is not owned by {imitated}.",
            points=30 if is_lookalike else 20,
        ))

    # 4. Organization-style name using a free personal email account.
    if from_owner in FREE_EMAIL_PROVIDERS and (brand or ORGANIZATION_WORDS.search(email.from_name)):
        findings.append(Finding(
            "Headers", "Organization name sent from a free personal account",
            f"'{email.from_name}' sounds like a company or executive, but the email was sent from "
            f"a free {from_owner} account that anyone can create.",
            points=15,
        ))

    # 5. Replies would go to a different domain than the sender.
    if email.reply_to:
        reply_owner = registered_domain(domain_of_email(email.reply_to))
        if reply_owner and reply_owner != from_owner:
            findings.append(Finding(
                "Headers", "Replies go to a different address",
                f"The email is from '{from_owner}', but if you hit reply your message goes to "
                f"'{email.reply_to}'. Scammers do this to receive your answer.",
                points=15,
            ))

    # 6. Bounce address differs (weak signal: mailing services do this legitimately).
    if email.return_path:
        bounce_owner = registered_domain(domain_of_email(email.return_path))
        if bounce_owner and from_owner and bounce_owner != from_owner:
            findings.append(Finding(
                "Headers", "Return-Path domain differs from sender",
                f"Bounced mail goes to '{bounce_owner}' instead of '{from_owner}'. This is a weak "
                "signal - newsletter services do it legitimately - but it adds to other evidence.",
                points=5,
            ))

    return findings
