"""
domain_tools.py - small helpers for working with web addresses and domain names.

Phishers love to play tricks with addresses, so several checks in this project
need to answer questions like:

  * "What website does this link REALLY go to?"
  * "Who really owns login.paypal.com.evil-site.top?"  (answer: evil-site.top)
  * "Is paypa1.com pretending to be paypal.com?"        (answer: yes)

Those answers live here so every other file can reuse them.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Well-known brands that phishers like to impersonate, and the domains those
# companies ACTUALLY use. If a message claims to be "PayPal" but comes from a
# domain that is not in PayPal's list, that's a red flag.
# (This list is intentionally short and easy to extend.)
# ---------------------------------------------------------------------------
BRANDS: dict[str, set[str]] = {
    "PayPal": {"paypal.com", "paypal.me"},
    "Microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"},
    "Office 365": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com"},
    "Outlook": {"microsoft.com", "outlook.com", "live.com"},
    "Apple": {"apple.com", "icloud.com"},
    "iCloud": {"apple.com", "icloud.com"},
    "Amazon": {"amazon.com", "amazon.co.uk", "amazon.ca", "amazonaws.com"},
    "Netflix": {"netflix.com"},
    "Google": {"google.com", "youtube.com", "googleusercontent.com"},
    "DocuSign": {"docusign.com", "docusign.net"},
    "Dropbox": {"dropbox.com"},
    "FedEx": {"fedex.com"},
    "UPS": {"ups.com"},
    "DHL": {"dhl.com"},
    "USPS": {"usps.com"},
    "IRS": {"irs.gov"},
    "LinkedIn": {"linkedin.com"},
    "Facebook": {"facebook.com", "fb.com", "meta.com"},
    "Instagram": {"instagram.com"},
    "Wells Fargo": {"wellsfargo.com"},
    "Chase": {"chase.com"},
    "Bank of America": {"bankofamerica.com", "bofa.com"},
}

# Every official domain from the list above, in one big set.
ALL_OFFICIAL_DOMAINS: set[str] = set().union(*BRANDS.values())

# Some countries use two-part endings like ".co.uk". Without this list we
# would wrongly think "bbc.co.uk" is owned by "co.uk".
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.in", "com.br", "com.mx", "co.za",
}

# Characters attackers swap to make fake domains look real at a glance.
# Order matters: "rn" must be handled before single letters.
CONFUSABLE_SWAPS = [
    ("rn", "m"),   # "rn" looks like "m"   -> arnazon.com
    ("vv", "w"),   # "vv" looks like "w"
    ("0", "o"),    # zero for letter o     -> micr0soft.com
    ("1", "l"),    # one for letter l      -> paypa1.com
    ("3", "e"),
    ("5", "s"),
]


def host_from_url(url: str) -> str:
    """Return just the website name from a link.

    "https://user@login.example.com:8080/page?x=1"  ->  "login.example.com"
    """
    url = url.strip()
    if "://" not in url:
        url = "http://" + url  # let "www.example.com" be understood too
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:  # the link is so broken it can't be read
        return ""
    return host.lower().rstrip(".")


def url_has_hidden_username(url: str) -> bool:
    """True if the link uses the '@' trick.

    In "http://paypal.com@203.0.113.9/login" everything before '@' is ignored
    by the browser - the real destination is 203.0.113.9.
    """
    if "://" not in url:
        url = "http://" + url
    try:
        return "@" in urlsplit(url).netloc
    except ValueError:
        return False


def is_ip_address(host: str) -> bool:
    """True if the 'website name' is actually a raw number like 203.0.113.9."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    """Return the part of a website name that someone actually bought/owns.

    "login.paypal.com"                      -> "paypal.com"
    "paypal.com.account-verify.top"         -> "account-verify.top"   (!)
    "www.bbc.co.uk"                         -> "bbc.co.uk"

    Note: this is a simplified version. Professional tools use the full
    "Public Suffix List" for perfect accuracy.
    """
    host = host.lower().strip(".")
    if not host or is_ip_address(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of_email(address: str) -> str:
    """'security@paypa1-support.com' -> 'paypa1-support.com'"""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").lower().rstrip(".")


def defang(text: str) -> str:
    """Make a link un-clickable so it is safe to show in a report.

    "http://evil.com/login" -> "hxxp://evil[.]com/login"
    This is standard practice in security reports and threat intel.
    """
    return (
        text.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
    )


def _undo_character_swaps(text: str) -> str:
    """Turn look-alike tricks back into normal letters: 'paypa1' -> 'paypal'."""
    text = text.lower()
    for fake, real in CONFUSABLE_SWAPS:
        text = text.replace(fake, real)
    return text


def _brand_key(brand: str) -> str:
    """'Bank of America' -> 'bankofamerica'"""
    return re.sub(r"[^a-z0-9]", "", brand.lower())


def impersonated_brand(host: str) -> tuple[str, bool] | None:
    """Check whether a website name is pretending to be a famous brand.

    Returns (brand, is_lookalike) or None.
      * is_lookalike=True  -> letters were swapped, e.g. "paypa1.com"
      * is_lookalike=False -> the real brand name is used on someone else's
                              domain, e.g. "paypal.com.account-verify.top"
    """
    host = host.lower()
    if not host or is_ip_address(host):
        return None
    if registered_domain(host) in ALL_OFFICIAL_DOMAINS:
        return None  # it's the real company's website

    # Split "paypa1-support.com.verify.top" into pieces: paypa1, support, com, ...
    for piece in re.split(r"[.\-_]+", host):
        if not piece:
            continue
        cleaned_piece = _undo_character_swaps(piece)
        for brand in BRANDS:
            key = _brand_key(brand)
            cleaned_key = _undo_character_swaps(key)
            exact = cleaned_piece == cleaned_key
            # Longer brand names may also appear glued to other words,
            # e.g. "microsoftonline-verify". Short ones (UPS, IRS) must match
            # exactly, otherwise "startups" would match "ups".
            prefix = len(key) >= 5 and cleaned_piece.startswith(cleaned_key)
            if exact or prefix:
                written_honestly = piece == key or (len(key) >= 5 and piece.startswith(key))
                return brand, not written_honestly
    return None


def brand_in_display_name(name: str) -> str | None:
    """Find a famous brand mentioned in a sender's display name.

    'PayPal Security' -> 'PayPal'
    """
    for brand in BRANDS:
        words = [re.escape(word) for word in brand.split()]
        pattern = r"\b" + r"\s*".join(words) + r"\b"
        if re.search(pattern, name, re.IGNORECASE):
            return brand
    return None
