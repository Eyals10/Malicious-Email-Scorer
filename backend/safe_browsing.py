"""Google Safe Browsing: asks Google whether any link is on its list of known phishing or malware sites."""
import logging
import os
import time
from urllib.parse import urlsplit, urlunsplit

import requests

_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
BATCH = 500        # Google's limit per request; more links are sent in several requests
TIMEOUT = 3        # seconds for one request
TOTAL_BUDGET = 5   # seconds for all requests together: the add-on must answer well within Gmail's 30 s
THREATS = {"SOCIAL_ENGINEERING": "phishing", "MALWARE": "malware",
           "UNWANTED_SOFTWARE": "unwanted software", "POTENTIALLY_HARMFUL_APPLICATION": "harmful apps"}


def without_private_parts(url: str) -> str:
    """Drop everything after ? and # (reset tokens, tracking IDs). Google matches by site and path."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def known_bad(urls: list[str]) -> dict[str, str]:
    """{url: 'phishing' | 'malware' | ...} for links on Google's list. Empty if none, no key, or Google failed."""
    key = os.environ.get("SAFE_BROWSING_KEY")
    if not key or not urls:
        return {}
    found: dict[str, str] = {}
    deadline = time.monotonic() + TOTAL_BUDGET
    # Every link is checked, not just the first 500: padding with harmless links must not hide a bad one.
    for start in range(0, len(urls), BATCH):
        left = deadline - time.monotonic()
        if left <= 0:
            logging.warning("Safe Browsing check stopped: time budget used up")
            break
        body = {
            "client": {"clientId": "malicious-email-scorer", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": list(THREATS),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls[start:start + BATCH]],
            },
        }
        try:
            r = requests.post(_API, params={"key": key}, json=body, timeout=min(TIMEOUT, left))
            r.raise_for_status()
            matches = r.json().get("matches", [])
        except (requests.RequestException, ValueError) as e:
            # Log only the kind of failure: the full error text contains the key and the links.
            status = getattr(getattr(e, "response", None), "status_code", None)
            logging.warning("Safe Browsing check skipped: %s", status or type(e).__name__)
            break  # keep what earlier batches found; the other checks still score the email
        found.update({m["threat"]["url"]: THREATS.get(m["threatType"], "harmful") for m in matches})
    return found
