"""Google Safe Browsing: asks Google whether any link is on its list of known phishing or malware sites."""
import logging
import os
from urllib.parse import urlsplit, urlunsplit

import requests

_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
MAX_URLS = 500  # Google's limit for one request
TIMEOUT = 3     # seconds: a slow answer must not hold up the whole score
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
    body = {
        "client": {"clientId": "malicious-email-scorer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(THREATS),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:MAX_URLS]],
        },
    }
    try:
        r = requests.post(_API, params={"key": key}, json=body, timeout=TIMEOUT)
        r.raise_for_status()
        matches = r.json().get("matches", [])
    except (requests.RequestException, ValueError) as e:
        # Log only the kind of failure: the full error text contains the key and the links.
        status = getattr(getattr(e, "response", None), "status_code", None)
        logging.warning("Safe Browsing check skipped: %s", status or type(e).__name__)
        return {}  # skip this one check; the others still score the email
    return {m["threat"]["url"]: THREATS.get(m["threatType"], "harmful") for m in matches}
