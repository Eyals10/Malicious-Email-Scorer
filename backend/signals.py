"""The checks. Each one looks at one part of the email and returns signals:
small findings with points and a plain-language reason for the user."""
import re
from dataclasses import dataclass

from brands import brand_in_text, lookalike_of
from domains import decode_punycode, display_name_of, domain_of, registrable_domain
from links import MAX_HOSTS, SHORTENERS, TRACKERS, domain_in_text, extract_links, host_of, is_ip


@dataclass(frozen=True)
class Signal:
    group: str              # "auth", "identity", "links" or "attachments"
    points: int
    reason: str             # plain-language sentence shown to the user
    override: bool = False  # True = Malicious no matter what the total is


# ── Authentication: SPF / DKIM / DMARC ─────────────────────────────────────────

_AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc)=([a-z]+)", re.IGNORECASE)


def check_auth(auth_results: str) -> list[Signal]:
    """Read Gmail's SPF / DKIM / DMARC verdicts from the Authentication-Results header."""
    # Trust only the header Gmail added; a sender can write a fake one claiming "pass".
    if not auth_results.strip().lower().startswith("mx.google.com"):
        return []

    results: dict[str, set[str]] = {}  # e.g. {"dkim": {"fail", "pass"}}: an email can carry several signatures
    for method, result in _AUTH_RESULT.findall(auth_results):
        results.setdefault(method.lower(), set()).add(result.lower())
    spf, dkim, dmarc = (results.get(m, set()) for m in ("spf", "dkim", "dmarc"))

    signals = []
    if "fail" in spf:
        signals.append(Signal("auth", 15,
                              "The sending server isn't authorized to send email for this domain (SPF failed)."))
    elif "softfail" in spf:
        signals.append(Signal("auth", 5,
                              "The sending server isn't on the domain's approved list (SPF soft fail)."))
    if "pass" not in dkim:  # one valid signature is enough
        if "fail" in dkim:
            signals.append(Signal("auth", 10,
                                  "The email's digital signature is broken, so it may be forged or altered (DKIM failed)."))
        else:
            signals.append(Signal("auth", 10, "The email has no digital signature (DKIM missing)."))
    if "fail" in dmarc:
        signals.append(Signal("auth", 20,
                              "The sender's domain says this email isn't really from them (DMARC failed)."))
    return signals


# ── Identity: who the sender pretends to be ───────────────────────────────────

def check_identity(sender: str, reply_to: str) -> list[Signal]:
    """Is the sender pretending to be someone else?"""
    domain = domain_of(sender)
    if not domain:
        return []
    signals = []

    # 1. The address itself imitates a brand: paypa1.com, rnicrosoft.com
    brand = lookalike_of(domain)
    if brand:
        reason = f"The sender's domain ({domain}) imitates {brand}."
        if decode_punycode(domain) != domain:
            reason += " It uses look-alike foreign letters to hide this."
        signals.append(Signal("identity", 30, reason))

    # 2. The display name claims a brand the address doesn't belong to: "PayPal Security" <x@gmail.com>
    claimed = brand_in_text(display_name_of(sender))
    if claimed:
        name, domains = claimed
        if registrable_domain(domain) not in domains:
            signals.append(Signal("identity", 25, f"The sender's name says {name}, but the email comes from "
                                                  f"{domain}, which isn't {name}'s domain."))

    # 3. Replies go to a different company than the sender's
    reply_domain = domain_of(reply_to)
    if reply_domain and registrable_domain(reply_domain) != registrable_domain(domain):
        signals.append(Signal("identity", 15,
                              f"Replies would go to {reply_domain}, not to the sender's domain ({domain})."))
    return signals


# ── Links: where they really go ───────────────────────────────────────────────

# "too_many" equals "lookalike", the check it replaces, so padding with harmless links never lowers the score.
_LINK_POINTS = {"mismatch": 25, "lookalike": 25, "too_many": 25, "ip": 20, "punycode": 15, "shortener": 5}


def check_links(html_body: str) -> list[Signal]:
    """Where do the links really go? One signal per kind of problem, however many links have it."""
    found: dict[str, list[str]] = {}
    seen_hosts: dict[str, str | None] = {}  # host -> brand it imitates; the costly check runs once per host
    for href, text in extract_links(html_body):
        host = host_of(href)
        if not host:  # mailto:, javascript:, broken links
            continue
        if host not in seen_hosts:
            if len(seen_hosts) < MAX_HOSTS:
                seen_hosts[host] = lookalike_of(host)
            else:  # skip only the slow check; the cheap checks below still run on every link
                found["too_many"] = ["This email links to an unusual number of different websites."]

        reg = registrable_domain(host)
        shown = domain_in_text(text)
        if shown and registrable_domain(shown) != reg and reg not in TRACKERS:
            found.setdefault("mismatch", []).append(f"A link says {shown} but really goes to {host}.")
        brand = seen_hosts.get(host)
        if brand:
            found.setdefault("lookalike", []).append(f"A link goes to {host}, which imitates {brand}.")
        if is_ip(host):
            found.setdefault("ip", []).append(
                f"A link goes to a bare IP address ({host}) instead of a named website.")
        if "xn--" in host:
            found.setdefault("punycode", []).append(f"A link's address ({host}) uses look-alike foreign letters.")
        if reg in SHORTENERS:
            found.setdefault("shortener", []).append(f"A link uses a shortener ({host}) that hides where it leads.")

    return _one_per_kind("links", _LINK_POINTS, found)


# ── Attachments: is a file hiding what it is? ─────────────────────────────────

_BIDI = re.compile("[\u202A-\u202E\u2066-\u2069]")  # invisible characters that flip how text is displayed

RUNS_CODE = {"exe", "scr", "com", "bat", "cmd", "pif", "msi", "js", "jse", "vbs", "vbe", "wsf",
             "hta", "ps1", "jar", "lnk", "iso", "img", "html", "htm"}
DECOYS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "zip"}
MACROS = {"docm", "xlsm", "pptm", "dotm", "xlam"}

_ATTACHMENT_POINTS = {"disguised": 35, "runs_code": 30, "macro": 20}


def check_attachments(names: list[str]) -> list[Signal]:
    """Judge attachments by file name: hidden real types, programs, macro files."""
    found: dict[str, list[str]] = {}
    for name in names:
        shown = _BIDI.sub("", name).strip()  # never put the flipping characters in our own card
        # Windows drops trailing dots and spaces when saving, so "setup.exe. " lands on disk as "setup.exe".
        parts = [p.strip() for p in shown.lower().rstrip(". ").split(".")]
        ext = parts[-1] if len(parts) > 1 else ""
        if _BIDI.search(name) or (len(parts) > 2 and ext in RUNS_CODE and parts[-2] in DECOYS):
            found.setdefault("disguised", []).append(f"The attachment {shown} hides its real file type (.{ext}).")
        elif ext in RUNS_CODE:
            found.setdefault("runs_code", []).append(
                f"The attachment {shown} is a file type that can run code or show a fake login page (.{ext}).")
        elif ext in MACROS:
            found.setdefault("macro", []).append(
                f"The attachment {shown} is an Office file with macros, which can run code.")
    return _one_per_kind("attachments", _ATTACHMENT_POINTS, found, overrides=("disguised",))


# ── Shared ─────────────────────────────────────────────────────────────────────

def _one_per_kind(group: str, points_by_kind: dict[str, int], found: dict[str, list[str]],
                  overrides: tuple[str, ...] = ()) -> list[Signal]:
    """One signal per kind of problem; extra cases become '(and N more)'."""
    signals = []
    for kind, points in points_by_kind.items():
        if kind in found:
            reasons = found[kind]
            more = f" (and {len(reasons) - 1} more)" if len(reasons) > 1 else ""
            signals.append(Signal(group, points, reasons[0] + more, kind in overrides))
    return signals
