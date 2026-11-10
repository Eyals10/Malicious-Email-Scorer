import re
from dataclasses import dataclass

from brands import brand_in_text, lookalike_of
from domains import decode_punycode, display_name_of, domain_of, registrable_domain


@dataclass(frozen=True)
class Signal:
    group: str              # "auth", "identity", "links" or "attachments"
    points: int
    reason: str             # plain-language sentence shown to the user
    override: bool = False  # True = Malicious no matter what the total is


_AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc)=([a-z]+)", re.IGNORECASE)


def check_auth(auth_results: str) -> list[Signal]:
    """Read Gmail's SPF / DKIM / DMARC verdicts from the Authentication-Results header."""
    # Trust only the header Gmail added; a sender can write a fake one claiming "pass".
    if not auth_results.strip().lower().startswith("mx.google.com"):
        return []

    results: dict[str, set[str]] = {}
    for method, result in _AUTH_RESULT.findall(auth_results):
        results.setdefault(method.lower(), set()).add(result.lower())
    spf, dkim, dmarc = (results.get(m, set()) for m in ("spf", "dkim", "dmarc"))

    signals = []
    if "fail" in spf:
        signals.append(Signal("auth", 15, "The sending server isn't authorized to send email for this domain (SPF failed)."))
    elif "softfail" in spf:
        signals.append(Signal("auth", 5, "The sending server isn't on the domain's approved list (SPF soft fail)."))
    if "pass" not in dkim:
        if "fail" in dkim:
            signals.append(Signal("auth", 10, "The email's digital signature is broken, so it may be forged or altered (DKIM failed)."))
        else:
            signals.append(Signal("auth", 10, "The email has no digital signature (DKIM missing)."))
    if "fail" in dmarc:
        signals.append(Signal("auth", 20, "The sender's domain says this email isn't really from them (DMARC failed)."))
    return signals


def check_identity(sender: str, reply_to: str) -> list[Signal]:
    """Is the sender pretending to be someone else?"""
    domain = domain_of(sender)
    if not domain:
        return []
    signals = []

    brand = lookalike_of(domain)
    if brand:
        reason = f"The sender's domain ({domain}) imitates {brand}."
        if decode_punycode(domain) != domain:
            reason += " It uses look-alike foreign letters to hide this."
        signals.append(Signal("identity", 30, reason))

    claimed = brand_in_text(display_name_of(sender))
    if claimed and registrable_domain(domain) not in claimed[1]:
        name = claimed[0]
        signals.append(Signal("identity", 25, f"The sender's name says {name}, but the email comes from {domain}, which isn't {name}'s domain."))

    reply_domain = domain_of(reply_to)
    if reply_domain and registrable_domain(reply_domain) != registrable_domain(domain):
        signals.append(Signal("identity", 15, f"Replies would go to {reply_domain}, not to the sender's domain ({domain})."))
    return signals
