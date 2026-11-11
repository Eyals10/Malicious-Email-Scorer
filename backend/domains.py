"""Domain helpers: read addresses, find the part of a domain a person buys, and undo disguises."""
from email.utils import parseaddr

# shortcut: hand-picked two-part suffixes; switch to the Public Suffix List (tldextract) for production.
_TWO_PART_SUFFIXES = {
    "co.il", "org.il", "ac.il", "net.il", "gov.il", "muni.il",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "com.br", "co.in", "co.nz", "co.za",
}

# Characters attackers swap in because they look like Latin letters (digits + Cyrillic).
_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
})


def domain_of(address: str) -> str:
    """'"PayPal" <x@Mail.PayPal.com>' -> 'mail.paypal.com' ('' if there's no address)."""
    _, addr = parseaddr(address)
    return addr.rpartition("@")[2].strip().lower().rstrip(".") if "@" in addr else ""


def display_name_of(address: str) -> str:
    """'"PayPal Security" <x@gmail.com>' -> 'PayPal Security'."""
    return parseaddr(address)[0]


def registrable_domain(host: str) -> str:
    """The part a person actually buys: 'mail.paypal.com' -> 'paypal.com', 'x.leumi.co.il' -> 'leumi.co.il'."""
    labels = host.lower().strip(".").split(".")
    keep = 3 if ".".join(labels[-2:]) in _TWO_PART_SUFFIXES else 2
    return ".".join(labels[-keep:])


def decode_punycode(host: str) -> str:
    """'xn--pple-43d.com' -> 'аpple.com' (with a Cyrillic 'а'). Unchanged if it isn't punycode."""
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


def normalize(text: str) -> str:
    """Undo common disguises, so 'paypa1', 'аpple', 'rnicrosoft' and 'vvhatsapp' read as the real names."""
    return text.lower().translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def edit_distance(a: str, b: str) -> int:
    """How many single-letter changes turn a into b: insert, delete, substitute,
    or swap two neighbouring letters (so 'microsfot' is 1 change from 'microsoft')."""
    d = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]
