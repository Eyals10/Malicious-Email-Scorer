import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

# Real emails link to a handful of different websites; past this, we stop and flag the email
# instead of silently skipping links (padding with harmless links must not hide a bad one).
MAX_HOSTS = 200

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc"}

# Newsletter services send every link through their own click-tracking address, so
# "text says ynet.co.il, link goes to sendgrid.net" is normal for them.
# shortcut: a few big services only; attackers who use these services also skip the text-mismatch check.
TRACKERS = {"sendgrid.net", "list-manage.com", "mandrillapp.com", "rs6.net",
            "hubspotlinks.com", "sparkpostmail.com", "exct.net"}

_COMMON_TLDS = {"com", "net", "org", "io", "co", "il", "uk", "us", "de", "fr", "ru", "cn",
                "info", "biz", "gov", "edu", "me", "app", "xyz"}
_URLISH = re.compile(r"(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})")


class _LinkParser(HTMLParser):
    """Collects (href, visible text) for every <a> tag."""

    def __init__(self):
        super().__init__(convert_charrefs=True)  # turns &amp; into & etc.
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._text).split())))
            self._href = None


def extract_links(html: str) -> list[tuple[str, str]]:
    """'<a href="https://x.com">Click <b>here</b></a>' -> [('https://x.com', 'Click here')]"""
    parser = _LinkParser()
    parser.feed(html)
    parser.close()
    return parser.links


def host_of(href: str) -> str:
    """The real destination host. '' for mailto:, javascript: and broken links."""
    try:
        parts = urlsplit(href)
    except ValueError:
        return ""
    return (parts.hostname or "") if parts.scheme in ("http", "https") else ""


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def domain_in_text(text: str) -> str:
    """'www.chase.com' or 'https://chase.com/login' -> 'chase.com'. '' if the text isn't a web address."""
    t = text.strip().lower()
    m = _URLISH.match(t)
    if not m:
        return ""
    domain = m.group(1)
    looks_like_address = t.startswith(("http://", "https://", "www.")) or domain.rsplit(".", 1)[1] in _COMMON_TLDS
    return domain if looks_like_address else ""
