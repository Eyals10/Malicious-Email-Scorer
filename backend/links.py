"""Link helpers: pull links out of the email's HTML and read where each one really goes."""
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

# Real emails link to a handful of different websites. Past this, we skip the slow lookalike check
# and flag the email instead (padding with harmless links must not hide a bad one).
MAX_HOSTS = 200

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc"}

# Newsletter services send every link through their own click-tracking address, so
# "text says ynet.co.il, link goes to sendgrid.net" is normal for them.
# shortcut: a few big services only; attackers who use these services also skip the text-mismatch check.
TRACKERS = {"sendgrid.net", "list-manage.com", "mandrillapp.com", "rs6.net",
            "hubspotlinks.com", "sparkpostmail.com", "exct.net", "awstrack.me"}

_COMMON_TLDS = {"com", "net", "org", "io", "co", "il", "uk", "us", "de", "fr", "ru", "cn",
                "info", "biz", "gov", "edu", "me", "app", "xyz"}
_URLISH = re.compile(r"(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})")
_BARE_URL = re.compile(r"https?://[^\s<>\"']+")


class _LinkParser(HTMLParser):
    """Collects (href, visible text) for every <a> tag, plus web addresses typed out as plain text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)  # turns &amp; into & etc.
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._finish()  # browsers close an open link when the next one starts
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)
        else:  # Gmail makes typed-out addresses clickable, so they count as links too
            self.links.extend((url, url) for url in _BARE_URL.findall(data))

    def handle_endtag(self, tag):
        if tag == "a":
            self._finish()

    def close(self):
        super().close()
        self._finish()  # a link never closed is still clickable

    def _finish(self):
        if self._href is not None:
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
    """'185.23.11.4', '::1', and the one-number forms browsers also open: '3105225988', '0xb9170b04'."""
    last = host.rsplit(".", 1)[-1]
    if last.isdigit() or last.startswith("0x"):  # no real website name ends in a number, so browsers read it as an IP
        return True
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
    # "invoice.pdf" matches the pattern too, so also require a web prefix or a common ending (.com, .co.il, ...)
    looks_like_address = (t.startswith(("http://", "https://", "www."))
                          or domain.rsplit(".", 1)[1] in _COMMON_TLDS)
    return domain if looks_like_address else ""
