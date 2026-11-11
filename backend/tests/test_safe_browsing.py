import pytest
import requests

import safe_browsing
from signals import check_links


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


@pytest.fixture
def google(monkeypatch):
    """Pretend a key is set. A fake Google lists the URLs in google['listed'] and records every request."""
    monkeypatch.setenv("SAFE_BROWSING_KEY", "test-key")
    state = {"listed": set(), "requests": []}

    def fake_post(url, params, json, timeout):
        sent = [entry["url"] for entry in json["threatInfo"]["threatEntries"]]
        state["requests"].append(sent)
        return FakeResponse({"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": u}}
                                         for u in sent if u in state["listed"]]})

    monkeypatch.setattr(safe_browsing.requests, "post", fake_post)
    return state


def test_no_key_means_no_request(monkeypatch):
    monkeypatch.delenv("SAFE_BROWSING_KEY", raising=False)
    monkeypatch.setattr(safe_browsing.requests, "post", lambda *a, **k: pytest.fail("must not call Google"))
    assert safe_browsing.known_bad(["https://x.com"]) == {}


def test_listed_link_forces_malicious(google):
    google["listed"].add("https://evil.example/login")
    [signal] = check_links('<a href="https://evil.example/login?token=secret">Log in</a>')
    assert signal.override and "phishing" in signal.reason
    assert google["requests"] == [["https://evil.example/login"]]  # one request, token never sent


def test_padding_does_not_hide_a_listed_link(google):
    bad = "https://evil.example/login"
    google["listed"].add(bad)
    padding = "".join(f'<a href="https://my-site.example/{i}">x</a>' for i in range(safe_browsing.BATCH))
    signals = check_links(padding + f'<a href="{bad}">Log in</a>')
    assert any(s.override for s in signals)          # link 501 is still checked...
    assert [len(r) for r in google["requests"]] == [500, 1]  # ...in a second request


def test_google_down_skips_only_this_check(google, monkeypatch):
    def timeout(*a, **k):
        raise requests.Timeout()

    monkeypatch.setattr(safe_browsing.requests, "post", timeout)
    assert [s.points for s in check_links('<a href="http://185.23.11.4/x">x</a>')] == [20]  # IP check still works
