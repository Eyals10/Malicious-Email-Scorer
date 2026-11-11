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
    """Pretend a key is set, and record what would be sent to Google instead of calling it."""
    monkeypatch.setenv("SAFE_BROWSING_KEY", "test-key")
    sent = {"answer": {}}

    def fake_post(url, params, json, timeout):
        sent["body"] = json
        return FakeResponse(sent["answer"])

    monkeypatch.setattr(safe_browsing.requests, "post", fake_post)
    return sent


def test_no_key_means_no_request(monkeypatch):
    monkeypatch.delenv("SAFE_BROWSING_KEY", raising=False)
    monkeypatch.setattr(safe_browsing.requests, "post", lambda *a, **k: pytest.fail("must not call Google"))
    assert safe_browsing.known_bad(["https://x.com"]) == {}


def test_listed_link_forces_malicious(google):
    google["answer"] = {"matches": [{"threatType": "SOCIAL_ENGINEERING",
                                     "threat": {"url": "https://evil.example/login"}}]}
    [signal] = check_links('<a href="https://evil.example/login?token=secret">Log in</a>')
    assert signal.override and "phishing" in signal.reason
    assert google["body"]["threatInfo"]["threatEntries"] == [{"url": "https://evil.example/login"}]  # token never sent


def test_google_down_skips_only_this_check(google, monkeypatch):
    def timeout(*a, **k):
        raise requests.Timeout()

    monkeypatch.setattr(safe_browsing.requests, "post", timeout)
    assert [s.points for s in check_links('<a href="http://185.23.11.4/x">x</a>')] == [20]  # IP check still works
