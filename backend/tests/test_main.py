import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image

import main

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def configured_server(monkeypatch):
    """Every test starts with an audience set, like the real deployed server."""
    monkeypatch.setattr(main, "TOKEN_AUDIENCE", "test-audience")
    yield
    main.app.dependency_overrides.clear()


@pytest.fixture
def logged_in():
    """Skip the real token check, pretending a valid user is logged in."""
    main.app.dependency_overrides[main.verify_user] = lambda: "user@example.com"


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_missing_token_rejected():
    assert client.post("/analyze", json={}).status_code == 401


def test_fake_token_rejected():
    r = client.post("/analyze", json={}, headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_unconfigured_server_fails_closed(monkeypatch):
    monkeypatch.setattr(main, "TOKEN_AUDIENCE", "")
    r = client.post("/analyze", json={}, headers={"Authorization": "Bearer anything"})
    assert r.status_code == 503


def test_logged_in_user_gets_a_score(logged_in):
    r = client.post("/analyze", json={"sender": "a@b.com", "subject": "hi"})
    assert r.status_code == 200
    assert set(r.json()) == {"score", "verdict", "reasons", "signals"}


def test_oversized_sender_rejected(logged_in):
    r = client.post("/analyze", json={"sender": "x" * 501})
    assert r.status_code == 422


def test_gauge_is_public_animated_gif():
    r = client.get("/gauge/85.gif")  # no token: Gmail's image fetch can't send one
    assert r.status_code == 200 and r.headers["content-type"] == "image/gif"
    assert Image.open(io.BytesIO(r.content)).is_animated


def test_gauge_rejects_out_of_range_scores():
    assert client.get("/gauge/101.gif").status_code == 422
