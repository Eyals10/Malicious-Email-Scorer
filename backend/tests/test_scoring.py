from scoring import score_signals
from signals import Signal


def test_no_signals_is_safe():
    r = score_signals([])
    assert (r["score"], r["verdict"], r["reasons"]) == (0, "Safe", [])


def test_group_cap_applies():
    r = score_signals([Signal("auth", 20, "a"), Signal("auth", 20, "b")])
    assert r["score"] == 35  # 40 capped to auth's 35


def test_thresholds():
    assert score_signals([Signal("links", 29, "x")])["verdict"] == "Safe"
    assert score_signals([Signal("links", 30, "x")])["verdict"] == "Suspicious"
    assert score_signals([Signal("links", 30, "x"), Signal("identity", 40, "y")])["verdict"] == "Malicious"


def test_total_never_exceeds_100():
    signals = [Signal(g, 50, g) for g in ("auth", "identity", "links", "attachments")]
    assert score_signals(signals)["score"] == 100


def test_override_forces_malicious():
    r = score_signals([Signal("attachments", 35, "double extension", override=True)])
    assert (r["score"], r["verdict"]) == (100, "Malicious")


def test_top_three_reasons_by_points():
    signals = [Signal("auth", 5, "low"), Signal("links", 25, "high"),
               Signal("identity", 15, "mid"), Signal("auth", 10, "midlow")]
    assert [r["text"] for r in score_signals(signals)["reasons"]] == ["high", "mid", "midlow"]
