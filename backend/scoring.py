"""Scoring: turns signals into the final score, verdict and top reasons."""
from dataclasses import asdict

from signals import Signal, check_attachments, check_auth, check_identity, check_links

# The most points each kind of check can add, so one noisy area can't decide the verdict alone.
GROUP_CAPS = {"auth": 35, "identity": 50, "links": 45, "attachments": 50}


def verdict_for(score: int) -> str:
    """0-29 Safe, 30-69 Suspicious, 70-100 Malicious."""
    if score >= 70:
        return "Malicious"
    if score >= 30:
        return "Suspicious"
    return "Safe"


def score_signals(signals: list[Signal]) -> dict:
    """Turn signals into the response: capped score, verdict, top reasons."""
    per_group: dict[str, int] = {}
    for s in signals:
        per_group[s.group] = per_group.get(s.group, 0) + s.points
    total = sum(min(points, GROUP_CAPS[group]) for group, points in per_group.items())

    score = 100 if any(s.override for s in signals) else min(total, 100)
    top = sorted(signals, key=lambda s: s.points, reverse=True)[:3]
    return {
        "score": score,
        "verdict": verdict_for(score),
        "reasons": [{"group": s.group, "text": s.reason} for s in top],  # shown on the card
        "signals": [asdict(s) for s in signals],                         # "All findings" on the card
    }


def score_email(req) -> dict:
    """Run every check on the email. req is the AnalyzeRequest from main.py."""
    return score_signals(check_auth(req.auth_results)
                         + check_identity(req.sender, req.reply_to)
                         + check_links(req.html_body)
                         + check_attachments(req.attachments))
