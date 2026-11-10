from dataclasses import asdict

from signals import Signal, check_attachments, check_auth, check_identity, check_links

GROUP_CAPS = {"auth": 35, "identity": 50, "links": 45, "attachments": 50}


def verdict_for(score: int) -> str:
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
        "reasons": [{"group": s.group, "text": s.reason} for s in top],
        "signals": [asdict(s) for s in signals],
    }


def score_email(req) -> dict:
    """Run every check on the email."""
    return score_signals(check_auth(req.auth_results)
                         + check_identity(req.sender, req.reply_to)
                         + check_links(req.html_body)
                         + check_attachments(req.attachments))
