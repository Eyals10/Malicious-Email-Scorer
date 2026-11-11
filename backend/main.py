import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Response
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from pydantic import BaseModel, Field

from gauge import gauge_gif
from scoring import score_email

# The add-on's OAuth client ID. Tokens issued for any other app are rejected.
TOKEN_AUDIENCE = os.environ.get("TOKEN_AUDIENCE", "")

app = FastAPI(title="Malicious Email Scorer")
_google_request = google_requests.Request()


def verify_user(authorization: str | None = Header(default=None)) -> str:
    """Accept only requests carrying a valid Google ID token issued to our add-on."""
    if not TOKEN_AUDIENCE:
        # Fail closed: an unconfigured server must not serve anyone.
        raise HTTPException(503, "Server not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    try:
        claims = id_token.verify_oauth2_token(
            authorization.removeprefix("Bearer "), _google_request, TOKEN_AUDIENCE
        )
    except ValueError:
        raise HTTPException(401, "Invalid token")
    return claims.get("email", "")


class AnalyzeRequest(BaseModel):
    # Generous limits: they block abuse, while the add-on trims real emails to fit.
    sender: str = Field(default="", max_length=500)
    auth_results: str = Field(default="", max_length=5000)
    reply_to: str = Field(default="", max_length=500)
    html_body: str = Field(default="", max_length=200_000)
    attachments: list[Annotated[str, Field(max_length=255)]] = Field(default=[], max_length=100)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/gauge/{score}.gif")
def gauge(score: int = Path(ge=0, le=100)):
    """Public: Gmail fetches card images itself, without our token. The picture shows only a number."""
    return Response(gauge_gif(score), media_type="image/gif",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.post("/analyze")
def analyze(req: AnalyzeRequest, user: str = Depends(verify_user)):
    return score_email(req)
