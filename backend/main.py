import os

from fastapi import Depends, FastAPI, Header, HTTPException
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from pydantic import BaseModel, Field

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
    subject: str = Field(default="", max_length=1000)
    auth_results: str = Field(default="", max_length=5000)
    reply_to: str = Field(default="", max_length=500)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest, user: str = Depends(verify_user)):
    return score_email(req)
