import hmac
import os
import time

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
JWT_TTL_SECONDS = int(os.environ.get("JWT_TTL_SECONDS", "3600"))

PORTAL_USERNAME = os.environ.get("PORTAL_USERNAME", "analyst")
PORTAL_PASSWORD = os.environ.get("PORTAL_PASSWORD", "analyst-password")

_bearer = HTTPBearer(auto_error=False)


def issue_token(subject: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": subject, "iat": now, "exp": now + JWT_TTL_SECONDS},
        JWT_SECRET,
        algorithm=JWT_ALG,
    )


def check_password(username: str, password: str) -> bool:
    return (
        hmac.compare_digest(username or "", PORTAL_USERNAME)
        and hmac.compare_digest(password or "", PORTAL_PASSWORD)
    )


def require_auth(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    if creds is None or (creds.scheme or "").lower() != "bearer":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError as e:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            f"invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return claims.get("sub", "")


BLOB_PUBLIC_URL = os.environ.get("BLOB_PUBLIC_URL", "http://127.0.0.1:9000").rstrip("/")
UPLOAD_TOKEN_TTL_SECONDS = int(os.environ.get("UPLOAD_TOKEN_TTL_SECONDS", "900"))


def issue_upload_token(key: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"key": key, "iat": now, "exp": now + UPLOAD_TOKEN_TTL_SECONDS},
        JWT_SECRET,
        algorithm=JWT_ALG,
    )
