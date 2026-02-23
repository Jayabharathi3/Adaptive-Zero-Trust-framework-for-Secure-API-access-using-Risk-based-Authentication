import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException, status
from jose import JWTError, jwt


class AuthError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


JWT_ALGORITHM = "HS256"
JWT_SECRET_ENV = "JWT_SECRET_KEY"


def get_jwt_secret() -> str:
    secret = os.getenv(JWT_SECRET_ENV)
    if not secret:
        raise RuntimeError(
            f"Missing JWT secret. Set environment variable {JWT_SECRET_ENV}."
        )
    return secret


def decode_jwt(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise AuthError("Invalid JWT") from exc

    exp: Optional[int] = payload.get("exp")  # type: ignore[assignment]
    if exp is not None:
        now_ts = int(datetime.now(tz=timezone.utc).timestamp())
        if now_ts > int(exp):
            raise AuthError("JWT has expired")

    return payload


def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify a JWT and return decoded user info.

    Raises HTTPException(401) when invalid/expired.
    Raises HTTPException(500) when server is misconfigured (missing secret).
    """
    try:
        return decode_jwt(token)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.message,
        ) from exc

