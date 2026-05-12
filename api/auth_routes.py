"""PhantomFeed — Authentication API Routes"""

import time
from collections import defaultdict
from fastapi import APIRouter, HTTPException, status, Request
from pydantic import BaseModel

from auth.auth import verify_password, create_access_token, get_current_user
from fastapi import Depends

router = APIRouter()

# AC-7 brute-force lockout: 5 failures → 15-minute lockout per username
_MAX_ATTEMPTS = 5
_LOCKOUT_SECONDS = 900  # 15 minutes
_attempts: dict = defaultdict(list)  # username -> [timestamp, ...]


def _check_lockout(username: str) -> None:
    now = time.monotonic()
    recent = [t for t in _attempts[username] if now - t < _LOCKOUT_SECONDS]
    _attempts[username] = recent
    if len(recent) >= _MAX_ATTEMPTS:
        remaining = int(_LOCKOUT_SECONDS - (now - recent[0]))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account locked after too many failed attempts. Try again in {remaining}s.",
        )


def _record_failure(username: str) -> None:
    _attempts[username].append(time.monotonic())


def _clear_failures(username: str) -> None:
    _attempts.pop(username, None)


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login", summary="Login and receive a JWT token")
async def login(req: LoginRequest):
    from db import database as db

    _check_lockout(req.username)

    user = await db.get_user_by_username(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        _record_failure(req.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    _clear_failures(req.username)
    token = create_access_token({"sub": user["id"], "role": user["role"], "username": user["username"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "display_name": user["username"],
        "client_id": user.get("client_id"),
    }


@router.get("/me", summary="Get the currently authenticated user")
async def me(user: dict = Depends(get_current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "client_id": user.get("client_id"),
    }
