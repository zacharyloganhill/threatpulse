"""PhantomFeed — Authentication API Routes"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from auth.auth import verify_password, create_access_token, get_current_user
from fastapi import Depends

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login", summary="Login and receive a JWT token")
async def login(req: LoginRequest):
    from db import database as db

    user = await db.get_user_by_username(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

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
