"""
PhantomFeed — Briefing Deck API Routes
"""
from fastapi import APIRouter, Depends, Query, HTTPException, status, Request
from fastapi.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional

router = APIRouter()

# Auth helper that accepts Bearer header OR ?token= query param (needed for window.open downloads)
bearer_scheme = HTTPBearer(auto_error=False)


async def _require_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    from auth.auth import decode_token
    from db import database as db

    token_str = None
    if credentials:
        token_str = credentials.credentials
    else:
        token_str = request.query_params.get("token")

    if not token_str:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_token(token_str)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@router.get("/clients/{client_id}/deck.pptx")
async def download_deck(
    client_id: str,
    days: int = Query(30, ge=7, le=365),
    user: dict = Depends(_require_user),
):
    """Generate and download the executive briefing deck as PPTX."""
    from reports.deck_generator import BriefingDeckGenerator
    gen = BriefingDeckGenerator()
    deck_bytes = await gen.generate_deck(client_id, days=days)
    from datetime import datetime
    filename = f"threat-brief-{client_id[:8]}-{datetime.utcnow().strftime('%Y%m%d')}.pptx"
    return Response(
        content=deck_bytes,
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/clients/{client_id}/deck-preview")
async def deck_preview(
    client_id: str,
    days: int = Query(30, ge=7, le=365),
    user: dict = Depends(_require_user),
):
    """Return slide outline JSON for preview without generating the file."""
    from reports.deck_generator import BriefingDeckGenerator
    gen = BriefingDeckGenerator()
    return await gen.get_deck_preview(client_id, days=days)
