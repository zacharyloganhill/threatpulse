"""
PhantomFeed — Tabletop Exercise API Routes
"""
from fastapi import APIRouter, Depends, Query, BackgroundTasks
from fastapi.responses import Response
from auth.auth import get_current_user

router = APIRouter()


@router.get("/clients/{client_id}/tabletops")
async def list_tabletops(client_id: str, user: dict = Depends(get_current_user)):
    from db import database as db
    exercises = await db.get_tabletops(client_id)
    return {"count": len(exercises), "exercises": exercises}


@router.post("/clients/{client_id}/tabletops/generate")
async def generate_tabletop(
    client_id: str,
    body: dict,
    user: dict = Depends(get_current_user),
):
    from reports.tabletop_generator import generate_tabletop_scenario
    scenario_type = body.get("scenario_type", "ransomware")
    custom_prompt = body.get("custom_prompt", "")
    result = await generate_tabletop_scenario(client_id, scenario_type, custom_prompt)
    return result


@router.get("/clients/{client_id}/tabletops/{exercise_id}")
async def get_tabletop(
    client_id: str,
    exercise_id: str,
    user: dict = Depends(get_current_user),
):
    from db import database as db
    ex = await db.get_tabletop(exercise_id)
    if not ex:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Exercise not found")
    return ex


@router.get("/clients/{client_id}/tabletops/{exercise_id}/export.pdf")
async def export_tabletop_pdf(
    client_id: str,
    exercise_id: str,
    user: dict = Depends(get_current_user),
):
    from db import database as db
    from reports.tabletop_generator import export_tabletop_pdf
    ex = await db.get_tabletop(exercise_id)
    if not ex:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Exercise not found")
    # Reconstruct full tabletop dict
    client = await db.get_client(client_id)
    tabletop = {
        "title": ex.get("title"),
        "client_name": client.get("name") if client else "",
        "industry": (client.get("industry") or "") if client else "",
        "generated_at": ex.get("created_at", ""),
        "scenario": ex.get("scenario_json", {}),
    }
    pdf_bytes = export_tabletop_pdf(tabletop)
    filename = f"tabletop-{exercise_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/clients/{client_id}/tabletops/{exercise_id}/export.pptx")
async def export_tabletop_pptx(
    client_id: str,
    exercise_id: str,
    user: dict = Depends(get_current_user),
):
    from db import database as db
    from reports.tabletop_generator import export_tabletop_pptx
    ex = await db.get_tabletop(exercise_id)
    if not ex:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Exercise not found")
    client = await db.get_client(client_id)
    tabletop = {
        "title": ex.get("title"),
        "client_name": client.get("name") if client else "",
        "industry": (client.get("industry") or "") if client else "",
        "generated_at": ex.get("created_at", ""),
        "scenario": ex.get("scenario_json", {}),
    }
    pptx_bytes = export_tabletop_pptx(tabletop)
    filename = f"tabletop-{exercise_id[:8]}.pptx"
    return Response(
        content=pptx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/tabletop/scenario-types")
async def scenario_types(user: dict = Depends(get_current_user)):
    from reports.tabletop_generator import SCENARIO_TEMPLATES
    return {
        k: {"title": v["title"], "phases": v["phases"]}
        for k, v in SCENARIO_TEMPLATES.items()
    }
