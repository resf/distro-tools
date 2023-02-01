from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from apollo.server.utils import templates

router = APIRouter(tags=["non-api"])


@router.get("/", response_class=HTMLResponse)
async def admin_general(request: Request):
    return templates.TemplateResponse(
        "admin_index.jinja", {
            "request": request,
        }
    )
