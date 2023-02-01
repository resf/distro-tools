from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from apollo.db import RedHatAdvisory, Advisory

from apollo.server.utils import templates

router = APIRouter(tags=["non-api"])


@router.get("/", response_class=HTMLResponse)
async def statistics(request: Request):
    rh_advisory_count = await RedHatAdvisory.all().count()
    advisory_count = await Advisory.all().count()
    return templates.TemplateResponse(
        "index.jinja", {
            "request": request,
            "rh_advisory_count": rh_advisory_count,
            "advisory_count": advisory_count,
        }
    )
