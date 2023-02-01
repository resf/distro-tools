from math import ceil

from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse
from fastapi_pagination import Params
from fastapi_pagination.ext.tortoise import paginate

from apollo.db import RedHatAdvisory
from apollo.server.utils import admin_user_scheme, templates

from common.fastapi import RenderErrorTemplateException

router = APIRouter(tags=["non-api"])


@router.get(
    "/advisories",
    response_class=HTMLResponse,
)
async def list_red_hat_advisories(request: Request, params: Params = Depends()):
    if not request.state.settings.serve_rh_advisories:
        raise RenderErrorTemplateException()

    params.size = 50
    advisories = await paginate(
        RedHatAdvisory.all().order_by("-red_hat_issued_at"),
        params=params,
    )
    return templates.TemplateResponse(
        "red_hat_advisories.jinja", {
            "request": request,
            "advisories": advisories,
            "advisories_pages": ceil(advisories.total / advisories.size),
        }
    )


@router.get(
    "/advisories/{advisory_name}",
    response_class=HTMLResponse,
)
async def get_red_hat_advisory(request: Request, advisory_name: str):
    if not request.state.settings.serve_rh_advisories:
        raise RenderErrorTemplateException()

    advisory = await RedHatAdvisory.get_or_none(
        name=advisory_name,
    ).prefetch_related(
        "packages",
        "cves",
        "bugzilla_tickets",
        "affected_products",
        "rpm_rh_overrides",
        "rpm_rh_overrides__supported_products_rh_mirror",
        "published_advisories",
    )
    if advisory is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": "Requested advisory not found",
            }
        )

    return templates.TemplateResponse(
        "red_hat_advisory.jinja", {
            "request": request,
            "advisory": advisory,
            "title": f"Red Hat Advisory {advisory.id}",
        }
    )


@router.post(
    "/advisories/{advisory_name}",
    response_class=HTMLResponse,
    dependencies=[Depends(admin_user_scheme)],
)
async def execute_red_hat_advisory_action(
    request: Request,
    advisory_name: str,
    action: str = Form(),
    data: str = Form()
):
    pass
