from typing import TypeVar, Generic

from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from fastapi_pagination.links import Page
from fastapi_pagination.ext.tortoise import paginate

from apollo.db import RedHatAdvisory
from apollo.db.serialize import RedHatAdvisory_Pydantic

router = APIRouter(tags=["red_hat"])

T = TypeVar("T")


class Pagination(Page[T], Generic[T]):
    class Config:
        allow_population_by_field_name = True
        fields = {"items": {"alias": "advisories"}}


@router.get(
    "/advisories",
    response_model=Pagination[RedHatAdvisory_Pydantic],
)
async def list_red_hat_advisories(request: Request):
    if not request.state.settings.serve_rh_advisories:
        raise HTTPException(404)

    advisories = await paginate(
        RedHatAdvisory.all().prefetch_related(
            "packages",
            "cves",
            "bugzilla_tickets",
            "affected_products",
        ).order_by("-red_hat_issued_at")
    )
    return advisories


@router.get(
    "/advisories/{advisory_name}",
    response_model=RedHatAdvisory_Pydantic,
)
async def get_red_hat_advisory(request: Request, advisory_name: str):
    if not request.state.settings.serve_rh_advisories:
        raise HTTPException(404)

    advisory = await RedHatAdvisory.filter(name=advisory_name).prefetch_related(
        "packages",
        "cves",
        "bugzilla_tickets",
        "affected_products",
    ).first()

    if advisory is None:
        raise HTTPException(404)

    return RedHatAdvisory_Pydantic.from_orm(advisory)
