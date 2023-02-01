from typing import TypeVar, Generic

from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from fastapi_pagination.links import Page
from fastapi_pagination.ext.tortoise import paginate

from apollo.db import Advisory
from apollo.db.serialize import Advisory_Pydantic

router = APIRouter(tags=["advisories"])

T = TypeVar("T")


class Pagination(Page[T], Generic[T]):
    class Config:
        allow_population_by_field_name = True
        fields = {"items": {"alias": "advisories"}}


@router.get(
    "/",
    response_model=Pagination[Advisory_Pydantic],
)
async def list_advisories():
    advisories = await paginate(
        Advisory.all().prefetch_related(
            "red_hat_advisory",
            "packages",
            "cves",
            "fixes",
            "affected_products",
        ).order_by("-published_at"),
    )

    return advisories


@router.get(
    "/{advisory_name}",
    response_model=Advisory_Pydantic,
)
async def get_advisory(advisory_name: str):
    advisory = await Advisory.filter(name=advisory_name).prefetch_related(
        "packages",
        "cves",
        "fixes",
        "affected_products",
        "red_hat_advisory",
    ).first()

    if advisory is None:
        raise HTTPException(404)

    return await Advisory_Pydantic.from_tortoise_orm(advisory)
