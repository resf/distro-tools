from typing import TypeVar, Generic, Optional

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from fastapi_pagination import Params
from fastapi_pagination.links import Page
from fastapi_pagination.ext.tortoise import paginate

from apollo.db import Advisory
from apollo.db.serialize import Advisory_Pydantic
from apollo.db.advisory import fetch_advisories

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
async def list_advisories(
    params: Params = Depends(),
    product: Optional[str] = None,
    before_raw: Optional[str] = None,
    after_raw: Optional[str] = None,
    cve: Optional[str] = None,
    synopsis: Optional[str] = None,
    keyword: Optional[str] = None,
    severity: Optional[str] = None,
    kind: Optional[str] = None,
):
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
        "packages",
        "packages__supported_product",
        "packages__supported_products_rh_mirror",
    ).get_or_none()

    if advisory is None:
        raise HTTPException(404)

    return await Advisory_Pydantic.from_tortoise_orm(advisory)
