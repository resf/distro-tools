from typing import TypeVar, Generic, Optional

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from fastapi_pagination import Params
from fastapi_pagination.links import Page
from fastapi_pagination.ext.tortoise import create_page

from apollo.db import Advisory, RedHatIndexState
from apollo.db.serialize import (
    Advisory_Pydantic,
    Advisory_Pydantic_V2_Source,
    Advisory_Pydantic_WithSource,
)
from apollo.server import attribution

router = APIRouter(tags=["advisories"])

T = TypeVar("T")


class Pagination(Page[T], Generic[T]):
    last_updated_at: Optional[str]

    class Config:
        allow_population_by_field_name = True
        fields = {"items": {"alias": "advisories"}}


def _advisory_source(advisory: Advisory) -> Optional[Advisory_Pydantic_V2_Source]:
    if not advisory.red_hat_advisory_id:
        return None
    return Advisory_Pydantic_V2_Source(
        **attribution.source_fields(advisory.red_hat_advisory.name)
    )


async def _advisory_with_source(advisory: Advisory) -> Advisory_Pydantic_WithSource:
    base = await Advisory_Pydantic.from_tortoise_orm(advisory)
    return Advisory_Pydantic_WithSource(
        **base.dict(), source=_advisory_source(advisory)
    )


@router.get(
    "/",
    response_model=Pagination[Advisory_Pydantic_WithSource],
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
    query = Advisory.all().prefetch_related(
        "red_hat_advisory",
        "packages",
        "cves",
        "fixes",
        "affected_products",
    ).order_by("-published_at")

    total = await query.count()
    page_orm = await query.offset(params.size * (params.page - 1)).limit(params.size)
    items = [await _advisory_with_source(adv) for adv in page_orm]
    advisories = create_page(items, total, params)

    state = await RedHatIndexState.first()
    advisories.last_updated_at = state.last_indexed_at.isoformat("T").replace(
        "+00:00",
        "",
    ) + "Z"

    return advisories


@router.get(
    "/{advisory_name}",
    response_model=Advisory_Pydantic_WithSource,
)
async def get_advisory(advisory_name: str):
    advisory = await Advisory.filter(name=advisory_name).prefetch_related(
        "red_hat_advisory",
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

    return await _advisory_with_source(advisory)
