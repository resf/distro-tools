import datetime
from typing import TypeVar, Generic, Optional

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from fastapi_pagination import Params
from fastapi_pagination.links import Page
from fastapi_pagination.ext.tortoise import create_page

from apollo.db import Advisory, RedHatIndexState
from apollo.db.advisory import fetch_advisories
from apollo.db.serialize import (
    Advisory_Pydantic,
    Advisory_Pydantic_V2_Source,
    Advisory_Pydantic_WithSource,
)
from apollo.server import attribution
from common.fastapi import parse_rfc3339_date

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


def _parse_list_date(raw: Optional[str], field: str) -> Optional[datetime.datetime]:
    """Parse before_raw/after_raw. Invalid values are 400, matching v2 compat."""
    if raw is None:
        return None
    parsed = parse_rfc3339_date(raw)
    if parsed is None:
        raise HTTPException(status_code=400, detail=f"Invalid {field} date")
    return parsed


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
    before = _parse_list_date(before_raw, "before")
    after = _parse_list_date(after_raw, "after")

    # Honor cve/keyword/product/etc. The previous Advisory.all() path ignored
    # every filter query param (distro-tools#38). OSV already uses this helper,
    # which also omits unpublished rows (published_at IS NOT NULL).
    total, page_orm = await fetch_advisories(
        params.size,
        params.size * (params.page - 1),
        keyword,
        product,
        before,
        after,
        cve,
        synopsis,
        severity,
        kind,
        fetch_related=True,
    )
    items = [await _advisory_with_source(adv) for adv in page_orm]
    advisories = create_page(items, total, params)

    state = await RedHatIndexState.first()
    if state and state.last_indexed_at:
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
