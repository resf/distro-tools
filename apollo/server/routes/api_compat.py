"""
This module implements the compatibility API for Apollo V2 advisories
"""

import datetime
from typing import TypeVar, Generic, Optional, Any, Sequence

from fastapi import APIRouter, Depends, Query, Response
from fastapi.exceptions import HTTPException
from fastapi_pagination import pagination_ctx
from fastapi_pagination.bases import BasePage
from fastapi_pagination.default import Page
from fastapi_pagination.types import GreaterEqualOne, GreaterEqualZero
from fastapi_pagination.ext.tortoise import create_page

from pydantic import BaseModel

from rssgen.feed import RssGenerator

from apollo.db import Advisory, RedHatIndexState
from apollo.db.advisory import fetch_advisories
from apollo.db.serialize import Advisory_Pydantic_V2, Advisory_Pydantic_V2_CVE, Advisory_Pydantic_V2_Fix, Advisory_Pydantic_V2_RPMs
from apollo.server.settings import UI_URL, COMPANY_NAME, MANAGING_EDITOR, get_setting

from common.fastapi import RenderErrorTemplateException, parse_rfc3339_date

router = APIRouter(tags=["v2_compat"])

T = TypeVar("T")


class CompatParams(BaseModel):
    page: int = Query(0, ge=0, description="Page number")
    limit: int = Query(20, ge=1, le=100, description="Page size")

    def get_offset(self) -> int:
        print(self.limit * self.page)
        return self.limit * self.page

    def get_size(self) -> int:
        return self.limit


class Pagination(BasePage[T], Generic[T]):
    lastUpdated: Optional[str]  # noqa # pylint: disable=invalid-name

    page: GreaterEqualZero
    size: GreaterEqualOne

    __params_type__ = CompatParams

    @classmethod
    def create(
        cls,
        items: Sequence[T],
        params: CompatParams,
        *,
        total: Optional[int] = None,
        **kwargs: Any,
    ) -> Page[T]:
        if not isinstance(params, CompatParams):
            raise ValueError("Pagination should be used with CompatParams")

        return cls(
            total=total,
            items=items,
            page=params.page,
            size=params.limit,
            **kwargs,
        )

    class Config:
        allow_population_by_field_name = True
        fields = {"items": {"alias": "advisories"}}


class AdvisoryResponse(BaseModel):
    advisory: Advisory_Pydantic_V2


def v3_advisory_to_v2(
    advisory: Advisory,
    include_rpms=True,
) -> Advisory_Pydantic_V2:
    kind = "TYPE_SECURITY"
    if advisory.kind == "Bug Fix":
        kind = "TYPE_BUGFIX"
    elif advisory.kind == "Enhancement":
        kind = "TYPE_ENHANCEMENT"

    affected_products = list(
        {
            f"{ap.variant} {ap.major_version}"
            for ap in advisory.affected_products
        }
    )

    cves = []
    for cve in advisory.cves:
        cves.append(
            Advisory_Pydantic_V2_CVE(
                name=cve.cve,
                cvss3ScoringVector=cve.cvss3_scoring_vector,
                cvss3BaseScore=cve.cvss3_base_score,
                cwe=cve.cwe,
                sourceBy="MITRE",
                sourceLink=
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.cve}",
            )
        )

    fixes = []
    for fix in advisory.fixes:
        fixes.append(
            Advisory_Pydantic_V2_Fix(
                ticket=fix.ticket_id,
                sourceBy="Red Hat",
                sourceLink=fix.source,
                description=fix.description,
            )
        )

    rpms = {}
    if include_rpms:
        for pkg in advisory.packages:
            name = f"{pkg.supported_product.name} {pkg.supported_products_rh_mirror.match_major_version}"
            if name not in rpms:
                rpms[name] = Advisory_Pydantic_V2_RPMs(nvras=[])
            if pkg.nevra not in rpms[name].nvras:
                rpms[name].nvras.append(pkg.nevra)

    published_at = advisory.published_at.isoformat("T"
                                                  ).replace("+00:00", "") + "Z"
    severity = advisory.severity.upper()
    if severity == "NONE":
        severity = "UNKNOWN"

    return Advisory_Pydantic_V2(
        id=advisory.id,
        publishedAt=published_at,
        name=advisory.name,
        synopsis=advisory.synopsis,
        description=advisory.description,
        type=kind,
        severity=f"SEVERITY_{severity}",
        shortCode=advisory.name[0:2],
        topic=advisory.topic if advisory.topic else "",
        solution=None,
        rpms=rpms,
        affectedProducts=affected_products,
        references=[],
        rebootSuggested=False,
        buildReferences=[],
        fixes=fixes,
        cves=cves,
    )


async def fetch_advisories_compat(
    params: CompatParams,
    product: Optional[str] = None,
    before_raw: Optional[str] = None,
    after_raw: Optional[str] = None,
    cve: Optional[str] = None,
    synopsis: Optional[str] = None,
    keyword: Optional[str] = None,
    severity: Optional[str] = None,
    kind: Optional[str] = None,
):
    before = None
    after = None
    if before_raw:
        before = parse_rfc3339_date(before_raw)
        if not before:
            raise RenderErrorTemplateException("Invalid before date", 400)  # noqa # pylint: disable=raise-missing-from
    if after_raw:
        after = parse_rfc3339_date(after_raw)
        if not after:
            raise RenderErrorTemplateException("Invalid after date", 400)  # noqa # pylint: disable=raise-missing-from

    q_kind = kind
    if q_kind:
        if q_kind == "TYPE_BUGFIX":
            q_kind = "Bug Fix"
        elif q_kind == "TYPE_ENHANCEMENT":
            q_kind = "Enhancement"
        elif q_kind == "TYPE_SECURITY":
            q_kind = "Security"

    q_severity = severity
    if q_severity:
        if q_severity == "SEVERITY_LOW":
            q_severity = "Low"
        elif q_severity == "SEVERITY_MEDIUM":
            q_severity = "Moderate"
        elif q_severity == "SEVERITY_IMPORTANT":
            q_severity = "Important"
        elif q_severity == "SEVERITY_CRITICAL":
            q_severity = "Critical"

    return await fetch_advisories(
        params.get_size(),
        params.get_offset(),
        keyword,
        product,
        before,
        after,
        cve,
        synopsis,
        q_severity,
        q_kind,
        fetch_related=True,
    )


@router.get(
    "",
    response_model=Pagination[Advisory_Pydantic_V2],
    dependencies=[
        Depends(pagination_ctx(Pagination[Advisory_Pydantic_V2], CompatParams))
    ]
)
async def list_advisories_compat_v2(
    params: CompatParams = Depends(),
    product: str = Query(default=None, alias="filters.product"),
    before_raw: str = Query(default=None, alias="filters.before"),
    after_raw: str = Query(default=None, alias="filters.after"),
    cve: str = Query(default=None, alias="filters.cve"),
    synopsis: str = Query(default=None, alias="filters.synopsis"),
    keyword: str = Query(default=None, alias="filters.keyword"),
    severity: str = Query(default=None, alias="filters.severity"),
    kind: str = Query(default=None, alias="filters.type"),
):
    state = await RedHatIndexState.first()

    fetch_adv = await fetch_advisories_compat(
        params,
        product,
        before_raw,
        after_raw,
        cve,
        synopsis,
        keyword,
        severity,
        kind,
    )
    count = fetch_adv[0]
    advisories = fetch_adv[1]

    v2_advisories: list[Advisory_Pydantic_V2] = [
        v3_advisory_to_v2(x) for x in advisories
    ]

    page = create_page(v2_advisories, count, params)
    page.lastUpdated = state.last_indexed_at.isoformat("T").replace(
        "+00:00",
        "",
    ) + "Z"

    return page


@router.get(":rss")
async def list_advisories_compat_v2_rss(
    params: CompatParams = Depends(),
    product: str = Query(default=None, alias="filters.product"),
    before_raw: str = Query(default=None, alias="filters.before"),
    after_raw: str = Query(default=None, alias="filters.after"),
    cve: str = Query(default=None, alias="filters.cve"),
    synopsis: str = Query(default=None, alias="filters.synopsis"),
    keyword: str = Query(default=None, alias="filters.keyword"),
    severity: str = Query(default=None, alias="filters.severity"),
    kind: str = Query(default=None, alias="filters.type"),
):
    fetch_adv = await fetch_advisories_compat(
        params,
        product,
        before_raw,
        after_raw,
        cve,
        synopsis,
        keyword,
        severity,
        kind,
    )
    count = fetch_adv[0]
    advisories = fetch_adv[1]
    advisories.reverse()

    ui_url = await get_setting(UI_URL)
    company_name = await get_setting(COMPANY_NAME)
    managing_editor = await get_setting(MANAGING_EDITOR)

    fg = RssGenerator()
    fg.title(f"{company_name} Errata Feed")
    fg.link(href=ui_url, rel="alternate")
    fg.language("en")
    fg.description(f"Advisories issued by {company_name}")
    fg.copyright(
        f"(C) {company_name} {datetime.datetime.now().year}. All rights reserved. CVE sources are copyright of their respective owners."
    )
    fg.managingEditor(f"{managing_editor} ({company_name})")

    if count != 0:
        fg.pubDate(advisories[0].published_at)
        fg.lastBuildDate(advisories[0].published_at)

    for advisory in advisories:
        fe = fg.add_entry()
        fe.title(f"{advisory.name}: {advisory.synopsis}")
        fe.link(href=f"{ui_url}/{advisory.name}", rel="alternate")
        fe.description(advisory.topic)
        fe.id(str(advisory.id))
        fe.pubDate(advisory.published_at)

    return Response(content=fg.rss_str(), media_type="application/xml")


@router.get(
    "/{advisory_name}",
    response_model=AdvisoryResponse,
)
async def get_advisory_compat_v2(advisory_name: str):
    advisory = await Advisory.filter(name=advisory_name).prefetch_related(
        "packages",
        "cves",
        "fixes",
        "affected_products",
        "packages",
        "packages__supported_product",
        "packages__supported_products_rh_mirror",
    ).get_or_none()

    if not advisory:
        raise HTTPException(404)

    return AdvisoryResponse(
        advisory=Advisory_Pydantic_V2.from_orm(v3_advisory_to_v2(advisory))
    )
