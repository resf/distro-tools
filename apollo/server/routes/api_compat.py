"""
This module implements the compatibility API for Apollo V2 advisories
"""

import datetime
from typing import TypeVar, Generic, Optional

from tortoise import connections

from fastapi import APIRouter, Depends, Query
from fastapi.exceptions import HTTPException
from fastapi_pagination.links import Page
from fastapi_pagination import Params
from fastapi_pagination.ext.tortoise import create_page

from apollo.db import Advisory, RedHatIndexState
from apollo.db.serialize import Advisory_Pydantic_V2, Advisory_Pydantic_V2_CVE, Advisory_Pydantic_V2_Fix

from common.fastapi import RenderErrorTemplateException

router = APIRouter(tags=["v2_compat"])

T = TypeVar("T")


class Pagination(Page[T], Generic[T]):
    lastUpdated: Optional[str]  # noqa # pylint: disable=invalid-name

    class Config:
        allow_population_by_field_name = True
        fields = {"items": {"alias": "advisories"}}


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
        set(
            [
                f"{ap.variant} {ap.major_version}"
                for ap in advisory.affected_products
            ]
        )
    )

    cves = []
    for cve in advisory.cves:
        cves.append(
            Advisory_Pydantic_V2_CVE(
                name=cve.cve,
                cvss3ScoringVector=cve.cvss3_scoring_vector,
                cvss3BaseScore=cve.cvss3_base_score,
                cwe=cve.cwe,
                sourceBy="Red Hat",
                sourceLink=
                f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve.cve}.json",
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
            name = f"{pkg.supported_product.variant} {pkg.supported_products_rh_mirror.match_major_version}"
            if name not in rpms:
                rpms[name] = []
            rpms[name].append(pkg.nevra)

    return Advisory_Pydantic_V2(
        id=advisory.id,
        publishedAt=advisory.published_at,
        name=advisory.name,
        synopsis=advisory.synopsis,
        description=advisory.description,
        type=kind,
        severity=f"SEVERITY_{advisory.severity.upper()}",
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


@router.get(
    "/",
    response_model=Pagination[Advisory_Pydantic_V2],
)
async def list_advisories_compat_v2(
    params: Params = Depends(),
    product: str = Query(default=None, alias="filters.product"),
    before_raw: str = Query(default=None, alias="filters.before"),
    after_raw: str = Query(default=None, alias="filters.after"),
    cve: str = Query(default=None, alias="filters.cve"),
    synopsis: str = Query(default=None, alias="filters.synopsis"),
    keyword: str = Query(default=None, alias="filters.keyword"),
    severity: str = Query(default=None, alias="filters.severity"),
    kind: str = Query(default=None, alias="filters.type"),
):
    before = None
    after = None

    try:
        if before_raw:
            before = datetime.datetime.fromisoformat(
                before_raw.removesuffix("Z")
            )
    except:
        raise RenderErrorTemplateException("Invalid before date", 400)

    try:
        if after_raw:
            after = datetime.datetime.fromisoformat(after_raw.removesuffix("Z"))
    except:
        raise RenderErrorTemplateException("Invalid after date", 400)

    state = await RedHatIndexState.first()

    a = """
        with vars (search, size, page_offset, product, before, after, cve, synopsis, severity, kind) as (
            values ($1 :: text, $2 :: bigint, $3 :: bigint, $4 :: text, $5 :: timestamp, $6 :: timestamp, $7 :: text, $8 :: text, $9 :: text, $10 :: text)
        )
        select
            a.id,
            a.created_at,
            a.updated_at,
            a.published_at,
            a.name,
            a.synopsis,
            a.description,
            a.kind,
            a.severity,
            a.topic,
            a.red_hat_advisory_id,
            count(a.*) over () as total
        from
            advisories a
        left outer join advisory_affected_products ap on ap.advisory_id = a.id
        left outer join advisory_cves c on c.advisory_id = a.id
        left outer join advisory_fixes f on f.advisory_id = a.id
        where
            ((select product from vars) is null or ap.name ilike '%' || (select product from vars) || '%')
            and ((select before from vars) is null or a.published_at < (select before from vars))
            and ((select after from vars) is null or a.published_at > (select after from vars))
            and (a.published_at is not null)
            and ((select cve from vars) is null or exists (select cve from advisory_cves where advisory_id = a.id and cve ilike '%' || (select cve from vars) || '%'))
            and ((select synopsis from vars) is null or a.synopsis ilike '%' || (select synopsis from vars) || '%')
            and ((select severity from vars) is null or a.severity = (select severity from vars))
            and ((select kind from vars) is null or a.kind = (select kind from vars))
            and ((select search from vars) is null or
            ap.name ilike '%' || (select search from vars) || '%' or
            a.synopsis ilike '%' || (select search from vars) || '%' or
            a.description ilike '%' || (select search from vars) || '%' or
            exists (select cve from advisory_cves where advisory_id = a.id and cve ilike '%' || (select search from vars) || '%') or
            exists (select ticket_id from advisory_fixes where advisory_id = a.id and ticket_id ilike '%' || (select search from vars) || '%') or
            a.name ilike '%' || (select search from vars) || '%')
        group by a.id
        order by a.published_at desc
        limit (select size from vars) offset (select page_offset from vars)
        """

    connection = connections.get("default")
    results = await connection.execute_query(
        a, [
            keyword, params.size, params.size * (params.page - 1), product,
            before, after, cve, synopsis, severity, kind
        ]
    )

    count = 0
    if results:
        if results[1]:
            count = results[1][0]["total"]

    advisories = []
    for adv in results[1]:
        advisory = Advisory(**adv)
        await advisory.fetch_related(
            "packages",
            "cves",
            "fixes",
            "affected_products",
            "packages",
            "packages__supported_product",
            "packages__supported_products_rh_mirror",
        )
        advisories.append(advisory)

    v2_advisories: list[Advisory_Pydantic_V2] = []
    for advisory in advisories:
        v2_advisories.append(v3_advisory_to_v2(advisory))

    page = create_page(v2_advisories, count, params)
    page.lastUpdated = state.last_indexed_at.isoformat("T").replace(
        "+00:00", ""
    ) + "Z"

    return page


@router.get(
    "/{advisory_name}",
    response_model=Advisory_Pydantic_V2,
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

    return Advisory_Pydantic_V2.from_orm(v3_advisory_to_v2(advisory))
