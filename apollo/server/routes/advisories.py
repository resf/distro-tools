from math import ceil

from tortoise import connections

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi_pagination import Params
from fastapi_pagination.ext.tortoise import paginate, create_page

from apollo.db import Advisory
from apollo.server.utils import templates

router = APIRouter(tags=["non-api"])


@router.get(
    "/",
    response_class=HTMLResponse,
)
async def list_advisories(
    request: Request,
    params: Params = Depends(),
    search: str = None,
):
    params.size = 50
    if search:
        a = """
        with vars (search, size, page_offset) as (
            values ($1 :: text, $2 :: bigint, $3 :: bigint)
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
            (select search from vars) is null or
            ap.name ilike '%' || (select search from vars) || '%' or
            a.synopsis ilike '%' || (select search from vars) || '%' or
            a.description ilike '%' || (select search from vars) || '%' or
            exists (select cve from advisory_cves where advisory_id = a.id and cve ilike '%' || (select search from vars) || '%') or
            exists (select ticket_id from advisory_fixes where advisory_id = a.id and ticket_id ilike '%' || (select search from vars) || '%') or
            a.name ilike '%' || (select search from vars) || '%'
        group by a.id
        order by a.published_at desc
        limit (select size from vars) offset (select page_offset from vars)
        """

        connection = connections.get("default")
        results = await connection.execute_query(
            a, [search, params.size, params.size * (params.page - 1)]
        )
        count = 0
        if results:
            if results[1]:
                count = results[1][0]["total"]

        advisories = create_page(
            results[1],
            count,
            params,
        )
    else:
        advisories = await paginate(
            Advisory.all().order_by("-published_at"),
            params=params,
        )
    return templates.TemplateResponse(
        "advisories.jinja", {
            "request": request,
            "params": params,
            "search": search if search else "",
            "advisories": advisories,
            "advisories_pages": ceil(advisories.total / advisories.size)
        }
    )


@router.get(
    "/{advisory_name}",
    response_class=HTMLResponse,
)
async def get_advisory(request: Request, advisory_name: str):
    advisory = await Advisory.get_or_none(name=advisory_name,
                                         ).prefetch_related(
                                             "red_hat_advisory",
                                             "packages",
                                             "cves",
                                             "fixes",
                                             "affected_products",
                                         )
    if advisory is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": "Requested advisory not found",
            }
        )

    package_map = {}
    for package in advisory.packages:
        name = f"{package.product_name} - {package.repo_name}"
        if name not in package_map:
            package_map[name] = []

        package_map[name].append(package.nevra)

    return templates.TemplateResponse(
        "advisory.jinja", {
            "request": request,
            "title": f"Advisory {advisory.id}",
            "advisory": advisory,
            "package_map": package_map,
        }
    )
