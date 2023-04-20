import datetime
from typing import Optional

from tortoise import connections

from apollo.db import Advisory


async def fetch_advisories(
    size: int,
    page_offset: int,
    keyword: Optional[str],
    product: Optional[str],
    before: Optional[datetime.datetime],
    after: Optional[datetime.datetime],
    cve: Optional[str],
    synopsis: Optional[str],
    severity: Optional[str],
    kind: Optional[str],
    fetch_related: bool = False,
) -> tuple[int, list[Advisory]]:
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
            a.published_at is not null
"""

    where_stmt = ""

    if product:
        where_stmt += """
            and exists (select name from advisory_affected_products where advisory_id = a.id and name like '%' || (select product from vars) || '%')
        """

    if before:
        where_stmt += """
            and a.published_at < (select before from vars)
        """

    if after:
        where_stmt += """
            and a.published_at > (select after from vars)
        """

    if cve:
        where_stmt += """
            and exists (select cve from advisory_cves where advisory_id = a.id and cve ilike '%' || (select cve from vars) || '%')
        """

    if synopsis:
        where_stmt += """
            and a.synopsis ilike '%' || (select synopsis from vars) || '%'
        """

    if severity:
        where_stmt += """
            and a.severity = (select severity from vars)
        """

    if kind:
        where_stmt += """
            and a.kind = (select kind from vars)
        """

    if keyword:
        where_stmt += """
            and (ap.name like '%' || (select search from vars) || '%' or
            a.synopsis ilike '%' || (select search from vars) || '%' or
            a.description ilike '%' || (select search from vars) || '%' or
            exists (select cve from advisory_cves where advisory_id = a.id and cve ilike '%' || (select search from vars) || '%') or
            exists (select ticket_id from advisory_fixes where advisory_id = a.id and ticket_id ilike '%' || (select search from vars) || '%') or
            a.name ilike '%' || (select search from vars) || '%')
        """

    a += where_stmt
    a += """
        group by a.id
        order by a.published_at desc
        limit (select size from vars) offset (select page_offset from vars)
    """

    connection = connections.get("default")
    results = await connection.execute_query(
        a, [
            keyword,
            size,
            page_offset,
            product,
            before,
            after,
            cve,
            synopsis,
            severity,
            kind,
        ]
    )

    count = 0
    if results:
        if results[1]:
            count = results[1][0]["total"]

    advisories = [Advisory(**x) for x in results[1]]
    if fetch_related:
        for advisory in advisories:
            await advisory.fetch_related(
                "packages",
                "cves",
                "fixes",
                "affected_products",
                "packages",
                "packages__supported_product",
                "packages__supported_products_rh_mirror",
            )
    return (
        count,
        advisories,
    )
