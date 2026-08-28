"""
OpenVEX-style export for Rocky CVE product statuses.

Only emits status documents — never package fix lists for not_shipped /
under_investigation. Fixed statuses reference the RLSA id when known.
Excluded from updateinfo by design (updateinfo stays package-fix only).
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from apollo.db import CveProductStatus, SupportedProduct

router = APIRouter(tags=["vex"])


class VexProductStatus(BaseModel):
    product_id: str
    product_name: str
    status: str
    reason: Optional[str] = None
    advisory_id: Optional[int] = None
    red_hat_advisory_id: Optional[int] = None


class VexDocument(BaseModel):
    """Minimal OpenVEX-inspired document for one CVE."""

    context: str = Field(
        default="https://openvex.dev/ns/v0.2.0",
        alias="@context",
    )
    id: str
    author: str = "Rocky Linux Apollo"
    version: int = 1
    statements: list[dict]

    class Config:
        allow_population_by_field_name = True


_STATUS_TO_VEX = {
    "fixed": "fixed",
    "not_shipped": "not_affected",
    "under_investigation": "under_investigation",
}


@router.get("/cves/{cve_id}", response_model=VexDocument)
async def vex_for_cve(cve_id: str):
    cve = cve_id.upper()
    if not cve.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="cve_id must look like CVE-YYYY-NNNN")

    rows = await CveProductStatus.filter(cve=cve).prefetch_related("supported_product")
    if not rows:
        raise HTTPException(status_code=404, detail=f"No VEX status for {cve}")

    statements = []
    for row in rows:
        product = row.supported_product
        vex_status = _STATUS_TO_VEX.get(row.status, row.status)
        statement = {
            "vulnerability": {"name": cve},
            "products": [
                {
                    "id": f"apollo:product:{row.supported_product_id}",
                    "name": product.name if product else str(row.supported_product_id),
                }
            ],
            "status": vex_status,
        }
        if row.reason:
            statement["status_notes"] = row.reason
        if row.status == "fixed" and row.advisory_id:
            statement["action_statement"] = f"Fixed in advisory_id={row.advisory_id}"
        # Explicitly no package URLs for not_shipped / under_investigation.
        statements.append(statement)

    return VexDocument(
        id=f"apollo:vex:{cve}",
        statements=statements,
    )


@router.get("/products/{product_name}")
async def vex_for_product(
    product_name: str,
    status: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
):
    """List VEX statement summaries for a supported product."""
    product = await SupportedProduct.filter(name=product_name).first()
    if not product:
        raise HTTPException(status_code=404, detail=f"Unknown product {product_name}")

    query = CveProductStatus.filter(supported_product_id=product.id)
    if status:
        query = query.filter(status=status)
    rows = await query.limit(limit).order_by("cve")

    return {
        "product": product.name,
        "total": await query.count(),
        "statements": [
            {
                "cve": row.cve,
                "status": _STATUS_TO_VEX.get(row.status, row.status),
                "reason": row.reason,
                "advisory_id": row.advisory_id if row.status == "fixed" else None,
            }
            for row in rows
        ],
    }
