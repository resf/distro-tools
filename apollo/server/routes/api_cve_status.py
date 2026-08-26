"""CVE product status API (distro-tools#73 status surface)."""

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from apollo.db import CveProductStatus, SupportedProduct

router = APIRouter(tags=["cve-status"])


class CveStatusItem(BaseModel):
    cve: str
    status: str
    reason: Optional[str] = None
    supported_product_id: int
    supported_product_name: Optional[str] = None
    red_hat_advisory_id: Optional[int] = None
    advisory_id: Optional[int] = None
    updated_at: Optional[str] = None


class CveStatusResponse(BaseModel):
    cve: str
    statuses: list[CveStatusItem]


class CveStatusListResponse(BaseModel):
    total: int
    items: list[CveStatusItem]


def _serialize(row: CveProductStatus, product_name: Optional[str] = None) -> CveStatusItem:
    return CveStatusItem(
        cve=row.cve,
        status=row.status,
        reason=row.reason,
        supported_product_id=row.supported_product_id,
        supported_product_name=product_name,
        red_hat_advisory_id=row.red_hat_advisory_id,
        advisory_id=row.advisory_id,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


@router.get("/", response_model=CveStatusListResponse)
async def list_cve_statuses(
    cve: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    product: Optional[str] = Query(None, description="Supported product name"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List CVE product statuses with optional filters."""
    query = CveProductStatus.all().prefetch_related("supported_product")
    if cve:
        query = query.filter(cve=cve.upper())
    if status:
        query = query.filter(status=status)
    if product:
        sp = await SupportedProduct.filter(name=product).first()
        if not sp:
            raise HTTPException(status_code=404, detail=f"Unknown product {product}")
        query = query.filter(supported_product_id=sp.id)

    total = await query.count()
    rows = await query.offset(offset).limit(limit).order_by("cve")
    return CveStatusListResponse(
        total=total,
        items=[
            _serialize(row, row.supported_product.name if row.supported_product else None)
            for row in rows
        ],
    )


@router.get("/{cve_id}", response_model=CveStatusResponse)
async def get_cve_statuses(cve_id: str):
    """Return Rocky-facing statuses for a CVE across supported products."""
    cve = cve_id.upper()
    if not cve.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="cve_id must look like CVE-YYYY-NNNN")

    rows = await CveProductStatus.filter(cve=cve).prefetch_related("supported_product")
    if not rows:
        raise HTTPException(status_code=404, detail=f"No status rows for {cve}")

    return CveStatusResponse(
        cve=cve,
        statuses=[
            _serialize(row, row.supported_product.name if row.supported_product else None)
            for row in rows
        ],
    )
