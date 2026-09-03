"""
Classify Rocky-facing CVE product statuses for distro-tools#73.

Rules (per supported product + CVE):
  - fixed: an RLSA exists that lists the CVE
  - under_investigation: RHSA is uncloned but RhBlock is younger than 14 days
    (matcher may still retry)
  - not_shipped: RHSA is uncloned / blocked older than 14 days, and none of the
    RHSA package names appear on any RLSA package for that product

Never creates empty-package RLSAs or copies RH fixed NEVRAs as Rocky fixes.
"""

from __future__ import annotations

import datetime
import re

from temporalio import activity
from tortoise.transactions import in_transaction

from apollo.db import (
    AdvisoryCVE,
    AdvisoryPackage,
    CveProductStatus,
    RedHatAdvisory,
    SupportedProduct,
    SupportedProductsRhBlock,
    SupportedProductsRhMirror,
)
from apollo.rpm_helpers import parse_nevra
from common.logger import Logger

STATUS_FIXED = "fixed"
STATUS_NOT_SHIPPED = "not_shipped"
STATUS_UNDER_INVESTIGATION = "under_investigation"
REMATCH_WINDOW_DAYS = 14

_EPOCH_NEVRA_RE = re.compile(r"-([0-9]+):")


def package_name_from_nevra(nevra: str) -> str | None:
    """Extract RPM name from NEVRA, tolerating missing dist tags."""
    try:
        return parse_nevra(nevra)["name"]
    except ValueError:
        # Fall back: strip trailing .rpm and everything from epoch marker.
        raw = nevra.removesuffix(".rpm")
        if _EPOCH_NEVRA_RE.search(raw):
            return _EPOCH_NEVRA_RE.split(raw)[0]
        # name-ver-rel.arch
        parts = raw.rsplit(".", 1)
        if len(parts) != 2:
            return None
        nvr = parts[0]
        try:
            name = nvr.rsplit("-", 1)[0].rsplit("-", 1)[0]
            return name
        except ValueError:
            return None


_STATUS_PRIORITY = {
    STATUS_FIXED: 3,
    STATUS_UNDER_INVESTIGATION: 2,
    STATUS_NOT_SHIPPED: 1,
}


async def shipped_package_names_for_product(supported_product_id: int) -> set[str]:
    """Package names previously shipped via RLSAs for this product (proxy for Rocky repos)."""
    names: set[str] = set()
    rows = await AdvisoryPackage.filter(
        supported_product_id=supported_product_id
    ).values_list("_package_name", "nevra")
    for package_name, nevra in rows:
        if package_name:
            cleaned = AdvisoryPackage._clean_package_name(package_name)
            if cleaned:
                names.add(cleaned)
            continue
        extracted = package_name_from_nevra(nevra)
        if extracted:
            names.add(extracted)
    return names


async def classify_product_cve_statuses(supported_product_id: int) -> dict:
    """
    Materialize cve_product_statuses for one supported product.

    Returns counts: {fixed, not_shipped, under_investigation, upserted}.
    """
    logger = Logger()
    product = await SupportedProduct.filter(id=supported_product_id).first()
    if not product:
        logger.warning("Supported product %s not found", supported_product_id)
        return {"fixed": 0, "not_shipped": 0, "under_investigation": 0, "upserted": 0}

    mirrors = await SupportedProductsRhMirror.filter(
        supported_product_id=supported_product_id,
        active=True,
    )
    mirror_ids = [m.id for m in mirrors]
    majors = {int(m.match_major_version) for m in mirrors}

    # CVEs already fixed on an RLSA for this product (via affected products).
    fixed_cves: dict[str, int] = {}
    fixed_rows = await AdvisoryCVE.filter(
        advisory__affected_products__supported_product_id=supported_product_id
    ).prefetch_related("advisory")
    for row in fixed_rows:
        fixed_cves[row.cve] = row.advisory_id

    shipped_names = await shipped_package_names_for_product(supported_product_id)

    # Recent blocks: still within rematch window.
    now = datetime.datetime.now(datetime.timezone.utc)
    recent_blocked_rh_ids: set[int] = set()
    if mirror_ids:
        blocks = await SupportedProductsRhBlock.filter(
            supported_products_rh_mirror_id__in=mirror_ids
        )
        for block in blocks:
            age = now - block.created_at
            if age.days < REMATCH_WINDOW_DAYS:
                recent_blocked_rh_ids.add(block.red_hat_advisory_id)

    # Uncloned RHSAs that affect this product's majors.
    candidate_rhsas = await RedHatAdvisory.filter(
        name__startswith="RHSA-",
        affected_products__major_version__in=list(majors) if majors else [-1],
    ).prefetch_related("packages", "cves", "published_advisories")

    counts = {
        STATUS_FIXED: 0,
        STATUS_NOT_SHIPPED: 0,
        STATUS_UNDER_INVESTIGATION: 0,
        "upserted": 0,
    }
    # Deduplicate by CVE; prefer fixed > under_investigation > not_shipped.
    by_cve: dict[str, CveProductStatus] = {}

    def _consider(row: CveProductStatus) -> None:
        existing = by_cve.get(row.cve)
        if existing is None:
            by_cve[row.cve] = row
            return
        if _STATUS_PRIORITY.get(row.status, 0) > _STATUS_PRIORITY.get(
            existing.status, 0
        ):
            by_cve[row.cve] = row

    # Always record fixed CVEs first.
    for cve, advisory_id in fixed_cves.items():
        _consider(
            CveProductStatus(
                cve=cve,
                supported_product_id=supported_product_id,
                status=STATUS_FIXED,
                reason="RLSA exists for this supported product",
                advisory_id=advisory_id,
                red_hat_advisory_id=None,
            )
        )

    for rhsa in candidate_rhsas:
        if rhsa.published_advisories:
            # Cloned somewhere; fixed path already covers product-scoped RLSAs.
            continue
        if not rhsa.cves:
            continue

        pkg_names = set()
        for pkg in rhsa.packages:
            name = package_name_from_nevra(pkg.nevra)
            if name:
                pkg_names.add(name)

        any_shipped = bool(pkg_names & shipped_names)
        if rhsa.id in recent_blocked_rh_ids or any_shipped:
            status = STATUS_UNDER_INVESTIGATION
            reason = (
                "Uncloned RHSA still within rematch window or packages are shipped"
            )
        else:
            status = STATUS_NOT_SHIPPED
            reason = (
                "No Rocky RLSA and no shipped package name overlap for this product"
            )

        for cve_row in rhsa.cves:
            if cve_row.cve in fixed_cves:
                continue
            _consider(
                CveProductStatus(
                    cve=cve_row.cve,
                    supported_product_id=supported_product_id,
                    status=status,
                    reason=reason,
                    red_hat_advisory_id=rhsa.id,
                    advisory_id=None,
                )
            )

    for row in by_cve.values():
        counts[row.status] += 1

    async with in_transaction():
        # Per-row SELECT+save is fine for infrequent Temporal runs; switch to
        # bulk INSERT ... ON CONFLICT if classify of ~12k CVEs/product is slow.
        for row in by_cve.values():
            existing = await CveProductStatus.filter(
                cve=row.cve,
                supported_product_id=supported_product_id,
            ).first()
            if existing:
                # Prefer fixed over other statuses; never downgrade fixed.
                if existing.status == STATUS_FIXED and row.status != STATUS_FIXED:
                    continue
                if (
                    row.status != STATUS_FIXED
                    and _STATUS_PRIORITY.get(row.status, 0)
                    < _STATUS_PRIORITY.get(existing.status, 0)
                ):
                    continue
                existing.status = row.status
                existing.reason = row.reason
                existing.red_hat_advisory_id = row.red_hat_advisory_id
                existing.advisory_id = row.advisory_id
                await existing.save()
            else:
                await row.save()
            counts["upserted"] += 1

    logger.info(
        "CVE status classify product=%s fixed=%s not_shipped=%s under_investigation=%s upserted=%s",
        supported_product_id,
        counts[STATUS_FIXED],
        counts[STATUS_NOT_SHIPPED],
        counts[STATUS_UNDER_INVESTIGATION],
        counts["upserted"],
    )
    return counts


@activity.defn
async def classify_cve_statuses_for_product(supported_product_id: int) -> dict:
    return await classify_product_cve_statuses(supported_product_id)


@activity.defn
async def classify_cve_statuses_all_products() -> dict:
    products = await SupportedProduct.all()
    totals = {
        STATUS_FIXED: 0,
        STATUS_NOT_SHIPPED: 0,
        STATUS_UNDER_INVESTIGATION: 0,
        "upserted": 0,
        "products": 0,
    }
    for product in products:
        counts = await classify_product_cve_statuses(product.id)
        for key in (
            STATUS_FIXED,
            STATUS_NOT_SHIPPED,
            STATUS_UNDER_INVESTIGATION,
            "upserted",
        ):
            totals[key] += counts[key]
        totals["products"] += 1
    return totals
