from typing import TypeVar, Generic, Optional

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from fastapi_pagination import create_page
from fastapi_pagination.links import Page
from pydantic import BaseModel
from slugify import slugify

from apollo.db import Advisory
from apollo.db.advisory import fetch_advisories
from apollo.rpmworker.repomd import EPOCH_RE, NVRA_RE
from apollo.server.settings import UI_URL, get_setting

from common.fastapi import Params, to_rfc3339_date

router = APIRouter(tags=["osv"])

T = TypeVar("T")


class Pagination(Page[T], Generic[T]):
    class Config:
        allow_population_by_field_name = True
        fields = {"items": {"alias": "advisories"}}


class OSVSeverity(BaseModel):
    type: str
    score: str


class OSVPackage(BaseModel):
    ecosystem: str
    name: str
    purl: Optional[str] = None


class OSVEvent(BaseModel):
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    last_affected: Optional[str] = None
    limit: Optional[str] = None


class OSVRangeDatabaseSpecific(BaseModel):
    pass


class OSVRange(BaseModel):
    type: str
    repo: str
    events: list[OSVEvent]
    database_specific: OSVRangeDatabaseSpecific


class OSVEcosystemSpecific(BaseModel):
    pass


class OSVAffectedDatabaseSpecific(BaseModel):
    pass


class OSVAffected(BaseModel):
    package: OSVPackage
    ranges: list[OSVRange]
    versions: list[str]
    ecosystem_specific: OSVEcosystemSpecific
    database_specific: OSVAffectedDatabaseSpecific


class OSVReference(BaseModel):
    type: str
    url: str


class OSVCredit(BaseModel):
    name: str
    contact: list[str] = None


class OSVDatabaseSpecific(BaseModel):
    pass


class OSVAdvisory(BaseModel):
    schema_version: str = "1.3.1"
    id: str
    modified: str
    published: str
    withdrawn: Optional[str]
    aliases: list[str]
    related: list[str]
    summary: str
    details: str
    severity: list[OSVSeverity]
    affected: list[OSVAffected]
    references: list[OSVReference]
    credits: list[OSVCredit]
    database_specific: OSVDatabaseSpecific


def to_osv_advisory(ui_url: str, advisory: Advisory) -> OSVAdvisory:
    affected_pkgs = []

    pkg_name_map = {}
    for pkg in advisory.packages:
        product_name = slugify(pkg.product_name)
        if pkg.supported_products_rh_mirror:
            product_name = f"{slugify(pkg.supported_product.variant)}:{pkg.supported_products_rh_mirror.match_major_version}"

        if product_name not in pkg_name_map:
            pkg_name_map[product_name] = {}
        if pkg.package_name not in pkg_name_map[product_name]:
            pkg_name_map[product_name][pkg.package_name] = []

        pkg_name_map[product_name][pkg.package_name].append(pkg)

    vendors = []
    for product_name, pkgs in pkg_name_map.items():
        for pkg_name, affected_packages in pkgs.items():
            if not affected_packages:
                continue

            first_pkg = None
            noarch_pkg = None
            arch = None
            nvra = None
            ver_rel = None
            for x in affected_packages:
                if x.supported_product.vendor not in vendors:
                    vendors.append(x.supported_product.vendor)
                nvra = NVRA_RE.search(EPOCH_RE.sub("", x.nevra))
                if not nvra:
                    continue
                ver_rel = f"{nvra.group(2)}-{nvra.group(3)}"
                if x.supported_products_rh_mirror:
                    first_pkg = x
                    arch = x.supported_products_rh_mirror.match_arch
                    break
                arch = nvra.group(4).lower()

                if arch == "src":
                    continue

                if arch == "noarch":
                    noarch_pkg = x
                    continue

                first_pkg = x
                break

            if not first_pkg and noarch_pkg:
                first_pkg = noarch_pkg

            if not ver_rel:
                continue

            purl = None
            if first_pkg:
                slugified = slugify(first_pkg.supported_product.variant)
                slugified_distro = slugify(first_pkg.product_name)
                slugified_distro = slugified_distro.replace(
                    f"-{slugify(arch)}",
                    "",
                )

                purl = f"pkg:rpm/{slugified}/{pkg_name}@{ver_rel}?arch={arch}&distro={slugified_distro}"
            affected = OSVAffected(
                package=OSVPackage(
                    ecosystem=product_name,
                    name=pkg_name,
                    purl=purl,
                ),
                ranges=[],
                versions=[],
                ecosystem_specific=OSVEcosystemSpecific(),
                database_specific=OSVAffectedDatabaseSpecific(),
            )
            for x in affected_packages:
                ranges = [
                    OSVRange(
                        type="ECOSYSTEM",
                        repo=x.repo_name,
                        events=[
                            OSVEvent(introduced="0"),
                            OSVEvent(fixed=ver_rel),
                        ],
                        database_specific=OSVRangeDatabaseSpecific(),
                    )
                ]
                affected.ranges.extend(ranges)

            affected_pkgs.append(affected)

    references = [
        OSVReference(type="ADVISORY", url=f"{ui_url}/{advisory.name}"),
    ]
    for fix in advisory.fixes:
        references.append(OSVReference(type="REPORT", url=fix.source))

    osv_credits = [OSVCredit(name=x) for x in vendors]
    if advisory.red_hat_advisory:
        osv_credits.append(OSVCredit(name="Red Hat"))

    return OSVAdvisory(
        id=advisory.name,
        modified=to_rfc3339_date(advisory.updated_at),
        published=to_rfc3339_date(advisory.published_at),
        withdrawn=None,
        aliases=[x.cve for x in advisory.cves],
        related=[],
        summary=advisory.synopsis,
        details=advisory.description,
        severity=[
            OSVSeverity(type="CVSS_V3", score=x.cvss3_scoring_vector)
            for x in advisory.cves
        ],
        affected=affected_pkgs,
        references=references,
        credits=osv_credits,
        database_specific=OSVDatabaseSpecific(),
    )


@router.get("/", response_model=Pagination[OSVAdvisory])
async def get_advisories_osv(
    params: Params = Depends(),
    product: Optional[str] = None,
    before: Optional[str] = None,
    after: Optional[str] = None,
    cve: Optional[str] = None,
    synopsis: Optional[str] = None,
    keyword: Optional[str] = None,
    severity: Optional[str] = None,
    kind: Optional[str] = None,
):
    fetch_adv = await fetch_advisories(
        params.get_size(),
        params.get_offset(),
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
    count = fetch_adv[0]
    advisories = fetch_adv[1]

    ui_url = await get_setting(UI_URL)
    osv_advisories = [to_osv_advisory(ui_url, x) for x in advisories]
    return create_page(osv_advisories, count, params)


@router.get("/{advisory_id}", response_model=OSVAdvisory)
async def get_advisory_osv(advisory_id: str):
    advisory = await Advisory.filter(name=advisory_id).prefetch_related(
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

    ui_url = await get_setting(UI_URL)
    return to_osv_advisory(ui_url, advisory)
