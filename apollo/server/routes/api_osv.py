from typing import TypeVar, Generic, Optional

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from fastapi_pagination import create_page
from fastapi_pagination.links import Page
from pydantic import BaseModel
from slugify import slugify

from apollo.db import Advisory
from apollo.db.advisory import fetch_advisories
from apollo.rpmworker.repomd import EPOCH_RE, NEVRA_RE
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
    yum_repository: str


class OSVRange(BaseModel):
    type: str
    repo: Optional[str]
    events: list[OSVEvent]
    database_specific: Optional[OSVRangeDatabaseSpecific]


class OSVEcosystemSpecific(BaseModel):
    pass


class OSVAffectedDatabaseSpecific(BaseModel):
    pass


class OSVAffected(BaseModel):
    package: OSVPackage
    ranges: list[OSVRange]
    versions: Optional[list[str]]
    ecosystem_specific: Optional[OSVEcosystemSpecific]
    database_specific: Optional[OSVAffectedDatabaseSpecific]


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
    related: Optional[list[str]]
    summary: str
    details: str
    severity: Optional[list[OSVSeverity]]
    affected: list[OSVAffected]
    references: list[OSVReference]
    credits: list[OSVCredit]
    database_specific: Optional[OSVDatabaseSpecific]


def to_osv_advisory(ui_url: str, advisory: Advisory) -> OSVAdvisory:
    affected_pkgs = []

    vendors = []
    pkg_name_map = {}
    for pkg in advisory.packages:
        if pkg.supported_product.vendor not in vendors:
            vendors.append(pkg.supported_product.vendor)

        nevra = NEVRA_RE.search(pkg.nevra)
        name = nevra.group(1)
        arch = nevra.group(5).lower()

        product_name = slugify(pkg.product_name)
        if pkg.supported_products_rh_mirror:
            product_name = f"{pkg.supported_product.variant}:{pkg.supported_products_rh_mirror.match_major_version}"

        if product_name not in pkg_name_map:
            pkg_name_map[product_name] = {}
        if arch not in pkg_name_map[product_name]:
            pkg_name_map[product_name][arch] = {}
        if name not in pkg_name_map[product_name][arch]:
            pkg_name_map[product_name][arch][name] = []

        pkg_name_map[product_name][arch][name].append((pkg, nevra))

    processed_nvra = {}

    for product_name, arches in pkg_name_map.items():
        for _, affected_arches in arches.items():
            if not affected_arches:
                continue

            for pkg_name, affected_packages in affected_arches.items():
                for pkg in affected_packages:
                    x = pkg[0]
                    nevra = pkg[1]
                    # Only process "src" packages
                    if nevra.group(5) != "src":
                        continue
                    if x.nevra in processed_nvra:
                        continue
                    processed_nvra[x.nevra] = True

                    ver_rel = f"{nevra.group(3)}-{nevra.group(4)}"
                    slugified = slugify(x.supported_product.variant)
                    slugified_distro = slugify(x.product_name)
                    for arch_, _ in arches.items():
                        slugified_arch = f"-{slugify(arch_)}"
                        slugified_distro = slugified_distro.replace(
                            slugified_arch,
                            "",
                        )
                    epoch = nevra.group(2)

                    purl = f"pkg:rpm/{slugified}/{pkg_name}@{ver_rel}?distro={slugified_distro}&epoch={epoch}"

                    affected = OSVAffected(
                        package=OSVPackage(
                            ecosystem=product_name,
                            name=pkg_name,
                            purl=purl,
                        ),
                        ranges=[
                            OSVRange(
                                type="ECOSYSTEM",
                                events=[
                                    OSVEvent(introduced="0"),
                                    OSVEvent(fixed=ver_rel),
                                ],
                                database_specific=OSVRangeDatabaseSpecific(
                                    yum_repository=x.repo_name,
                                ),
                            )
                        ],
                        versions=None,
                        ecosystem_specific=None,
                        database_specific=None,
                    )

                    affected_pkgs.append(affected)

    references = [
        OSVReference(type="ADVISORY", url=f"{ui_url}/{advisory.name}"),
    ]
    for fix in advisory.fixes:
        references.append(OSVReference(type="REPORT", url=fix.source))

    osv_credits = [OSVCredit(name=x) for x in vendors]
    if advisory.red_hat_advisory:
        osv_credits.append(OSVCredit(name="Red Hat"))

    # Calculate severity by finding the highest CVSS score
    highest_cvss_base_score = 0.0
    final_score_vector = None
    for x in advisory.cves:
        # Convert cvss3_scoring_vector to a float
        base_score = x.cvss3_base_score
        if base_score and base_score != "UNKNOWN":
            base_score = float(base_score)
            if base_score > highest_cvss_base_score:
                highest_cvss_base_score = base_score
                final_score_vector = x.cvss3_scoring_vector

    severity = None
    if final_score_vector:
        severity = [OSVSeverity(type="CVSS_V3", score=final_score_vector)]

    return OSVAdvisory(
        id=advisory.name,
        modified=to_rfc3339_date(advisory.updated_at),
        published=to_rfc3339_date(advisory.published_at),
        withdrawn=None,
        aliases=[x.cve for x in advisory.cves],
        related=None,
        summary=advisory.synopsis,
        details=advisory.description,
        severity=severity,
        affected=affected_pkgs,
        references=references,
        credits=osv_credits,
        database_specific=None,
    )


@router.get("/", response_model=Pagination[OSVAdvisory], response_model_exclude_none=True)
async def get_advisories_osv(
    params: Params = Depends(),
    product: Optional[str] = None,
    before: Optional[str] = None,
    after: Optional[str] = None,
    cve: Optional[str] = None,
    synopsis: Optional[str] = None,
    keyword: Optional[str] = None,
    severity: Optional[str] = None,
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
        kind="Security",
        fetch_related=True,
    )
    count = fetch_adv[0]
    advisories = fetch_adv[1]

    ui_url = await get_setting(UI_URL)
    osv_advisories = [to_osv_advisory(ui_url, x) for x in advisories]
    return create_page(osv_advisories, count, params)


@router.get("/{advisory_id}", response_model=OSVAdvisory, response_model_exclude_none=True)
async def get_advisory_osv(advisory_id: str):
    advisory = await Advisory.filter(name=advisory_id, kind="Security").prefetch_related(
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
