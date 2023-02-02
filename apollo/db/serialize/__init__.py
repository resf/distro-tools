import datetime
from typing import Optional

from tortoise.contrib.pydantic import pydantic_model_creator, pydantic_queryset_creator
from pydantic import BaseModel

from apollo import db

RedHatAdvisoryCVE_Pydantic = pydantic_model_creator(
    db.RedHatAdvisoryCVE,
    name="RedHatAdvisoryCVE",
)
RedHatAdvisoryBugzillaBug_Pydantic = pydantic_model_creator(
    db.RedHatAdvisoryBugzillaBug,
    name="RedHatAdvisoryBugzillaBug",
)
RedHatAdvisoryAffectedProduct_Pydantic = pydantic_model_creator(
    db.RedHatAdvisoryAffectedProduct,
    name="RedHatAdvisoryAffectedProduct",
)
RedHatAdvisoryPackage_Pydantic = pydantic_model_creator(
    db.RedHatAdvisoryPackage,
    name="RedHatAdvisoryPackage",
)
RedHatAdvisory_Pydantic = pydantic_model_creator(
    db.RedHatAdvisory,
    name="RedHatAdvisory",
)

AdvisoryCVE_Pydantic = pydantic_model_creator(
    db.AdvisoryCVE,
    name="AdvisoryCVE",
)
AdvisoryFix_Pydantic = pydantic_model_creator(
    db.AdvisoryFix,
    name="AdvisoryFix",
)
AdvisoryAffectedProduct_Pydantic = pydantic_model_creator(
    db.AdvisoryAffectedProduct,
    name="AdvisoryAffectedProduct",
)
AdvisoryPackage_Pydantic = pydantic_model_creator(
    db.AdvisoryPackage,
    name="AdvisoryPackage",
)
Advisory_Pydantic = pydantic_model_creator(
    db.Advisory,
    name="Advisory",
    exclude=(
        "red_hat_advisory",
        "packages.supported_product",
        "packages.supported_product_id",
        "packages.supported_products_rh_mirror",
        "packages.supported_products_rh_mirror_id",
        "cves.advisory",
        "cves.advisory_id",
        "fixes.advisory",
        "fixes.advisory_id",
        "affected_products.advisory",
        "affected_products.advisory_id",
        "affected_products.supported_product",
    ),
)


# Legacy API models
# pylint: disable=invalid-name
class Advisory_Pydantic_V2_Fix(BaseModel):
    ticket: str
    sourceBy: str
    sourceLink: str
    description: str


class Advisory_Pydantic_V2_RPM(BaseModel):
    nevra: str


class Advisory_Pydantic_V2_CVE(BaseModel):
    name: str
    sourceBy: str
    sourceLink: str
    cvss3ScoringVector: str
    cvss3BaseScore: str
    cwe: str


class Advisory_Pydantic_V2(BaseModel):
    type: str
    shortCode: str
    name: str
    synopsis: str
    severity: str
    topic: str
    description: str
    solution: Optional[str]
    affectedProducts: list[str]
    fixes: list[Advisory_Pydantic_V2_Fix]
    cves: list[Advisory_Pydantic_V2_CVE]
    references: list[str]
    publishedAt: str
    rpms: dict[str, list[Advisory_Pydantic_V2_RPM]]
    rebootSuggested: bool
    buildReferences: list[str]

    class Config:
        orm_mode = True
