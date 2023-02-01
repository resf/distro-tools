import datetime

from tortoise.models import Model
from tortoise import fields


class Code(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    archived_at = fields.DatetimeField(null=True)
    code = fields.CharField(max_length=255, unique=True)
    description = fields.TextField()

    supported_products: fields.ReverseRelation["SupportedProduct"]

    class Meta:
        table = "codes"


class SupportedProduct(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    eol_at = fields.DatetimeField(null=True)
    name = fields.CharField(max_length=255, unique=True)
    variant = fields.CharField(max_length=255)
    code = fields.ForeignKeyField(
        "models.Code",
        related_name="supported_products",
    )
    vendor = fields.TextField()

    rh_mirrors: fields.ReverseRelation["SupportedProductsRhMirror"]
    advisory_packages: fields.ReverseRelation["AdvisoryPackage"]
    advisory_affected_products: fields.ReverseRelation["AdvisoryAffectedProduct"
                                                      ]

    class Meta:
        table = "supported_products"


class RedHatIndexState(Model):
    id = fields.BigIntField(pk=True)
    last_indexed_at = fields.DatetimeField(null=True)

    class Meta:
        table = "red_hat_index_state"


class RedHatAdvisory(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    red_hat_issued_at = fields.DatetimeField()
    name = fields.CharField(max_length=255, unique=True)
    synopsis = fields.TextField()
    description = fields.TextField()
    kind = fields.CharField(max_length=255)
    severity = fields.CharField(max_length=255)
    topic = fields.TextField()

    packages: fields.ReverseRelation["RedHatAdvisoryPackage"]
    cves: fields.ReverseRelation["RedHatAdvisoryCVE"]
    bugzilla_tickets: fields.ReverseRelation["RedHatAdvisoryBugzillaBug"]
    affected_products: fields.ReverseRelation["RedHatAdvisoryAffectedProduct"]
    rpm_rh_overrides: fields.ReverseRelation["SupportedProductsRpmRhOverride"]
    rh_blocks: fields.ReverseRelation["SupportedProductsRhBlock"]
    published_advisories: fields.ReverseRelation["Advisory"]

    class Meta:
        table = "red_hat_advisories"

    class PydanticMeta:
        exclude = ("rpm_rh_overrides", "rh_blocks", "published_advisories")


class RedHatAdvisoryPackage(Model):
    id = fields.BigIntField(pk=True)
    red_hat_advisory = fields.ForeignKeyField(
        "models.RedHatAdvisory",
        related_name="packages",
    )
    nevra = fields.TextField()

    class Meta:
        table = "red_hat_advisory_packages"
        unique_together = ("red_hat_advisory_id", "nevra")


class RedHatAdvisoryCVE(Model):
    id = fields.BigIntField(pk=True)
    red_hat_advisory = fields.ForeignKeyField(
        "models.RedHatAdvisory",
        related_name="cves",
    )
    cve = fields.TextField()
    cvss3_scoring_vector = fields.TextField(null=True)
    cvss3_base_score = fields.TextField(null=True)
    cwe = fields.TextField(null=True)

    class Meta:
        table = "red_hat_advisory_cves"
        unique_together = ("red_hat_advisory_id", "cve")


class RedHatAdvisoryBugzillaBug(Model):
    id = fields.BigIntField(pk=True)
    red_hat_advisory = fields.ForeignKeyField(
        "models.RedHatAdvisory",
        related_name="bugzilla_tickets",
    )
    bugzilla_bug_id = fields.TextField()
    description = fields.TextField(null=True)

    class Meta:
        table = "red_hat_advisory_bugzilla_bugs"
        unique_together = ("red_hat_advisory_id", "bugzilla_bug_id")


class RedHatAdvisoryAffectedProduct(Model):
    id = fields.BigIntField(pk=True)
    red_hat_advisory = fields.ForeignKeyField(
        "models.RedHatAdvisory",
        related_name="affected_products",
    )
    variant = fields.TextField()
    name = fields.TextField()
    major_version = fields.IntField()
    minor_version = fields.IntField(null=True)
    arch = fields.TextField()

    class Meta:
        table = "red_hat_advisory_affected_products"
        unique_together = (
            "red_hat_advisory_id", "variant", "name", "major_version",
            "minor_version", "arch"
        )


class User(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    archived_at = fields.DatetimeField(null=True)
    email = fields.CharField(max_length=255, unique=True)
    password = fields.CharField(max_length=255)
    name = fields.CharField(max_length=255)
    role = fields.CharField(max_length=255)

    class Meta:
        table = "users"

    class PydanticMeta:
        exclude = ("password", )


class Settings(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    name = fields.CharField(max_length=255, unique=True)
    value = fields.TextField()

    class Meta:
        table = "settings"


class SupportedProductsRhMirror(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    supported_product = fields.ForeignKeyField(
        "models.SupportedProduct",
        related_name="rh_mirrors",
    )
    name = fields.CharField(max_length=255)
    match_variant = fields.CharField(max_length=255)
    match_major_version = fields.IntField()
    match_minor_version = fields.IntField(null=True)
    match_arch = fields.CharField(max_length=255)

    rpm_repomds: fields.ReverseRelation["SupportedProductsRpmRepomd"]
    rpm_rh_overrides: fields.ReverseRelation["SupportedProductsRpmRhOverride"]
    rh_blocks: fields.ReverseRelation["SupportedProductsRhBlock"]
    advisory_packages: fields.ReverseRelation["AdvisoryPackage"]

    class Meta:
        table = "supported_products_rh_mirrors"


class SupportedProductsRpmRepomd(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    supported_products_rh_mirror = fields.ForeignKeyField(
        "models.SupportedProductsRhMirror",
        related_name="rpm_repomds",
    )
    production = fields.BooleanField()
    arch = fields.CharField(max_length=255)
    url = fields.TextField()
    debug_url = fields.TextField()
    source_url = fields.TextField()
    repo_name = fields.CharField(max_length=255)

    class Meta:
        table = "supported_products_rpm_repomds"


class SupportedProductsRpmRhOverride(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    supported_products_rh_mirror = fields.ForeignKeyField(
        "models.SupportedProductsRhMirror",
        related_name="rpm_rh_overrides",
    )
    red_hat_advisory = fields.ForeignKeyField(
        "models.RedHatAdvisory",
        related_name="rpm_rh_overrides",
    )

    class Meta:
        table = "supported_products_rpm_rh_overrides"


class SupportedProductsRhBlock(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    supported_products_rh_mirror = fields.ForeignKeyField(
        "models.SupportedProductsRhMirror",
        related_name="rh_blocks",
    )
    red_hat_advisory = fields.ForeignKeyField(
        "models.RedHatAdvisory",
        related_name="rh_blocks",
    )

    class Meta:
        table = "supported_products_rh_blocks"


class Advisory(Model):
    id = fields.BigIntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True, null=True)
    published_at = fields.DatetimeField()
    name = fields.CharField(max_length=255, unique=True)
    synopsis = fields.TextField()
    description = fields.TextField()
    kind = fields.CharField(max_length=255)
    severity = fields.CharField(max_length=255)
    topic = fields.TextField()
    red_hat_advisory = fields.ForeignKeyField(
        "models.RedHatAdvisory",
        related_name="published_advisories",
    )

    packages: fields.ReverseRelation["AdvisoryPackage"]
    cves: fields.ReverseRelation["AdvisoryCVE"]
    fixes: fields.ReverseRelation["AdvisoryFix"]
    affected_products: fields.ReverseRelation["AdvisoryAffectedProduct"]

    class Meta:
        table = "advisories"


class AdvisoryPackage(Model):
    id = fields.BigIntField(pk=True)
    advisory = fields.ForeignKeyField(
        "models.Advisory",
        related_name="packages",
    )
    nevra = fields.TextField()
    checksum = fields.TextField()
    checksum_type = fields.CharField(max_length=255)
    module_context = fields.TextField(null=True)
    module_name = fields.TextField(null=True)
    module_stream = fields.TextField(null=True)
    module_version = fields.TextField(null=True)
    repo_name = fields.TextField()
    package_name = fields.TextField()
    product_name = fields.TextField()
    supported_products_rh_mirror = fields.ForeignKeyField(
        "models.SupportedProductsRhMirror",
        related_name="advisory_packages",
    )
    supported_product = fields.ForeignKeyField(
        "models.SupportedProduct",
        related_name="advisory_packages",
    )

    class Meta:
        table = "advisory_packages"
        unique_together = ("advisory_id", "nevra")


class AdvisoryCVE(Model):
    id = fields.BigIntField(pk=True)
    advisory = fields.ForeignKeyField(
        "models.Advisory",
        related_name="cves",
    )
    cve = fields.TextField()
    cvss3_scoring_vector = fields.TextField(null=True)
    cvss3_base_score = fields.TextField(null=True)
    cwe = fields.TextField(null=True)

    class Meta:
        table = "advisory_cves"
        unique_together = ("advisory_id", "cve")


class AdvisoryFix(Model):
    id = fields.BigIntField(pk=True)
    advisory = fields.ForeignKeyField(
        "models.Advisory",
        related_name="fixes",
    )
    ticket_id = fields.TextField()
    source = fields.TextField()
    description = fields.TextField(null=True)

    class Meta:
        table = "advisory_fixes"
        unique_together = ("advisory_id", "ticket_id")


class AdvisoryAffectedProduct(Model):
    id = fields.BigIntField(pk=True)
    advisory = fields.ForeignKeyField(
        "models.Advisory",
        related_name="affected_products",
    )
    variant = fields.TextField()
    name = fields.TextField()
    major_version = fields.IntField()
    minor_version = fields.IntField(null=True)
    arch = fields.TextField()
    supported_product = fields.ForeignKeyField(
        "models.SupportedProduct",
        related_name="advisory_affected_products",
    )

    class Meta:
        table = "advisory_affected_products"
        unique_together = (
            "advisory_id",
            "variant",
            "name",
            "major_version",
            "minor_version",
            "arch",
        )
