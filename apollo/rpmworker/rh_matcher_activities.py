import datetime
from dataclasses import dataclass
from xml.etree import ElementTree as ET

from temporalio import activity
from tortoise.transactions import in_transaction

from apollo.db import SupportedProduct, SupportedProductsRhMirror, SupportedProductsRpmRepomd, SupportedProductsRpmRhOverride, SupportedProductsRhBlock
from apollo.db import RedHatAdvisory, Advisory, AdvisoryAffectedProduct, AdvisoryCVE, AdvisoryFix, AdvisoryPackage
from apollo.rpmworker import repomd

from common.logger import Logger


@dataclass
class NewPackage:
    nevra: str
    checksum: str
    checksum_type: str
    module_context: str
    module_name: str
    module_stream: str
    module_version: str
    repo_name: str
    package_name: str
    mirror_id: int
    supported_product_id: int
    product_name: str


@activity.defn
async def get_supported_products_with_rh_mirrors() -> list[int]:
    """
    Get supported product IDs that has an RH mirror configuration
    """
    rh_mirrors = await SupportedProductsRhMirror.all().prefetch_related(
        "rpm_repomds",
    )

    ret = []
    for rh_mirror in rh_mirrors:
        if rh_mirror.supported_product_id not in ret and rh_mirror.rpm_repomds:
            ret.append(rh_mirror.supported_product_id)

    return ret


async def get_matching_rh_advisories(
    mirror: SupportedProductsRhMirror
) -> list[RedHatAdvisory]:
    # First get advisories that matches the mirrored product
    # And also the overrides
    # Also exclude blocked advisories and advisories without packages
    advisories = await RedHatAdvisory.filter(
        affected_products__variant=mirror.match_variant,
        affected_products__major_version=mirror.match_major_version,
        affected_products__minor_version=mirror.match_minor_version,
        affected_products__arch=mirror.match_arch,
    ).order_by("red_hat_issued_at").prefetch_related(
        "packages", "cves", "bugzilla_tickets"
    )

    override_ids = []
    overrides = await SupportedProductsRpmRhOverride.filter(
        supported_products_rh_mirror_id=mirror.id
    ).prefetch_related("red_hat_advisory")
    for override in overrides:
        override_ids.append(override.red_hat_advisory_id)
        advisories.append(override.red_hat_advisory)

    blocked = await SupportedProductsRhBlock.filter(
        supported_products_rh_mirror_id=mirror.id,
    ).all()
    blocked_ids = []
    now = datetime.datetime.now(datetime.timezone.utc)
    for b in blocked:
        delta = now - b.created_at
        if delta.days >= 14:
            blocked_ids.append(b.red_hat_advisory_id)

    # Remove all advisories without packages and blocked advisories
    final = []
    for advisory in advisories:
        if advisory.packages and (
            advisory.id not in blocked_ids and advisory.id not in override_ids
        ):
            final.append(advisory)

    return final


async def clone_advisory(
    product: SupportedProduct,
    mirrors: list[SupportedProductsRhMirror],
    advisory: RedHatAdvisory,
    all_pkgs: list[ET.ElementTree],
    module_pkgs: dict,
    published_at: datetime.datetime,
):
    logger = Logger()
    logger.info("Cloning advisory %s to %s", advisory.name, product.name)

    acceptable_arches = list(set([x.match_arch for x in mirrors]))
    acceptable_arches.extend(["src", "noarch"])
    for mirror in mirrors:
        if mirror.match_arch == "x86_64":
            acceptable_arches.append("i686")
            break

    clean_advisory_nvras = {}
    for advisory_pkg in advisory.packages:
        nvra = repomd.NVRA_RE.search(advisory_pkg.nevra)
        if nvra.group(4) not in acceptable_arches:
            continue
        cleaned = repomd.clean_nvra(advisory_pkg.nevra)
        if cleaned not in clean_advisory_nvras:
            clean_advisory_nvras[cleaned] = True

    if not clean_advisory_nvras:
        logger.info(
            "Blocking advisory %s, no packages match arches",
            advisory.name,
        )
        await SupportedProductsRhBlock.bulk_create(
            [
                SupportedProductsRhBlock(
                    **{
                        "supported_products_rh_mirror_id": mirror.id,
                        "red_hat_advisory_id": advisory.id,
                    }
                ) for mirror in mirrors
            ],
            ignore_conflicts=True,
        )
        overrides = await SupportedProductsRpmRhOverride.filter(
            supported_products_rh_mirror_id__in=[x.id for x in mirrors],
            red_hat_advisory_id=advisory.id,
        ).all()
        if overrides:
            for override in overrides:
                await override.delete()
        return

    pkg_nvras = {}
    for pkgs in all_pkgs:
        for pkg in pkgs:
            cleaned = repomd.clean_nvra_pkg(pkg)
            if cleaned not in pkg_nvras:
                pkg_nvras[cleaned] = [pkg]
            else:
                pkg_nvras[cleaned].append(pkg)

    async with in_transaction():
        # Create advisory
        name = f"{product.code.code}{advisory.name.removeprefix('RH')}"
        synopsis = advisory.synopsis.replace(
            "Red Hat Enterprise Linux", product.name
        )
        synopsis = synopsis.replace("RHEL", product.name)
        synopsis = synopsis.replace("Red Hat", product.vendor)
        synopsis = synopsis.replace(advisory.name, name)
        description = advisory.description.replace(
            "Red Hat Enterprise Linux", product.name
        )
        description = description.replace("RHEL", product.name)
        description = description.replace("Red Hat", product.vendor)
        description = description.replace(advisory.name, name)

        existing_advisory = await Advisory.filter(name=name).get_or_none()
        if not existing_advisory:
            new_advisory = await Advisory.create(
                name=name,
                synopsis=synopsis,
                description=description,
                kind=advisory.kind,
                severity=advisory.severity,
                red_hat_advisory_id=advisory.id,
                published_at=published_at,
                topic=advisory.topic,
            )
        else:
            new_advisory = existing_advisory

        # Clone packages
        new_pkgs = []
        for advisory_nvra, _ in clean_advisory_nvras.items():
            if advisory_nvra not in pkg_nvras:
                continue

            pkgs_to_process = pkg_nvras[advisory_nvra]
            for pkg in pkgs_to_process:
                pkg_name = pkg.find(
                    "{http://linux.duke.edu/metadata/common}name"
                ).text
                version_tree = pkg.find(
                    "{http://linux.duke.edu/metadata/common}version"
                )
                version = version_tree.attrib["ver"]
                release = version_tree.attrib["rel"]
                epoch = version_tree.attrib["epoch"]
                arch = pkg.find(
                    "{http://linux.duke.edu/metadata/common}arch"
                ).text
                nevra = f"{pkg_name}-{epoch}:{version}-{release}.{arch}.rpm"

                source_rpm = pkg.find(
                    "{http://linux.duke.edu/metadata/common}format"
                ).find("{http://linux.duke.edu/metadata/rpm}sourcerpm")

                # This means we're checking a source RPM
                if advisory_nvra.endswith(".src.rpm"
                                         ) or advisory_nvra.endswith(".src"):
                    source_nvra = repomd.NVRA_RE.search(advisory_nvra)
                    package_name = source_nvra.group(1)
                else:
                    source_nvra = repomd.NVRA_RE.search(source_rpm.text)
                    package_name = source_nvra.group(1)

                checksum_tree = pkg.find(
                    "{http://linux.duke.edu/metadata/common}checksum"
                )
                checksum = checksum_tree.text
                checksum_type = checksum_tree.attrib["type"]

                module_context = None
                module_name = None
                module_stream = None
                module_version = None

                if ".module+" in release:
                    for module_pkg, data in module_pkgs.items():
                        if module_pkg == nevra.removesuffix(".rpm"):
                            module_name = data[0]
                            module_stream = data[1]
                            module_version = data[2]
                            module_context = data[3]

                for mirror in mirrors:
                    if pkg.attrib["mirror_id"] != str(mirror.id):
                        continue

                    new_pkgs.append(
                        NewPackage(
                            nevra=nevra,
                            checksum=checksum,
                            checksum_type=checksum_type,
                            module_context=module_context,
                            module_name=module_name,
                            module_stream=module_stream,
                            module_version=module_version,
                            repo_name=pkg.attrib["repo_name"],
                            package_name=package_name,
                            mirror_id=mirror.id,
                            supported_product_id=mirror.supported_product_id,
                            product_name=mirror.name,
                        )
                    )

        if not new_pkgs:
            logger.info(
                "Blocking advisory %s, no packages",
                advisory.name,
            )
            if not existing_advisory:
                await new_advisory.delete()
            await SupportedProductsRhBlock.bulk_create(
                [
                    SupportedProductsRhBlock(
                        **{
                            "supported_products_rh_mirror_id": mirror.id,
                            "red_hat_advisory_id": advisory.id,
                        }
                    ) for mirror in mirrors
                ],
                ignore_conflicts=True,
            )
            overrides = await SupportedProductsRpmRhOverride.filter(
                supported_products_rh_mirror_id__in=[x.id for x in mirrors],
                red_hat_advisory_id=advisory.id,
            ).all()
            if overrides:
                for override in overrides:
                    await override.delete()
            return

        await AdvisoryPackage.bulk_create(
            [
                AdvisoryPackage(
                    **{
                        "advisory_id": new_advisory.id,
                        "nevra": pkg.nevra,
                        "checksum": pkg.checksum,
                        "checksum_type": pkg.checksum_type,
                        "module_context": pkg.module_context,
                        "module_name": pkg.module_name,
                        "module_stream": pkg.module_stream,
                        "module_version": pkg.module_version,
                        "repo_name": pkg.repo_name,
                        "package_name": pkg.package_name,
                        "supported_products_rh_mirror_id": pkg.mirror_id,
                        "supported_product_id": pkg.supported_product_id,
                        "product_name": pkg.product_name,
                    }
                ) for pkg in new_pkgs
            ],
            ignore_conflicts=True,
        )

        # Clone CVEs
        if advisory.cves:
            await AdvisoryCVE.bulk_create(
                [
                    AdvisoryCVE(
                        **{
                            "advisory_id": new_advisory.id,
                            "cve": cve.cve,
                            "cvss3_scoring_vector": cve.cvss3_scoring_vector,
                            "cvss3_base_score": cve.cvss3_base_score,
                            "cwe": cve.cwe,
                        }
                    ) for cve in advisory.cves
                ],
                ignore_conflicts=True,
            )

        # Clone fixes
        if advisory.bugzilla_tickets:
            await AdvisoryFix.bulk_create(
                [
                    AdvisoryFix(
                        **{
                            "advisory_id":
                                new_advisory.id,
                            "ticket_id":
                                fix.bugzilla_bug_id,
                            "source":
                                f"https://bugzilla.redhat.com/show_bug.cgi?id={fix.bugzilla_bug_id}",
                            "description":
                                fix.description,
                        }
                    ) for fix in advisory.bugzilla_tickets
                ],
                ignore_conflicts=True,
            )

        # Add affected products
        await AdvisoryAffectedProduct.bulk_create(
            [
                AdvisoryAffectedProduct(
                    **{
                        "advisory_id": new_advisory.id,
                        "variant": product.name,
                        "name": mirror.name,
                        "major_version": mirror.match_major_version,
                        "minor_version": mirror.match_minor_version,
                        "arch": mirror.match_arch,
                        "supported_product_id": mirror.supported_product_id,
                    }
                ) for mirror in mirrors
            ],
            ignore_conflicts=True,
        )

        # Check if topic is empty, if so construct it
        if not new_advisory.topic:
            package_names = list(set([p.package_name for p in new_pkgs]))
            affected_products = list(
                set(
                    [
                        f"{product.name} {mirror.match_major_version}"
                        for mirror in mirrors
                    ]
                )
            )
            topic = f"""An update is available for {', '.join(package_names)}.
This update affects {', '.join(affected_products)}.
A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE list"""
            new_advisory.topic = topic

            await new_advisory.save()

        # Block advisory from being attempted to be mirrored again
        await SupportedProductsRhBlock.bulk_create(
            [
                SupportedProductsRhBlock(
                    **{
                        "supported_products_rh_mirror_id": mirror.id,
                        "red_hat_advisory_id": advisory.id,
                    }
                ) for mirror in mirrors
            ],
            ignore_conflicts=True,
        )


async def process_repomd(
    mirror: SupportedProductsRhMirror,
    rpm_repomd: SupportedProductsRpmRepomd,
    advisories: list[RedHatAdvisory],
):
    logger = Logger()

    all_pkgs = []
    urls_to_fetch = [
        rpm_repomd.url, rpm_repomd.debug_url, rpm_repomd.source_url
    ]
    module_packages = {}
    for url in urls_to_fetch:
        logger.info("Fetching %s", url)
        repomd_xml = await repomd.download_xml(url)
        primary_xml = await repomd.get_data_from_repomd(
            url, "primary", repomd_xml
        )
        pkgs = primary_xml.findall(
            "{http://linux.duke.edu/metadata/common}package"
        )
        all_pkgs.extend(pkgs)

        module_yaml_data = await repomd.get_data_from_repomd(
            url,
            "modules",
            repomd_xml,
            is_yaml=True,
        )
        if module_yaml_data:
            logger.info("Found modules.yaml")
            for module_data in module_yaml_data:
                if module_data.get("document") != "modulemd":
                    continue
                data = module_data.get("data")
                if not data.get("artifacts"):
                    continue
                for nevra in data.get("artifacts").get("rpms"):
                    module_packages[nevra] = (
                        data.get("name"),
                        data.get("stream"),
                        data.get("version"),
                        data.get("context"),
                    )

    ret = {}

    pkg_nvras = {}
    for pkg in all_pkgs:
        cleaned = repomd.clean_nvra_pkg(pkg)
        if cleaned not in pkg_nvras:
            pkg_nvras[cleaned] = pkg

    check_pkgs = []

    # Now check against advisories, and see if we're matching any
    # If we match, that means we can start creating the supporting
    # mirror advisories
    for advisory in advisories:
        clean_advisory_nvras = {}
        for advisory_pkg in advisory.packages:
            cleaned = repomd.clean_nvra(advisory_pkg.nevra)
            if cleaned not in clean_advisory_nvras:
                clean_advisory_nvras[cleaned] = True

        if not clean_advisory_nvras:
            continue

        did_match_any = False

        for nevra, _ in clean_advisory_nvras.items():
            if nevra in pkg_nvras:
                pkg = pkg_nvras[nevra]
                # Set repo name as an attribute to packages
                pkg.set("repo_name", rpm_repomd.repo_name)
                pkg.set("mirror_id", str(mirror.id))
                check_pkgs.append(pkg)
                did_match_any = True

        if did_match_any:
            ret.update(
                {
                    advisory.name:
                        {
                            "advisory": advisory,
                            "packages": [check_pkgs],
                            "module_packages": module_packages,
                        }
                }
            )

    return ret


@activity.defn
async def match_rh_repos(supported_product_id: int) -> None:
    """
    Process the repomd files for the supported product
    """
    logger = Logger()

    supported_product = await SupportedProduct.filter(
        id=supported_product_id
    ).first().prefetch_related("rh_mirrors", "rh_mirrors__rpm_repomds", "code")

    all_advisories = {}

    for mirror in supported_product.rh_mirrors:
        logger.info("Processing mirror: %s", mirror.name)
        advisories = await get_matching_rh_advisories(mirror)
        for rpm_repomd in mirror.rpm_repomds:
            if rpm_repomd.arch != mirror.match_arch:
                continue
            published_at = None
            if rpm_repomd.production:
                published_at = datetime.datetime.now()
            advisory_map = await process_repomd(mirror, rpm_repomd, advisories)
            if advisory_map:
                for advisory_name, obj in advisory_map.items():
                    if advisory_name in all_advisories:
                        all_advisories[advisory_name]["packages"].extend(
                            obj["packages"]
                        )
                        all_advisories[advisory_name]["mirrors"].append(mirror)

                        for key, val in obj["module_packages"].items():
                            all_advisories[advisory_name]["module_packages"][
                                key] = val
                    else:
                        new_obj = dict(obj)
                        new_obj["published_at"] = published_at
                        new_obj["mirrors"] = [mirror]
                        all_advisories.update({advisory_name: new_obj})

    for advisory_name, obj in all_advisories.items():
        await clone_advisory(
            supported_product,
            list(set(obj["mirrors"])),
            obj["advisory"],
            obj["packages"],
            obj["module_packages"],
            obj["published_at"],
        )


@activity.defn
async def block_remaining_rh_advisories(supported_product_id: int) -> None:
    supported_product = await SupportedProduct.filter(
        id=supported_product_id
    ).first().prefetch_related("rh_mirrors")
    for mirror in supported_product.rh_mirrors:
        mirrors = await SupportedProductsRhMirror.filter(
            supported_product_id=supported_product_id
        )
        for mirror in mirrors:
            advisories = await get_matching_rh_advisories(mirror)
            await SupportedProductsRhBlock.bulk_create(
                [
                    SupportedProductsRhBlock(
                        **{
                            "supported_products_rh_mirror_id": mirror.id,
                            "red_hat_advsiory_id": advisory.id,
                        }
                    ) for advisory in advisories
                ],
                ignore_conflicts=True
            )
