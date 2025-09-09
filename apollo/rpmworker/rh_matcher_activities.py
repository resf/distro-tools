import datetime
import re
from dataclasses import dataclass
from typing import Optional
from xml.etree import ElementTree as ET
from temporalio import activity
from tortoise.transactions import in_transaction

from apollo.db import SupportedProduct, SupportedProductsRhMirror, SupportedProductsRpmRepomd, SupportedProductsRpmRhOverride, SupportedProductsRhBlock
from apollo.db import RedHatAdvisory, Advisory, AdvisoryAffectedProduct, AdvisoryCVE, AdvisoryFix, AdvisoryPackage
from apollo.rpmworker import repomd
from apollo.rpm_helpers import parse_nevra

from common.logger import Logger

RHEL_CONTAINER_RE = re.compile(r"rhel(?:\d|)\/")


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

async def create_or_update_advisory_packages(
    advisory: Advisory,
    packages: list[NewPackage],
    update_advisory: bool = False,
) -> None:
    """
    Add advisory packages for the given advisory.
    If update_advisory is True, remove packages not in the new list.
    """
    logger = Logger()
    logger.info("Creating or updating advisory packages for %s", advisory.name)

    existing_packages = await AdvisoryPackage.filter(advisory_id=advisory.id).all()
    existing_nevras = {pkg.nevra for pkg in existing_packages}
    new_nevras = {pkg.nevra for pkg in packages}

    # Add new packages
    new_packages = []
    for pkg in packages:
        if pkg.nevra not in existing_nevras:
            new_packages.append(
                AdvisoryPackage(
                    advisory_id=advisory.id,
                    nevra=pkg.nevra,
                    checksum=pkg.checksum,
                    checksum_type=pkg.checksum_type,
                    module_context=pkg.module_context,
                    module_name=pkg.module_name,
                    module_stream=pkg.module_stream,
                    module_version=pkg.module_version,
                    repo_name=pkg.repo_name,
                    package_name=pkg.package_name,
                    supported_products_rh_mirror_id=pkg.mirror_id,
                    supported_product_id=pkg.supported_product_id,
                    product_name=pkg.product_name,
                )
            )
    if new_packages:
        logger.info("Adding %d new packages to advisory %s", len(new_packages), advisory.name)
        await AdvisoryPackage.bulk_create(new_packages, ignore_conflicts=True)
    else:
        logger.info("No new packages to add to advisory %s", advisory.name)

    # Remove packages not in the new list if updating
    if update_advisory:
        nevras_to_remove = existing_nevras - new_nevras
        if nevras_to_remove:
            logger.info("Removing %d packages from advisory %s", len(nevras_to_remove), advisory.name)
            await AdvisoryPackage.filter(advisory_id=advisory.id, nevra__in=list(nevras_to_remove)).delete()


async def create_or_update_advisory_cves(
    advisory: Advisory,
    cves: list,
    update_advisory: bool = False,
) -> None:
    """
    Add or update CVEs for the given advisory.
    Remove CVEs currently associated with advisory if they don't exist in the list passed in.
    """
    logger = Logger()
    logger.info("Creating or updating CVEs for advisory %s", advisory.name)

    # Build a map of existing CVEs by cve_id
    existing_cves = {cve.cve: cve for cve in await AdvisoryCVE.filter(advisory_id=advisory.id).all()}
    existing_cve_ids = set(existing_cves.keys())

    # Support both dicts and objects
    def extract_cve_id(cve_data):
        if isinstance(cve_data, dict):
            return cve_data["cve"]
        return getattr(cve_data, "cve", None)

    new_cve_ids = set()
    for cve_data in cves:
        cve_id = extract_cve_id(cve_data)
        if not cve_id:
            continue
        new_cve_ids.add(cve_id)
        existing = existing_cves.get(cve_id)
        cvss3_scoring_vector = (
            cve_data.get("cvss3_scoring_vector") if isinstance(cve_data, dict)
            else getattr(cve_data, "cvss3_scoring_vector", None)
        )
        cvss3_base_score = (
            cve_data.get("cvss3_base_score") if isinstance(cve_data, dict)
            else getattr(cve_data, "cvss3_base_score", None)
        )
        cwe = (
            cve_data.get("cwe") if isinstance(cve_data, dict)
            else getattr(cve_data, "cwe", None)
        )

        if existing:
            needs_update = (
                existing.cvss3_scoring_vector != cvss3_scoring_vector or
                str(existing.cvss3_base_score) != str(cvss3_base_score) or
                (existing.cwe or "") != (cwe or "")
            )
            if needs_update:
                logger.info("Updating CVE %s for advisory %s", cve_id, advisory.name)
                existing.cvss3_scoring_vector = cvss3_scoring_vector
                existing.cvss3_base_score = str(cvss3_base_score) if cvss3_base_score else None
                existing.cwe = cwe if cwe else None
                await existing.save()
        else:
            logger.info("Adding new CVE %s to advisory %s", cve_id, advisory.name)
            await AdvisoryCVE.create(
                advisory_id=advisory.id,
                cve=cve_id,
                cvss3_scoring_vector=cvss3_scoring_vector,
                cvss3_base_score=str(cvss3_base_score) if cvss3_base_score else None,
                cwe=cwe if cwe else None,
            )

    # Remove CVEs not in the new list
    if update_advisory:
        cves_to_remove = existing_cve_ids - new_cve_ids
        if cves_to_remove:
            logger.info("Removing %d CVEs from advisory %s", len(cves_to_remove), advisory.name)
            await AdvisoryCVE.filter(advisory_id=advisory.id, cve__in=list(cves_to_remove)).delete()

async def create_or_update_advisory_fixes(
    advisory: Advisory,
    fixes: list,
    update_advisory: bool = False,
) -> None:
    """
    Add fixes for the given advisory.
    Remove fixes currently associated with advisory if they don't exist in the list passed in.
    """
    logger = Logger()
    logger.info("Creating or updating fixes for advisory %s", advisory.name)

    existing_fixes = await AdvisoryFix.filter(advisory_id=advisory.id).all()
    existing_ticket_ids = {fix.ticket_id for fix in existing_fixes}

    new_ticket_ids = {fix.bugzilla_bug_id for fix in fixes if fix.bugzilla_bug_id}

    # Add new fixes
    new_fixes = []
    for fix in fixes:
        if fix.bugzilla_bug_id and fix.bugzilla_bug_id not in existing_ticket_ids:
            new_fixes.append(
                AdvisoryFix(
                    advisory_id=advisory.id,
                    ticket_id=fix.bugzilla_bug_id,
                    source=f"https://bugzilla.redhat.com/show_bug.cgi?id={fix.bugzilla_bug_id}",
                    description=fix.description,
                )
            )

    if new_fixes:
        logger.info("Adding %d new fixes to advisory %s", len(new_fixes), advisory.name)
        await AdvisoryFix.bulk_create(new_fixes, ignore_conflicts=True)
    else:
        logger.info("No new fixes to add to advisory %s", advisory.name)

    # Remove fixes not in the new list
    if update_advisory:
        tickets_to_remove = existing_ticket_ids - new_ticket_ids
        if tickets_to_remove:
            logger.info("Removing %d fixes from advisory %s", len(tickets_to_remove), advisory.name)
            await AdvisoryFix.filter(advisory_id=advisory.id, ticket_id__in=list(tickets_to_remove)).delete()


async def create_or_update_advisory_affected_product(
    advisory: Advisory,
    product_name: str,
    mirrors: list[SupportedProductsRhMirror],
    update_advisory: bool = False,
    ) -> None:
    """
    Add affected products for the given advisory.
    Remove affected products currently associated with advisory if they don't exist in the list passed in.
    """
    logger = Logger()
    logger.info("Creating or updating affected products for advisory %s", advisory.name)

    existing_affected_products = await AdvisoryAffectedProduct.filter(advisory_id=advisory.id).all()
    existing_affected_product_ids = {(ap.variant, ap.name, ap.major_version, ap.minor_version, ap.arch) for ap in existing_affected_products}

    new_affected_products = list()

    for mirror in mirrors:
        new_affected_products.append(
            {
                "advisory_id": advisory.id,
                "variant": product_name,
                "name": mirror.name,
                "major_version": mirror.match_major_version,
                "minor_version": mirror.match_minor_version,
                "arch": mirror.match_arch,
                "supported_product_id": mirror.supported_product_id,
            }
        )

    # Add new affected products
    new_entries = []
    for product in new_affected_products:
        key = (product['variant'], product['name'], product['major_version'], product['minor_version'], product['arch'])
        if key not in existing_affected_product_ids:
            new_entries.append(
                AdvisoryAffectedProduct(
                    advisory_id=advisory.id,
                    variant=product['variant'],
                    name=product['name'],
                    major_version=product['major_version'],
                    minor_version=product['minor_version'],
                    arch=product['arch'],
                    supported_product_id=product.get('supported_product_id'),
                )
            )

    if new_entries:
        logger.info("Adding %d new affected products to advisory %s", len(new_entries), advisory.name)
        await AdvisoryAffectedProduct.bulk_create(new_entries, ignore_conflicts=True)
    else:
        logger.info("No new affected products to add to advisory %s", advisory.name)

    # Remove affected products not in the new list
    if update_advisory:
        # Build set of new keys for comparison
        new_keys = {(p['variant'], p['name'], p['major_version'], p['minor_version'], p['arch']) for p in new_affected_products}
        products_to_remove = existing_affected_product_ids - new_keys
        if products_to_remove:
            logger.info("Removing %d affected products from advisory %s", len(products_to_remove), advisory.name)
            # Remove each affected product by matching all tuple fields
            for key in products_to_remove:
                await AdvisoryAffectedProduct.filter(
                    advisory_id=advisory.id,
                    variant=key[0],
                    name=key[1],
                    major_version=key[2],
                    minor_version=key[3],
                    arch=key[4],
                ).delete()

@activity.defn
async def get_supported_products_with_rh_mirrors(filter_major_versions: Optional[list[int]] = None) -> list[int]:
    """
    Get supported product IDs that has an RH mirror configuration
    Note: filter_major_versions parameter is kept for backward compatibility but not used at this level.
    Filtering now happens at the mirror level within match_rh_repos activity.
    """
    logger = Logger()
    rh_mirrors = await SupportedProductsRhMirror.all().prefetch_related(
        "rpm_repomds",
    )
    ret = []
    for rh_mirror in rh_mirrors:
        if rh_mirror.supported_product_id not in ret and rh_mirror.rpm_repomds:
            logger.debug(f"Adding rh_mirror.supported_product_id ({rh_mirror.supported_product_id})")
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
        "packages",
        "cves",
        "bugzilla_tickets",
    )

    override_ids = []
    overrides = await SupportedProductsRpmRhOverride.filter(
        supported_products_rh_mirror_id=mirror.id,
        updated_at__isnull=True,
    ).prefetch_related(
        "red_hat_advisory",
        "red_hat_advisory__packages",
        "red_hat_advisory__cves",
        "red_hat_advisory__bugzilla_tickets",
    )
    for override in overrides:
        override_ids.append(override.red_hat_advisory_id)
        advisories.append(override.red_hat_advisory)

    blocked = await SupportedProductsRhBlock.filter(
        supported_products_rh_mirror_id=mirror.id
    ).all()
    blocked_ids = []
    now = datetime.datetime.now(datetime.timezone.utc)
    for b in blocked:
        if b.red_hat_advisory_id in override_ids:
            continue
        delta = now - b.created_at
        if delta.days >= 14:
            blocked_ids.append(b.red_hat_advisory_id)

    # Remove all advisories without packages and blocked advisories
    final = []
    final_ids = []
    for advisory in advisories:
        if advisory.packages and advisory.id not in blocked_ids:
            if advisory.id not in final_ids:
                final.append(advisory)
                final_ids.append(advisory.id)
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

    acceptable_arches = list({x.match_arch for x in mirrors})
    acceptable_arches.extend(["src", "noarch"])
    for mirror in mirrors:
        if mirror.match_arch == "x86_64":
            acceptable_arches.append("i686")
            break

    # Generate dictionary of clean advisory nvras
    clean_advisory_nvras = {}
    for advisory_pkg in advisory.packages:
        try:
            results = parse_nevra(advisory_pkg.nevra)
        except ValueError as e:
            logger.warning(f"Skipping invalid NEVRA '{advisory_pkg.nevra}': {e}")
            continue
        advisory_pkg_arch = results["arch"]
        if advisory_pkg_arch not in acceptable_arches:
            continue
        cleaned, raw = repomd.clean_nvra(advisory_pkg.nevra)
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
        return

    # Generate dictionary of all packages in the repomd
    pkg_nvras = {} # Populated from all_pkgs and contains a mapping of all pkg xml elemnts for each cleaned nvra
    # { cleaned_nvra: [pkg_xml_elem, pkg_xml_elem, ...] }
    pkg_name_map = {} # Populated from all_pkgs and contains a mapping of package name to all of the raw nvras associated with that package name
    # { pkg_name: [raw_nvra, raw_nvra, ...] }
    for pkgs in all_pkgs:
        for pkg in pkgs:
            cleaned, raw = repomd.clean_nvra_pkg(pkg)
            name = repomd.NVRA_RE.search(cleaned).group(1)
            if cleaned not in pkg_nvras:
                pkg_nvras[cleaned] = [pkg]
            else:
                pkg_nvras[cleaned].append(pkg)

            if name not in pkg_name_map:
                pkg_name_map[name] = []
            pkg_name_map[name].append(cleaned)

    nvra_alias = {} # Mapping of advisory nvra to pkg nvra where the pkg nvra comes from the pkg_name_map, however this only will get the first match and will ignore all others.
    for advisory_nvra, _ in clean_advisory_nvras.items():
        name = repomd.NVRA_RE.search(advisory_nvra).group(1)
        name_pkgs = pkg_name_map.get(name, [])
        for pkg_nvra in name_pkgs:
            pkg_nvra_rs = pkg_nvra.rsplit(".", 1)
            cleaned_rs = advisory_nvra.rsplit(".", 1)

            pkg_arch = pkg_nvra_rs[1]
            cleaned_arch = cleaned_rs[1]

            pkg_nvr = pkg_nvra_rs[0]
            cleaned_nvr = cleaned_rs[0]

            if pkg_nvr.startswith(cleaned_nvr) and pkg_arch == cleaned_arch:
                nvra_alias[advisory_nvra] = pkg_nvra
                break

    async with in_transaction():
        # Create advisory
        name = f"{product.code.code}{advisory.name.removeprefix('RH')}"
        synopsis = advisory.synopsis.replace(
            "Red Hat Enterprise Linux", product.name
        )
        synopsis = synopsis.replace("RHEL", product.name)
        synopsis = RHEL_CONTAINER_RE.sub("", synopsis)
        synopsis = synopsis.replace("Red Hat", product.vendor)
        synopsis = synopsis.replace(advisory.name, name)
        description = advisory.description.replace(
            "Red Hat Enterprise Linux", product.name
        )
        description = description.replace("RHEL", product.name)
        description = RHEL_CONTAINER_RE.sub("", description)
        description = description.replace("Red Hat", product.vendor)
        description = description.replace(advisory.name, name)

        existing_advisory = await Advisory.filter(name=name).get_or_none()
        update_advisory = False
        if not existing_advisory:
            logger.info(f"Creating advisory {name}")
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
            update_advisory = True
            new_advisory = existing_advisory

        # Clone packages
        new_pkgs = []
        for advisory_nvra, _ in clean_advisory_nvras.items():
            if advisory_nvra not in pkg_nvras:
                if advisory_nvra in nvra_alias:
                    advisory_nvra = nvra_alias[advisory_nvra]
                else:
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
            return

        await create_or_update_advisory_packages(new_advisory, new_pkgs, update_advisory)

        # Clone CVEs
        if advisory.cves:
            await create_or_update_advisory_cves(new_advisory, advisory.cves, update_advisory)

        # Clone fixes
        if advisory.bugzilla_tickets:
            await create_or_update_advisory_fixes(
                new_advisory,
                advisory.bugzilla_tickets,
                update_advisory
                )

        # Add affected products
        await create_or_update_advisory_affected_product(
            new_advisory,
            product.name,
            mirrors,
            update_advisory
        )

        # Construct topic
        package_names = list({p.package_name for p in new_pkgs})
        affected_products = list(
            {
                f"{product.name} {mirror.match_major_version}"
                for mirror in mirrors
            }
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

        # Set update_at to now for any overrides for advisory
        await SupportedProductsRpmRhOverride.filter(
            red_hat_advisory_id=advisory.id,
            supported_products_rh_mirror_id__in=[x.id for x in mirrors],
        ).update(updated_at=datetime.datetime.utcnow())


async def process_repomd(
    mirror: SupportedProductsRhMirror,
    rpm_repomd: SupportedProductsRpmRepomd,
    advisories: list[RedHatAdvisory],
):
    logger = Logger()
    all_pkgs = []
    urls_to_fetch = [
        url for url in [rpm_repomd.url, rpm_repomd.debug_url, rpm_repomd.source_url] 
        if url and url.strip()
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
    raw_pkg_nvras = {}
    raw_package_map = {}
    for pkg in all_pkgs:
        # in the case of a module nvra the cleaned variable
        # becomes the package stripped of any module information
        # and with the nvra prepended with 'module.'
        cleaned, raw = repomd.clean_nvra_pkg(pkg)
        name = repomd.NVRA_RE.search(cleaned).group(1)

        if cleaned not in raw_pkg_nvras:
            raw_pkg_nvras[cleaned] = []
        raw_pkg_nvras[cleaned].append(pkg)

        if name not in raw_package_map:
            raw_package_map[name] = []
        raw_package_map[name].append(raw)

    nvra_alias = {}
    check_pkgs = set()


    # Now check against advisories, and see if we're matching any
    # If we match, that means we can start creating the supporting
    # mirror advisories
    for advisory in advisories:
        logger.debug(f"Processing advisory: {advisory.name} inside of `process_repomd` for {mirror.name}")
        clean_advisory_nvras = {}
        # Loop through each package in the advisory and check if we
        # have a match from the rocky repos
        for advisory_pkg in advisory.packages:
            # cleaned will strip out module specific info from a package name
            # and prepend 'module.' to the name for modular packages.
            cleaned, raw = repomd.clean_nvra(advisory_pkg.nevra)
            try:
                results = parse_nevra(advisory_pkg.nevra)
            except ValueError as e:
                logger.warning(f"Skipping invalid NEVRA '{advisory_pkg.nevra}': {e}")
                continue
            name = results["name"]
            if cleaned not in clean_advisory_nvras:
                if not cleaned in raw_pkg_nvras:
                    # Check if we can match the prefix instead
                    # First let's fetch the name matching NVRAs
                    # To cut down on the number of checks
                    name_pkgs = raw_package_map.get(name, [])
                    # pkg_nvra's will be 'cleaned'
                    for pkg_nvra in name_pkgs:
                        pkg_nvra_rs = pkg_nvra.rsplit(".", 1)
                        cleaned_rs = cleaned.rsplit(".", 1)

                        pkg_arch = pkg_nvra_rs[1]
                        cleaned_arch = cleaned_rs[1]

                        pkg_nvr = pkg_nvra_rs[0]
                        cleaned_nvr = cleaned_rs[0]
                        if pkg_nvr.startswith(
                            cleaned_nvr
                        ) and pkg_arch == cleaned_arch:
                            nvra_alias[cleaned] = pkg_nvra
                            break
                clean_advisory_nvras[cleaned] = raw

        if not clean_advisory_nvras:
            logger.debug(f"No cleaned packages for {advisory.name}, moving on.")
            continue

        did_match_any = False
        for nevra, _ in clean_advisory_nvras.items():
            if nevra in raw_pkg_nvras:
                for pkg in raw_pkg_nvras[nevra]:
                    cleaned, raw = repomd.clean_nvra_pkg(pkg)
                    pkg.set("repo_name", rpm_repomd.repo_name)
                    pkg.set("mirror_id", str(mirror.id))
                    check_pkgs.add(pkg)
                    did_match_any = True

            elif nevra in nvra_alias:
                logger.debug(f"nevra: {nevra}")
                logger.debug(f"nvra_alias[nevra]: {nvra_alias[nevra]}")
                for pkg in raw_pkg_nvras.get(nvra_alias[nevra], []):
                    cleaned, raw = repomd.clean_nvra_pkg(pkg)
                    pkg.set("repo_name", rpm_repomd.repo_name)
                    pkg.set("mirror_id", str(mirror.id))
                    check_pkgs.add(pkg)
                    did_match_any = True

        if did_match_any:
            logger.debug(f"Found packages for {advisory.name}")
            ret.update(
                {
                    advisory.name:
                        {
                            "advisory": advisory,
                            "packages": [check_pkgs], # list of xml element strings
                            "module_packages": module_packages,
                        }
                }
            )
        else:
            logger.debug(f"No matching packages found for {advisory.name} inside of {mirror.name}")

    return ret


@activity.defn
async def match_rh_repos(params) -> None:
    """
    Process the repomd files for the supported product with optional major version filtering
    """
    # Handle both old format (int) and new format (dict) for backward compatibility
    if isinstance(params, int):
        supported_product_id = params
        filter_major_versions = None
    else:
        supported_product_id = params["supported_product_id"]
        filter_major_versions = params.get("filter_major_versions")
    
    logger = Logger()
    supported_product = await SupportedProduct.filter(
        id=supported_product_id
    ).first().prefetch_related("rh_mirrors", "rh_mirrors__rpm_repomds", "code")

    all_advisories = {}

    for mirror in supported_product.rh_mirrors:
        # Apply major version filtering if specified
        if filter_major_versions is not None and int(mirror.match_major_version) not in filter_major_versions:
            logger.debug(f"Skipping mirror {mirror.name} with major version {mirror.match_major_version} due to filtering")
            continue
        logger.info("Processing mirror: %s", mirror.name)
        advisories = await get_matching_rh_advisories(mirror)
        for rpm_repomd in mirror.rpm_repomds:
            if rpm_repomd.arch != mirror.match_arch:
                logger.debug(f"Skipping due to {rpm_repomd.arch} != {mirror.match_arch}")
                continue
            advisory_map = await process_repomd(mirror, rpm_repomd, advisories)
            if advisory_map:
                published_at = None
                if rpm_repomd.production:
                    published_at = datetime.datetime.utcnow()
                for advisory_name, obj in advisory_map.items():
                    logger.debug(f"Processing advisory: {advisory_name} for {mirror.name}")
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
        logger.debug(f"Attempting to clone advisory: {advisory_name}")
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
