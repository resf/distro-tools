import pathlib
import json

from common.logger import Logger
from apollo.rpm_helpers import parse_nevra

logger = Logger()

EUS_CPE_PRODUCTS = frozenset([
    "rhel_eus",  # Extended Update Support
    "rhel_e4s",  # Update Services for SAP Solutions
    "rhel_aus",  # Advanced Update Support (IBM Power)
    "rhel_tus",  # Telecommunications Update Service
])

EUS_PRODUCT_NAME_KEYWORDS = frozenset([
    "e4s",
    "eus",
    "aus",
    "tus",
    "extended update support",
    "update services for sap",
    "advanced update support",
    "telecommunications update service",
])

def _is_eus_product(product_name: str, cpe: str) -> bool:
    """
    Detects if a product is EUS-related based on product name and CPE.

    Args:
        product_name: Full product name (e.g., "Red Hat Enterprise Linux AppStream E4S (v.9.0)")
        cpe: CPE string (e.g., "cpe:/a:redhat:rhel_e4s:9.0::appstream")

    Returns:
        True if product is EUS/E4S/AUS/TUS, False otherwise
    """
    if cpe:
        parts = cpe.split(":")
        if len(parts) > 3:
            cpe_product = parts[3]
            if cpe_product in EUS_CPE_PRODUCTS:
                return True

    if product_name:
        name_lower = product_name.lower()
        for keyword in EUS_PRODUCT_NAME_KEYWORDS:
            if keyword in name_lower:
                return True

    return False


def extract_rhel_affected_products_for_db(csaf: dict) -> set:
    """
    Extracts all needed info for red_hat_advisory_affected_products table from CSAF product_tree.
    Expands 'noarch' to all main arches and maps names to user-friendly values.
    Returns a set of tuples: (variant, name, major_version, minor_version, arch)
    """
    arch_name_map = {
        "aarch64": "Red Hat Enterprise Linux for ARM 64",
        "x86_64": "Red Hat Enterprise Linux for x86_64",
        "s390x": "Red Hat Enterprise Linux for IBM z Systems",
        "ppc64le": "Red Hat Enterprise Linux for Power, little endian",
    }
    main_arches = list(arch_name_map.keys())
    affected_products = set()
    product_tree = csaf.get("product_tree", {})
    if not product_tree:
        logger.warning("No product tree found in CSAF document")
        return affected_products

    for vendor_branch in product_tree.get("branches", []):
        family_branch = None
        arches = set()
        for branch in vendor_branch.get("branches", []):
            if branch.get("category") == "product_family" and branch.get("name") == "Red Hat Enterprise Linux":
                family_branch = branch
            elif branch.get("category") == "architecture":
                arch = branch.get("name")
                if arch:
                    arches.add(arch)
        if "noarch" in arches:
            arches = set(main_arches)
        if not family_branch:
            continue
        prod_name = None
        cpe = None
        for branch in family_branch.get("branches", []):
            if branch.get("category") == "product_name":
                prod = branch.get("product", {})
                prod_name = prod.get("name")
                cpe = prod.get("product_identification_helper", {}).get("cpe")
                break
        if not prod_name or not cpe:
            continue

        if _is_eus_product(prod_name, cpe):
            logger.debug(f"Skipping EUS product: {prod_name}")
            continue

        # Example CPE: "cpe:/a:redhat:enterprise_linux:9::appstream"
        parts = cpe.split(":")
        major = None
        minor = None
        if len(parts) > 4:
            version = parts[4]
            if version:
                if "." in version:
                    major, minor = version.split(".", 1)
                    major = int(major)
                    minor = int(minor)
                else:
                    major = int(version)

        for arch in arches:
            name = arch_name_map.get(arch)
            if name is None:
                logger.warning(f"'{arch}' not in arch_name_map, skipping.")
                continue
            if major:
                affected_products.add((
                    family_branch.get("name"),
                    name,
                    major,
                    minor,
                    arch
                ))
    logger.debug(f"Number of affected products: {len(affected_products)}")
    return affected_products


def _traverse_for_eus(branches, product_eus_map=None):
    """
    Recursively traverse CSAF branches to build EUS product map.

    Args:
        branches: List of CSAF branch dictionaries to traverse
        product_eus_map: Optional dict to accumulate results

    Returns:
        Dict mapping product_id to boolean indicating if product is EUS
    """
    if product_eus_map is None:
        product_eus_map = {}

    for branch in branches:
        category = branch.get("category")

        if category == "product_name":
            prod = branch.get("product", {})
            product_id = prod.get("product_id")

            if product_id:
                product_name = prod.get("name", "")
                cpe = prod.get("product_identification_helper", {}).get("cpe", "")
                is_eus = _is_eus_product(product_name, cpe)
                product_eus_map[product_id] = is_eus

        if "branches" in branch:
            _traverse_for_eus(branch["branches"], product_eus_map)

    return product_eus_map


def _extract_packages_from_branches(branches, product_eus_map, packages=None):
    """
    Recursively traverse CSAF branches to extract package NEVRAs.

    Args:
        branches: List of CSAF branch dictionaries to traverse
        product_eus_map: Dict mapping product_id to EUS status
        packages: Optional set to accumulate results

    Returns:
        Set of NEVRA strings
    """
    if packages is None:
        packages = set()

    for branch in branches:
        category = branch.get("category")

        if category == "product_version":
            prod = branch.get("product", {})
            product_id = prod.get("product_id")
            purl = prod.get("product_identification_helper", {}).get("purl")

            if not product_id:
                continue

            if purl and not purl.startswith("pkg:rpm/"):
                continue

            # Product IDs for packages can have format: "AppStream-9.0.0.Z.E4S:package-nevra"
            # or just "package-nevra" for packages in product_version entries
            skip_eus = False
            for eus_prod_id, is_eus in product_eus_map.items():
                if is_eus and (":" in product_id and product_id.startswith(eus_prod_id + ":")):
                    skip_eus = True
                    break

            if skip_eus:
                continue

            # Format: "package-epoch:version-release.arch" or "package-epoch:version-release.arch::module:stream"
            packages.add(product_id.split("::")[0])

        if "branches" in branch:
            _extract_packages_from_branches(branch["branches"], product_eus_map, packages)

    return packages


def _extract_packages_from_product_tree(csaf: dict) -> set:
    """
    Extracts fixed packages from CSAF product_tree using product_id fields.
    Handles both regular and modular packages by extracting NEVRAs directly from product_id.
    Filters out EUS products.

    Args:
        csaf: CSAF document dict

    Returns:
        Set of NEVRA strings
    """
    product_tree = csaf.get("product_tree", {})

    if not product_tree:
        return set()

    product_eus_map = {}
    for vendor_branch in product_tree.get("branches", []):
        product_eus_map = _traverse_for_eus(vendor_branch.get("branches", []), product_eus_map)

    packages = set()
    for vendor_branch in product_tree.get("branches", []):
        packages = _extract_packages_from_branches(vendor_branch.get("branches", []), product_eus_map, packages)

    return packages


def red_hat_advisory_scraper(csaf: dict):
    # At the time of writing there are ~254 advisories that do not have any vulnerabilities.
    if not csaf.get("vulnerabilities"):
        logger.warning("No vulnerabilities found in CSAF document")
        return None

    name = csaf["document"]["tracking"]["id"]

    red_hat_affected_products = extract_rhel_affected_products_for_db(csaf)
    if not red_hat_affected_products:
        logger.info(f"Skipping advisory {name}: all products are EUS-only")
        return None

    red_hat_issued_at = csaf["document"]["tracking"]["initial_release_date"]
    red_hat_updated_at = csaf["document"]["tracking"]["current_release_date"]
    red_hat_synopsis = csaf["document"]["title"]
    red_hat_description = None
    topic = None
    for item in csaf["document"]["notes"]:
        if item["category"] == "general":
            red_hat_description = item["text"]
        elif item["category"] == "summary":
            topic = item["text"]
    kind_lookup = {"RHSA": "Security", "RHBA": "Bug Fix", "RHEA": "Enhancement"}
    kind = kind_lookup[name.split("-")[0]]
    severity = csaf["document"]["aggregate_severity"]["text"]

    # To maintain consistency with the existing database, replace
    # "Red Hat [KIND] Advisory:" prefixes with the severity level.
    red_hat_synopsis = red_hat_synopsis.replace("Red Hat Bug Fix Advisory: ", f"{severity}:")
    red_hat_synopsis = red_hat_synopsis.replace("Red Hat Security Advisory:", f"{severity}:")
    red_hat_synopsis = red_hat_synopsis.replace("Red Hat Enhancement Advisory: ", f"{severity}:")

    red_hat_fixed_packages = _extract_packages_from_product_tree(csaf)

    red_hat_cve_set = set()
    red_hat_bugzilla_set = set()

    for vulnerability in csaf["vulnerabilities"]:
        cve_id = vulnerability.get("cve", None)
        cve_cvss3_scoring_vector = vulnerability.get("scores", [{}])[0].get("cvss_v3", {}).get("vectorString", None)
        cve_cvss3_base_score = vulnerability.get("scores", [{}])[0].get("cvss_v3", {}).get("baseScore", None)
        cve_cwe = vulnerability.get("cwe", {}).get("id", None)
        red_hat_cve_set.add((cve_id, cve_cvss3_scoring_vector, cve_cvss3_base_score, cve_cwe))

        for bug_id in vulnerability.get("ids", []):
            if bug_id.get("system_name") == "Red Hat Bugzilla ID":
                red_hat_bugzilla_set.add(bug_id["text"])

    return {
        "red_hat_issued_at": str(red_hat_issued_at),
        "red_hat_updated_at": str(red_hat_updated_at),
        "name": str(name),
        "red_hat_synopsis": str(red_hat_synopsis),
        "red_hat_description": str(red_hat_description),
        "kind": str(kind),
        "severity": str(severity),
        "topic": str(topic),
        "red_hat_fixed_packages": list(red_hat_fixed_packages),
        "red_hat_cve_list": list(red_hat_cve_set),
        "red_hat_bugzilla_list": list(red_hat_bugzilla_set),
        "red_hat_affected_products": list(red_hat_affected_products),
    }


