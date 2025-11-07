import pathlib
import json

from common.logger import Logger
from apollo.rpm_helpers import parse_nevra

# Initialize Info before Logger for this module

logger = Logger()

def _is_eus_product(product_name: str, cpe: str) -> bool:
    """
    Detects if a product is EUS-related based on product name and CPE.

    Args:
        product_name: Full product name (e.g., "Red Hat Enterprise Linux AppStream E4S (v.9.0)")
        cpe: CPE string (e.g., "cpe:/a:redhat:rhel_e4s:9.0::appstream")

    Returns:
        True if product is EUS/E4S/AUS/TUS, False otherwise
    """
    # Check CPE product field (most reliable indicator)
    if cpe:
        parts = cpe.split(":")
        if len(parts) > 3:
            cpe_product = parts[3]
            if cpe_product in ("rhel_eus", "rhel_e4s", "rhel_aus", "rhel_tus"):
                return True

    # Check product name keywords as fallback
    if product_name:
        name_lower = product_name.lower()
        eus_keywords = ["e4s", "eus", "aus", "tus", "extended update support",
                       "update services for sap", "advanced update support",
                       "telecommunications update service"]
        for keyword in eus_keywords:
            if keyword in name_lower:
                return True

    return False


def extract_rhel_affected_products_for_db(csaf: dict) -> set:
    """
    Extracts all needed info for red_hat_advisory_affected_products table from CSAF product_tree.
    Expands 'noarch' to all main arches and maps names to user-friendly values.
    Returns a set of tuples: (variant, name, major_version, minor_version, arch)
    """
    # Maps architecture short names to user-friendly product names
    arch_name_map = {
        "aarch64": "Red Hat Enterprise Linux for ARM 64",
        "x86_64": "Red Hat Enterprise Linux for x86_64",
        "s390x": "Red Hat Enterprise Linux for IBM z Systems",
        "ppc64le": "Red Hat Enterprise Linux for Power, little endian",
    }
    # List of main architectures to expand 'noarch'
    main_arches = list(arch_name_map.keys())
    affected_products = set()
    product_tree = csaf.get("product_tree", {})
    if not product_tree:
        logger.warning("No product tree found in CSAF document")
        return affected_products

    # Iterate over all vendor branches in the product tree
    for vendor_branch in product_tree.get("branches", []):
        # Find the product_family branch for RHEL
        family_branch = None
        arches = set()
        for branch in vendor_branch.get("branches", []):
            if branch.get("category") == "product_family" and branch.get("name") == "Red Hat Enterprise Linux":
                family_branch = branch
            # Collect all architecture branches at the same level as product_family
            elif branch.get("category") == "architecture":
                arch = branch.get("name")
                if arch:
                    arches.add(arch)
        # If 'noarch' is present, expand to all main architectures
        if "noarch" in arches:
            arches = set(main_arches)
        if not family_branch:
            continue
        # Find the product_name branch for CPE/version info
        prod_name = None
        cpe = None
        product_full_name = None
        for branch in family_branch.get("branches", []):
            if branch.get("category") == "product_name":
                prod = branch.get("product", {})
                prod_name = prod.get("name")
                product_full_name = prod.get("name")
                cpe = prod.get("product_identification_helper", {}).get("cpe")
                break
        if not prod_name or not cpe:
            continue

        # Skip if this is an EUS product
        if _is_eus_product(product_full_name, cpe):
            logger.debug(f"Skipping EUS product: {product_full_name}")
            continue

        # Parses the CPE string to extract major and minor version numbers
        # Example CPE: "cpe:/a:redhat:enterprise_linux:9::appstream"
        parts = cpe.split(":")  # Split the CPE string by colon
        major = None
        minor = None
        if len(parts) > 4:
            version = parts[4]  # The version is typically the 5th field (index 4)
            if version:
                if "." in version:
                    # If the version contains a dot, split into major and minor
                    major, minor = version.split(".", 1)
                    major = int(major)
                    minor = int(minor)
                else:
                    # If no dot, only major version is present
                    major = int(version)

        # For each architecture, add a tuple with product info to the set
        for arch in arches:
            name = arch_name_map.get(arch)
            if name is None:
                logger.warning(f"'{arch}' not in arch_name_map, skipping.")
                continue
            if major:
                affected_products.add((
                    family_branch.get("name"),  # variant (e.g., "Red Hat Enterprise Linux")
                    name,                        # user-friendly architecture name
                    major,                       # major version number
                    minor,                       # minor version number (may be None)
                    arch                         # architecture short name
                ))
    logger.debug(f"Number of affected products: {len(affected_products)}")
    return affected_products


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
    packages = set()
    product_tree = csaf.get("product_tree", {})

    if not product_tree:
        return packages

    # Build a map of product_id -> is_eus
    product_eus_map = {}

    def traverse_for_eus(branches):
        """Recursively traverse to build EUS map"""
        for branch in branches:
            category = branch.get("category")

            # Check if this is a product_name with CPE
            if category == "product_name":
                prod = branch.get("product", {})
                product_id = prod.get("product_id")
                product_name = prod.get("name", "")
                cpe = prod.get("product_identification_helper", {}).get("cpe", "")

                if product_id:
                    is_eus = _is_eus_product(product_name, cpe)
                    product_eus_map[product_id] = is_eus

            # Recurse into nested branches
            if "branches" in branch:
                traverse_for_eus(branch["branches"])

    # First pass: build EUS map
    for vendor_branch in product_tree.get("branches", []):
        traverse_for_eus(vendor_branch.get("branches", []))

    # Now extract packages from product_version entries
    def extract_packages_from_branches(branches):
        """Recursively traverse to extract packages"""
        for branch in branches:
            category = branch.get("category")

            if category == "product_version":
                prod = branch.get("product", {})
                product_id = prod.get("product_id")
                purl = prod.get("product_identification_helper", {}).get("purl")

                # Skip if no product_id
                if not product_id:
                    continue

                # Check if this is an RPM using PURL (not container or other)
                if purl and not purl.startswith("pkg:rpm/"):
                    continue

                # Skip if product is EUS (check product_id prefix)
                # Product IDs for packages can have format: "AppStream-9.0.0.Z.E4S:package-nevra"
                # or just "package-nevra" for packages in product_version entries
                # We need to check if any parent product is EUS
                skip_eus = False
                for eus_prod_id, is_eus in product_eus_map.items():
                    if is_eus and (":" in product_id and product_id.startswith(eus_prod_id + ":")):
                        skip_eus = True
                        break

                if skip_eus:
                    continue

                # Extract NEVRA from product_id
                # Format: "package-epoch:version-release.arch" or "package-epoch:version-release.arch::module:stream"
                nevra = product_id

                # For modular packages, strip off the "::module:stream" suffix
                if "::" in nevra:
                    nevra = nevra.split("::")[0]

                if nevra:
                    packages.add(nevra)

            # Recurse
            if "branches" in branch:
                extract_packages_from_branches(branch["branches"])

    # Second pass: extract packages
    for vendor_branch in product_tree.get("branches", []):
        extract_packages_from_branches(vendor_branch.get("branches", []))

    return packages


def red_hat_advisory_scraper(csaf: dict):
    # At the time of writing there are ~254 advisories that do not have any vulnerabilities.
    if not csaf.get("vulnerabilities"):
        logger.warning("No vulnerabilities found in CSAF document")
        return None

    # red_hat_advisories table values
    red_hat_issued_at = csaf["document"]["tracking"]["initial_release_date"] # "2025-02-24T03:42:46+00:00"
    red_hat_updated_at = csaf["document"]["tracking"]["current_release_date"] # "2025-04-17T12:08:56+00:00"
    name = csaf["document"]["tracking"]["id"] # "RHSA-2025:1234"
    red_hat_synopsis = csaf["document"]["title"] # "Red Hat Bug Fix Advisory: Red Hat Quay v3.13.4 bug fix release"
    red_hat_description = None
    topic = None
    for item in csaf["document"]["notes"]:
        if item["category"] == "general":
            red_hat_description = item["text"]
        elif item["category"] == "summary":
            topic = item["text"]
    kind_lookup = {"RHSA": "Security", "RHBA": "Bug Fix", "RHEA": "Enhancement"}
    kind = kind_lookup[name.split("-")[0]] # "RHSA-2025:1234" --> "Security"
    severity = csaf["document"]["aggregate_severity"]["text"] # "Important"

    # To maintain consistency with the existing database, we need to replace the
    # "Red Hat [KIND] Advisory:" prefixes with the severity level.
    red_hat_synopsis = red_hat_synopsis.replace("Red Hat Bug Fix Advisory: ", f"{severity}:")
    red_hat_synopsis = red_hat_synopsis.replace("Red Hat Security Advisory:", f"{severity}:")
    red_hat_synopsis = red_hat_synopsis.replace("Red Hat Enhancement Advisory: ", f"{severity}:")

    # red_hat_advisory_packages table values
    # Extract packages from product_tree (handles both regular and modular packages)
    red_hat_fixed_packages = _extract_packages_from_product_tree(csaf)

    red_hat_cve_set = set()
    red_hat_bugzilla_set = set()

    for vulnerability in csaf["vulnerabilities"]:
        # red_hat_advisory_cves table values. Many older advisories do not have CVEs and so we need to handle that.
        cve_id = vulnerability.get("cve", None)
        cve_cvss3_scoring_vector = vulnerability.get("scores", [{}])[0].get("cvss_v3", {}).get("vectorString", None)
        cve_cvss3_base_score = vulnerability.get("scores", [{}])[0].get("cvss_v3", {}).get("baseScore", None)
        cve_cwe = vulnerability.get("cwe", {}).get("id", None)
        red_hat_cve_set.add((cve_id, cve_cvss3_scoring_vector, cve_cvss3_base_score, cve_cwe))

        # red_hat_advisory_bugzilla_bugs table values
        for bug_id in vulnerability.get("ids", []):
            if bug_id.get("system_name") == "Red Hat Bugzilla ID":
                red_hat_bugzilla_set.add(bug_id["text"])

    # red_hat_advisory_affected_products table values
    red_hat_affected_products = extract_rhel_affected_products_for_db(csaf)

    # If all products were EUS (none left after filtering), skip this advisory
    if len(red_hat_affected_products) == 0:
        logger.info(f"Skipping advisory {name}: all products are EUS-only")
        return None

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


