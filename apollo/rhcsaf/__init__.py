import pathlib
import json

from common.logger import Logger
from apollo.rpm_helpers import parse_nevra

# Initialize Info before Logger for this module

logger = Logger()

def extract_rhel_affected_products_for_db(csaf):
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
        for b in vendor_branch.get("branches", []):
            if b.get("category") == "product_family" and b.get("name") == "Red Hat Enterprise Linux":
                family_branch = b
                break
        if not family_branch:
            continue
        # Find the product_name branch for CPE/version info
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

        # Parses the CPE string to extract major and minor version numbers
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

        # Collect all architecture branches at the same level as product_family
        arches = set()
        for branch in vendor_branch.get("branches", []):
            if branch.get("category") == "architecture":
                arch = branch.get("name")
                if arch:
                    arches.add(arch)
        # If 'noarch' is present, expand to all main architectures
        if "noarch" in arches:
            arches = set(main_arches)
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
    red_hat_fixed_packages = set()
    red_hat_cve_set = set()
    red_hat_bugzilla_set = set()
    product_id_suffix_list = (
        ".aarch64",
        ".i386",
        ".i686",
        ".noarch",
        ".ppc",
        ".ppc64",
        ".ppc64le",
        ".s390",
        ".s390x",
        ".src",
        ".x86_64"
    ) # TODO: find a better way to filter product IDs. This is a workaround for the fact that
    # the product IDs in the CSAF documents also contain artifacts like container images
    # and we only are interested in RPMs.
    for vulnerability in csaf["vulnerabilities"]:
        for product_id in vulnerability["product_status"]["fixed"]:
            if product_id.endswith(product_id_suffix_list):
                # These IDs are in the format product:package_nevra
                # ie- AppStream-9.4.0.Z.EUS:rsync-0:3.2.3-19.el9_4.1.aarch64"
                split_on_colon = product_id.split(":")
                product = split_on_colon[0]
                package_nevra = ":".join(split_on_colon[-2:])
                red_hat_fixed_packages.add(package_nevra)

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


