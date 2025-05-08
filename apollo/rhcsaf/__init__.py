import pathlib
import json
import os
import re

from common.info import Info
from common.logger import Logger
from apollo.rpm_helpers import parse_nevra

# Initialize Info before Logger for this module

logger = Logger()
# logger = logging.getLogger(__name__)
# # Add a StreamHandler to output logs to the console
# console_handler = logging.StreamHandler()
# console_handler.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(levelname)s - %(message)s')
# console_handler.setFormatter(formatter)
# logger.addHandler(console_handler)


def red_hat_advisory_scraper(filename: pathlib.Path):
    logger.info(f"Parsing CSAF document{filename}")
    with open(filename, "r") as f:
        csaf = json.load(f)
    
    # At the time of writing there are ~254 advisories that do not have any vulnerabilities.
    if not csaf.get("vulnerabilities"):
        logger.warning("No vulnerabilities found in CSAF document %s", filename)
        return None

    # red_hat_advisories table values
    red_hat_issued_at = csaf["document"]["tracking"]["initial_release_date"] # "2025-02-24T03:42:46+00:00"
    red_hat_updated_at = csaf["document"]["tracking"]["current_release_date"] # "2025-04-17T12:08:56+00:00"
    name = csaf["document"]["tracking"]["id"] # "RHSA-2025:1234"
    red_hat_synopsis = csaf["document"]["title"] # "Red Hat Bug Fix Advisory: Red Hat Quay v3.13.4 bug fix release"
    red_hat_description = None
    for item in csaf["document"]["notes"]:
        if item["category"] == "general":
            red_hat_description = item["text"]
    kind_lookup = {"RHSA": "Security", "RHBA": "Bug Fix", "RHEA": "Enhancement"}
    kind = kind_lookup[name.split("-")[0]] # "RHSA-2025:1234" --> "Security"
    severity = csaf["document"]["aggregate_severity"]["text"] # "Important"

    # To maintain consistency with the existing database, we need to replace the
    # "Red Hat [KIND] Advisory:" prefixes with the severity level.
    red_hat_synopsis = red_hat_synopsis.replace("Red Hat Bug Fix Advisory: ", f"{severity}:")
    red_hat_synopsis = red_hat_synopsis.replace("Red Hat Security Advisory:", f"{severity}:")
    red_hat_synopsis = red_hat_synopsis.replace("Red Hat Enhancement Advisory: ", f"{severity}:")

    topic = None
    for item in csaf["document"]["notes"]:
        if item["category"] == "summary":
            topic = item["text"]

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
        for bug in vulnerability["references"]:
            if bug["category"] == "external" and "bugzilla" in bug["url"]:
                bugzilla_id = bug["url"].split("?")[-1].split("=")[-1] # "https://bugzilla.redhat.com/show_bug.cgi?id=123456" --> "123456"
                red_hat_bugzilla_set.add(bugzilla_id)

    # red_hat_advisory_affected_products table values
    red_hat_affected_products = set()
    for package_nevra in red_hat_fixed_packages:
        product_info = parse_nevra(package_nevra)
        if product_info:
            # Create a tuple of values to add to the set
            product_tuple = (
                "Red Hat Enterprise Linux",
                f"Red Hat Enterprise Linux {product_info['dist_major']}",
                product_info["dist_major"],
                product_info["dist_minor"],
                product_info["arch"]
            )
            red_hat_affected_products.add(product_tuple)

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


