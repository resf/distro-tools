import datetime
import re
import bz2
from typing import Optional
from xml.etree import ElementTree as ET

import aiohttp
from temporalio import activity
from tortoise.transactions import in_transaction

from apollo.db import RedHatIndexState, RedHatAdvisory, RedHatAdvisoryPackage
from apollo.db import RedHatAdvisoryBugzillaBug, RedHatAdvisoryAffectedProduct, RedHatAdvisoryCVE
from apollo.rherrata import API

from common.logger import Logger

OVAL_NS = {"": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
bz_re = re.compile(r"BZ#([0-9]+)")


def parse_red_hat_date(rhdate: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(rhdate.removesuffix("Z"))


@activity.defn
async def get_last_indexed_date() -> Optional[str]:
    state = await RedHatIndexState.get_or_none()
    return re.sub(
        r"\+\d\d:\d\d",
        "",
        state.last_indexed_at.isoformat("T") + "Z",
    ) if state else None


async def fetch_mapped_oval() -> dict[str, ET.ElementTree]:
    # Download the oval_url using aiohttp, decompress using bzip and parse
    oval_url = "https://access.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2"
    async with aiohttp.ClientSession() as session:
        async with session.get(oval_url) as response:
            if response.status == 200:
                data = await response.read()
                tree = ET.fromstring(bz2.decompress(data))

                # Index by advisory name
                def_map = {}
                definitions = tree.findall("definitions/definition", OVAL_NS)
                for definition in definitions:
                    def_id = definition.attrib["id"]
                    id_split = def_id.split(":")
                    name = f"{id_split[1].split('.')[2].upper()}-{id_split[3][0:4]}:{id_split[3][4:]}"
                    def_map[name] = definition

                return def_map
            else:
                raise Exception("Failed to fetch OVAL data")


@activity.defn
async def get_rh_advisories(from_timestamp: str = None) -> None:
    logger = Logger()
    advisories = await API().search(
        from_date=from_timestamp, rows=10000, sort_asc=True
    )
    oval = await fetch_mapped_oval()

    for advisory in advisories:
        async with in_transaction():
            advisory_last_indexed_at = parse_red_hat_date(
                advisory.portal_publication_date
            )
            state = await RedHatIndexState.first()
            if state:
                state.last_indexed_at = advisory_last_indexed_at
                await state.save()
            else:
                await RedHatIndexState().create(
                    last_index_at=advisory_last_indexed_at
                )

            logger.info("Processing advisory %s", advisory.id)

            existing_advisory = await RedHatAdvisory.filter(name=advisory.id
                                                           ).get_or_none()
            if existing_advisory:
                logger.info("Advisory %s already exists, skipping", advisory.id)
                continue

            kind = "Security"
            if "Enhancement" in advisory.portal_advisory_type:
                kind = "Enhancement"
            elif "Bug Fix" in advisory.portal_advisory_type:
                kind = "Bug Fix"

            issued_at = parse_red_hat_date(advisory.portal_publication_date)
            severity = advisory.portal_severity
            if not severity or severity == "":
                severity = "None"

            ra = await RedHatAdvisory.create(
                name=advisory.id,
                red_hat_issued_at=issued_at,
                synopsis=advisory.portal_synopsis,
                description=advisory.portal_description,
                kind=kind,
                severity=severity,
                topic="",
            )

            if advisory.portal_package:
                await RedHatAdvisoryPackage.bulk_create(
                    [
                        RedHatAdvisoryPackage(
                            **{
                                "red_hat_advisory_id": ra.id,
                                "nevra": nevra
                            }
                        ) for nevra in advisory.portal_package
                    ],
                    ignore_conflicts=True
                )

            if advisory.portal_CVE:
                cves_to_save = []

                definition = oval.get(advisory.id)
                if not definition:
                    # Fill in CVEs from Errata
                    for advisory_cve in advisory.portal_CVE:
                        cves_to_save.append(
                            RedHatAdvisoryCVE(
                                **{
                                    "red_hat_advisory_id": ra.id,
                                    "cve": advisory_cve,
                                    "cvss3_scoring_vector": "UNKNOWN",
                                    "cvss3_base_score": "UNKNOWN",
                                    "cwe": "UNKNOWN",
                                }
                            )
                        )
                else:
                    # Fetch CVEs from the OVAL
                    cves = definition.findall("metadata/advisory/cve", OVAL_NS)
                    for cve in cves:
                        cvss3_scoring_vector = "UNKNOWN"
                        cvss3_base_score = "UNKNOWN"

                        cvss3 = cve.attrib.get("cvss3")
                        if cvss3:
                            cvss3_raw = cvss3.split("/", 1)
                            cvss3_scoring_vector = cvss3_raw[
                                1] if cvss3_raw else "UNKNOWN"
                            cvss3_base_score = cvss3_raw[
                                0] if cvss3_raw else "UNKNOWN"

                        cwe = cve.attrib.get("cwe")
                        if not cwe:
                            cwe = "UNKNOWN"

                        cves_to_save.append(
                            RedHatAdvisoryCVE(
                                **{
                                    "red_hat_advisory_id":
                                        ra.id,
                                    "cve":
                                        cve.text,
                                    "cvss3_scoring_vector":
                                        cvss3_scoring_vector,
                                    "cvss3_base_score":
                                        cvss3_base_score,
                                    "cwe":
                                        cwe,
                                }
                            )
                        )

                if not cves_to_save:
                    raise Exception(f"Failed to find CVEs for {advisory.id}")

                await RedHatAdvisoryCVE.bulk_create(
                    cves_to_save,
                    ignore_conflicts=True,
                )

            if advisory.portal_BZ:
                bz_map = {}
                if advisory.portal_description:
                    for line in advisory.portal_description.splitlines():
                        search = bz_re.search(line)
                        if search:
                            bz_id = search.group(1)
                            bz_line = line.removeprefix("* ")
                            bz_line = line.removeprefix("* ")
                            bz_line = line.removeprefix("- ")
                            bz_line = line.replace(f"(BZ#{bz_id})", "")
                            bz_line = bz_line.strip()
                            bz_map[bz_id] = bz_line

                await RedHatAdvisoryBugzillaBug.bulk_create(
                    [
                        RedHatAdvisoryBugzillaBug(
                            **{
                                "red_hat_advisory_id": ra.id,
                                "bugzilla_bug_id": bugzilla_bug_id,
                                "description": bz_map.get(bugzilla_bug_id, ""),
                            }
                        ) for bugzilla_bug_id in advisory.portal_BZ
                    ],
                    ignore_conflicts=True
                )

            affected_products = advisory.get_products()
            if affected_products:
                await RedHatAdvisoryAffectedProduct.bulk_create(
                    [
                        RedHatAdvisoryAffectedProduct(
                            **{
                                "red_hat_advisory_id": ra.id,
                                "variant": product.variant,
                                "name": product.name,
                                "major_version": product.major_version,
                                "minor_version": product.minor_version,
                                "arch": product.arch
                            }
                        ) for product in affected_products
                    ],
                    ignore_conflicts=True
                )

            logger.info("Processed advisory %s", advisory.id)

    return None
