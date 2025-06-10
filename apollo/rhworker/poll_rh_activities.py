from datetime import datetime
import re
import bz2
from typing import Optional
from xml.etree import ElementTree as ET
import csv
import io
from datetime import datetime, timedelta, timezone


import aiohttp
from temporalio import activity
from tortoise.transactions import in_transaction

from apollo.db import RedHatIndexState, RedHatAdvisory, RedHatAdvisoryPackage
from apollo.db import (
    RedHatAdvisoryBugzillaBug,
    RedHatAdvisoryAffectedProduct,
    RedHatAdvisoryCVE,
)
from apollo.rherrata import API
from apollo.rhcsaf import red_hat_advisory_scraper

from common.logger import Logger

OVAL_NS = {"": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
bz_re = re.compile(r"BZ#([0-9]+)")


async def create_or_update_advisory_packages(
    advisory: RedHatAdvisory,
    new_nevras: set,
    update_advisory: bool = False,
) -> None:
    """
    Add new RedHatAdvisoryPackage entries for the given advisory.
    If update_advisory is True, remove packages not in the new set.
    """
    logger = Logger()
    logger.info(f"Creating or updating packages for advisory {advisory.name}")

    existing_packages = set(
        p.nevra for p in await RedHatAdvisoryPackage.filter(red_hat_advisory_id=advisory.id).all()
    )

    # Add new packages
    to_add = new_nevras - existing_packages
    if to_add:
        logger.info(f"Adding new packages for advisory {advisory.name}: {to_add}")
        await RedHatAdvisoryPackage.bulk_create([
            RedHatAdvisoryPackage(
                red_hat_advisory_id=advisory.id,
                nevra=nevra
            ) for nevra in to_add
        ], ignore_conflicts=True)
    else:
        logger.info(f"No new packages to add for advisory {advisory.name}")

    # Remove packages not in the new set if updating
    if update_advisory:
        to_remove = existing_packages - new_nevras
        if to_remove:
            logger.info(f"Removing packages for advisory {advisory.name}: {to_remove}")
            await RedHatAdvisoryPackage.filter(
                red_hat_advisory_id=advisory.id, nevra__in=list(to_remove)
            ).delete()
        else:
            logger.info(f"No packages to remove for advisory {advisory.name}")


async def create_or_update_advisory_cves(
    advisory: RedHatAdvisory,
    new_cve_tuples: set,
    update_advisory: bool = False,
) -> None:
    """
    Add new RedHatAdvisoryCVE entries for the given advisory.
    If update_advisory is True, remove CVEs not in the new set.
    new_cve_tuples: set of (cve_id, vector, score, cwe)
    """
    logger = Logger()
    logger.info(f"Creating or updating CVEs for advisory {advisory.name}")

    # Get existing CVEs for this advisory
    existing_cves = {
        (c.cve, c.cvss3_scoring_vector, c.cvss3_base_score, c.cwe)
        for c in await RedHatAdvisoryCVE.filter(red_hat_advisory_id=advisory.id).all()
    }
    existing_cve_ids = {c[0] for c in existing_cves}
    new_cve_ids = {c[0] for c in new_cve_tuples}

    # Add new CVEs
    to_add = new_cve_tuples - existing_cves
    if to_add:
        logger.info(f"Adding new CVEs for advisory {advisory.name}: {to_add}")
        await RedHatAdvisoryCVE.bulk_create([
            RedHatAdvisoryCVE(
                red_hat_advisory_id=advisory.id,
                cve=cve_id,
                cvss3_scoring_vector=vector,
                cvss3_base_score=str(score) if score else None,
                cwe=cwe if cwe else None,
            ) for (cve_id, vector, score, cwe) in to_add
        ], ignore_conflicts=True)
    else:
        logger.info(f"No new CVEs to add for advisory {advisory.name}")

    # Remove CVEs not in the new set if updating
    if update_advisory:
        to_remove_ids = existing_cve_ids - new_cve_ids
        if to_remove_ids:
            logger.info(f"Removing CVEs for advisory {advisory.name}: {to_remove_ids}")
            await RedHatAdvisoryCVE.filter(
                red_hat_advisory_id=advisory.id, cve__in=list(to_remove_ids)
            ).delete()
        else:
            logger.info(f"No CVEs to remove for advisory {advisory.name}")


async def create_or_update_advisory_bugzilla_bugs(
    advisory,
    new_bug_ids: set,
    update_advisory: bool = False,
) -> None:
    """
    Add new RedHatAdvisoryBugzillaBug entries for the given advisory.
    If update_advisory is True, remove bugs not in the new set.
    """
    logger = Logger()
    logger.info(f"Creating or updating Bugzilla bugs for advisory {advisory.name}")

    # Get existing Bugzilla bug IDs for this advisory
    existing_bugs = set(
        b.bugzilla_bug_id for b in await RedHatAdvisoryBugzillaBug.filter(red_hat_advisory_id=advisory.id).all()
    )

    # Add new bugs
    to_add = new_bug_ids - existing_bugs
    if to_add:
        logger.info(f"Adding new Bugzilla bugs for advisory {advisory.name}: {to_add}")
        await RedHatAdvisoryBugzillaBug.bulk_create([
            RedHatAdvisoryBugzillaBug(
                red_hat_advisory_id=advisory.id,
                bugzilla_bug_id=bug_id,
                description=""  # No description available in CSAF data
            ) for bug_id in to_add
        ], ignore_conflicts=True)
    else:
        logger.info(f"No new Bugzilla bugs to add for advisory {advisory.name}")

    # Remove bugs not in the new set if updating
    if update_advisory:
        to_remove = existing_bugs - new_bug_ids
        if to_remove:
            logger.info(f"Removing Bugzilla bugs for advisory {advisory.name}: {to_remove}")
            await RedHatAdvisoryBugzillaBug.filter(
                red_hat_advisory_id=advisory.id, bugzilla_bug_id__in=list(to_remove)
            ).delete()
        else:
            logger.info(f"No Bugzilla bugs to remove for advisory {advisory.name}")


async def create_or_update_advisory_affected_products(
    advisory,
    new_products: set,
    update_advisory: bool = False,
) -> None:
    """
    Add new RedHatAdvisoryAffectedProduct entries for the given advisory.
    If update_advisory is True, remove affected products not in the new set.
    new_products: set of (variant, name, major_version, minor_version, arch)
    """
    logger = Logger()
    logger.info(f"Creating or updating affected products for advisory {advisory.name}")

    # Get existing affected products for this advisory
    existing_products = {
        (p.variant, p.name, p.major_version, p.minor_version, p.arch)
        for p in await RedHatAdvisoryAffectedProduct.filter(red_hat_advisory_id=advisory.id).all()
    }

    # Add new affected products
    to_add = new_products - existing_products
    if to_add:
        logger.info(f"Adding new affected products for advisory {advisory.name}: {to_add}")
        await RedHatAdvisoryAffectedProduct.bulk_create([
            RedHatAdvisoryAffectedProduct(
                red_hat_advisory_id=advisory.id,
                variant=variant,
                name=name,
                major_version=major,
                minor_version=minor,
                arch=arch,
            ) for (variant, name, major, minor, arch) in to_add
        ], ignore_conflicts=True)
    else:
        logger.info(f"No new affected products to add for advisory {advisory.name}")

    # Remove affected products not in the new set if updating
    if update_advisory:
        to_remove = existing_products - new_products
        if to_remove:
            logger.info(f"Removing affected products for advisory {advisory.name}: {to_remove}")
            for (variant, name, major, minor, arch) in to_remove:
                await RedHatAdvisoryAffectedProduct.filter(
                    red_hat_advisory_id=advisory.id,
                    variant=variant,
                    name=name,
                    major_version=major,
                    minor_version=minor,
                    arch=arch,
                ).delete()
        else:
            logger.info(f"No affected products to remove for advisory {advisory.name}")


def parse_red_hat_date(rhdate: str) -> datetime:
    return datetime.fromisoformat(rhdate.removesuffix("Z"))


def standardize_datetime_string(dt_str: str) -> str:
    """Standardize datetime string format by ensuring proper formatting of timezone"""
    # Remove any colons from timezone part
    if '+' in dt_str:
        base, tz = dt_str.split('+')
        tz = tz.replace(':', '')
        return f"{base}+{tz}"
    return dt_str


def parse_datetime(dt_str: str) -> datetime:
    """Parse datetime string with various formats"""
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",  # 2025-04-17T12:08:56+0000
        "%Y-%m-%dT%H%M%S%z",    # 2025-04-17T143259+0000
        "%Y-%m-%d %H:%M:%S%z"   # 2025-04-17 14:32:59+0000
    ]

    dt_str = standardize_datetime_string(dt_str)

    for fmt in formats:
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unable to parse datetime string: {dt_str}")

async def upsert_last_indexed_at(new_date: datetime) -> None:
    """
    Create or update the last_indexed_at field in red_hat_index_state,
    but only update if new_date is after the current value.
    """
    logger = Logger()
    state = await RedHatIndexState.first()
    if isinstance(new_date, str):
        logger.debug("new_date is a string, converting to datetime")
        new_date = parse_datetime(new_date)
    if isinstance(state, str):
        logger.debug("state is a string, converting to datetime")
        state = parse_datetime(state)
    logger.debug(f"Current state: {state}, new_date: {new_date}")
    if state:
        if not state.last_indexed_at or new_date > state.last_indexed_at:
            state.last_indexed_at = new_date
            await state.save()
    else:
        await RedHatIndexState.create(last_indexed_at=new_date)

@activity.defn
async def get_last_indexed_date() -> Optional[str]:
    state = await RedHatIndexState.get_or_none()
    return (
        re.sub(
            r"\+\d\d:\d\d",
            "",
            state.last_indexed_at.isoformat("T") + "Z",
        )
        if state
        else None
    )


async def fetch_mapped_oval() -> dict[str, ET.ElementTree]:
    # Download the oval_url using aiohttp, decompress using bzip and parse
    oval_urls = (
        'https://access.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2',
        'https://access.redhat.com/security/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2',
    )
    def_map = {}
    for url in oval_urls:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.read()
                    tree = ET.fromstring(bz2.decompress(data))

                    # Index by advisory name
                    definitions = tree.findall("definitions/definition", OVAL_NS)
                    for definition in definitions:
                        def_id = definition.attrib["id"]
                        id_split = def_id.split(":")
                        name = f"{id_split[1].split('.')[2].upper()}-{id_split[3][0:4]}:{id_split[3][4:]}"
                        def_map[name] = definition

                else:
                    raise Exception("Failed to fetch OVAL data")

    return def_map

@activity.defn
async def get_rh_advisories(from_timestamp: str = None) -> None:
    logger = Logger()
    advisories = await API().search(from_date=from_timestamp, rows=999, sort_asc=True)
    oval = await fetch_mapped_oval()

    for advisory in advisories:
        async with in_transaction():
            advisory_last_indexed_at = parse_red_hat_date(
                advisory.portal_publication_date
            )
            await upsert_last_indexed_at(advisory_last_indexed_at)

            logger.info("Processing advisory %s", advisory.id)

            existing_advisory = await RedHatAdvisory.filter(
                name=advisory.id
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
                            **{"red_hat_advisory_id": ra.id, "nevra": nevra}
                        )
                        for nevra in advisory.portal_package
                    ],
                    ignore_conflicts=True,
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
                            cvss3_scoring_vector = (
                                cvss3_raw[1] if cvss3_raw else "UNKNOWN"
                            )
                            cvss3_base_score = cvss3_raw[0] if cvss3_raw else "UNKNOWN"

                        cwe = cve.attrib.get("cwe")
                        if not cwe:
                            cwe = "UNKNOWN"

                        cves_to_save.append(
                            RedHatAdvisoryCVE(
                                **{
                                    "red_hat_advisory_id": ra.id,
                                    "cve": cve.text,
                                    "cvss3_scoring_vector": cvss3_scoring_vector,
                                    "cvss3_base_score": cvss3_base_score,
                                    "cwe": cwe,
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
                        )
                        for bugzilla_bug_id in advisory.portal_BZ
                    ],
                    ignore_conflicts=True,
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
                                "arch": product.arch,
                            }
                        )
                        for product in affected_products
                    ],
                    ignore_conflicts=True,
                )

            logger.info("Processed advisory %s", advisory.id)

    return None

async def process_csaf_file(json_data: dict, filepath: str) -> Optional[RedHatAdvisory]:
    """Process a CSAF file and insert/update the data in the database"""
    logger = Logger()
    data = red_hat_advisory_scraper(json_data)
    if not data:
        logger.warning(f"No data returned from scraper for {filepath}")
        return None
    # Check if advisory has any fixed packages. If not, skip it. It could have no fixed packages
    # because there were not packages for a Red Hat product starting with "Red Hat Enterprise Linux"
    if not data.get("red_hat_fixed_packages"):
        logger.warning(f"No fixed packages found in CSAF document {filepath}")
        return None
    update_advisory = False
    try:
        async with in_transaction():
            # Check if advisory already exists
            logger.info(f"Starting transaction for {filepath}")
            advisory = await RedHatAdvisory.get_or_none(name=data["name"])

            if advisory:
                logger.info(f"Advisory {advisory.name} already exists, checking for updates")
                # Update existing advisory if fields are different
                updates = {}
                if parse_datetime(str(advisory.red_hat_issued_at)) != parse_datetime(data["red_hat_issued_at"]):
                    logger.info(f"date from DB: {advisory.red_hat_issued_at} != date from CSAF: {data['red_hat_issued_at']}")
                    updates["red_hat_issued_at"] = parse_datetime(data["red_hat_issued_at"])

                # TODO: Update DB to track Red Hat updated at date
                # if advisory.red_hat_updated_at is None:
                #     logger.info(f"advisory.red_hat_updated_at is None")
                # elif parse_datetime(str(advisory.red_hat_updated_at)) != parse_datetime(data["red_hat_updated_at"]):
                #     logger.info(f"date from DB: {advisory.red_hat_updated_at} != date from CSAF: {data['red_hat_updated_at']}")
                #     updates["red_hat_updated_at"] = parse_datetime(data["red_hat_updated_at"])

                if advisory.synopsis != data["red_hat_synopsis"]:
                    updates["synopsis"] = data["red_hat_synopsis"]
                if advisory.description != data["red_hat_description"]:
                    updates["description"] = data["red_hat_description"]
                if advisory.kind != data["kind"]:
                    updates["kind"] = data["kind"]
                if advisory.severity != data["severity"]:
                    updates["severity"] = data["severity"]
                if advisory.topic != data["topic"]:
                    updates["topic"] = data["topic"]

                if updates:
                    updates["updated_at"] = datetime.now()
                    for field, value in updates.items():
                        setattr(advisory, field, value)
                        await advisory.save()
                update_advisory = True
            else:
                # Create new advisory
                logger.info(f"Creating new advisory {data['name']}")
                advisory = await RedHatAdvisory.create(
                    red_hat_issued_at=datetime.fromisoformat(data["red_hat_issued_at"]),
                    # TODO: Update DB to track Red Hat updated at date
                    # red_hat_updated_at=datetime.fromisoformat(data["red_hat_updated_at"]),
                    name=data["name"],
                    synopsis=data["red_hat_synopsis"],
                    description=data["red_hat_description"],
                    kind=data["kind"],
                    severity=data["severity"],
                    topic=data["topic"],
                )

            # Handle packages
            logger.info(f"Processing packages for advisory {advisory.name}")
            new_nevras = set(data["red_hat_fixed_packages"])
            await create_or_update_advisory_packages(
                advisory, new_nevras, update_advisory=update_advisory
            )

            # Handle CVEs
            logger.info(f"Processing CVEs for advisory {advisory.name}")
            new_cve_tuples = set(tuple(cve_data) for cve_data in data["red_hat_cve_list"])
            await create_or_update_advisory_cves(
                advisory, new_cve_tuples, update_advisory=update_advisory
            )

            # Handle Bugzilla tickets
            logger.info(f"Processing Bugzilla bugs for advisory {advisory.name}")
            new_bug_ids = set(data["red_hat_bugzilla_list"])
            await create_or_update_advisory_bugzilla_bugs(
                advisory, new_bug_ids, update_advisory=update_advisory
            )

            # Handle affected products
            logger.info(f"Processing affected products for advisory {advisory.name}")
            new_products = set(data["red_hat_affected_products"])
            await create_or_update_advisory_affected_products(
                advisory, new_products, update_advisory=update_advisory
            )
    except Exception as e:
        logger.error(f"Error in transaction: {str(e)}")
        raise

    # Update RedHatIndexState with the latest indexed date
    latest_date_str = data.get("red_hat_updated_at") or data.get("red_hat_issued_at")
    logger.debug(f"Latest date string from {advisory.name} CSAF data: {latest_date_str}")
    await upsert_last_indexed_at(latest_date_str)

    return advisory


@activity.defn
async def process_csaf_files(from_timestamp: str = None) -> dict:
    logger = Logger()
    logger.info("Starting CSAF file processing (streaming from Red Hat)")

    base_url = "https://security.access.redhat.com/data/csaf/v2/advisories/"

    async def fetch_csv_with_dates(session, url):
        async with session.get(url) as resp:
            resp.raise_for_status()
            text = await resp.text()
            reader = csv.reader(io.StringIO(text))
            # Return dict: advisory_id -> timestamp
            return {
                row[0].strip('"'): row[1].strip('"')
                for row in reader
                if row and row[0].endswith(".json") and len(row) > 1
            }

    processed = 0
    errors = 0

    async with aiohttp.ClientSession() as session:
        logger.info("Fetching CSV files from Red Hat")
        changes = await fetch_csv_with_dates(session, base_url + "changes.csv")
        releases = await fetch_csv_with_dates(session, base_url + "releases.csv")
        deletions = await fetch_csv_with_dates(session, base_url + "deletions.csv")

        # Merge changes and releases, keeping the most recent timestamp for each advisory
        all_advisories = {**changes, **releases}
        # Remove deletions
        for advisory_id in deletions:
            all_advisories.pop(advisory_id, None)

        if from_timestamp:
            from_timestamp_dt = datetime.fromisoformat(from_timestamp.replace("Z", "+00:00"))
        else:
            from_timestamp_dt = None
        filtered_advisory_ids = []
        for advisory_id, timestamp in all_advisories.items():
            # If from_timestamp_dt is not set, include all advisories.
            # Otherwise, only include advisories with a timestamp >= from_timestamp_dt.
            if not from_timestamp_dt:
                filtered_advisory_ids.append(advisory_id)
            else:
                advisory_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if advisory_time >= from_timestamp_dt:
                    filtered_advisory_ids.append(advisory_id)

        logger.info(f"Found {len(filtered_advisory_ids)} advisories to process since last indexed date ({from_timestamp})")

        for advisory_id in filtered_advisory_ids: #TODO: parallelize this for faster processing
            json_url = base_url + advisory_id
            try:
                async with session.get(json_url) as resp:
                    if resp.status != 200:
                        logger.warning(f"Failed to fetch {json_url}: HTTP {resp.status}")
                        errors += 1
                        continue
                    csaf_json = await resp.json()
                    advisory = await process_csaf_file(csaf_json, advisory_id)
                    if advisory:
                        logger.info(f"Successfully processed {advisory_id}")
                        processed += 1
                    else:
                        logger.warning(f"Skipped {advisory_id} - no data returned")
            except Exception as e:
                logger.error(f"Error processing {advisory_id}: {str(e)}")
                errors += 1
                continue

    logger.info(f"Processing complete. Processed: {processed}, Errors: {errors}")
    return {"processed": processed, "errors": errors}