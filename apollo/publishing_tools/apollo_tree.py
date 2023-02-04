#!/usr/bin/env python3

import os
import argparse
import asyncio
import logging
import hashlib
import gzip
from dataclasses import dataclass
import time
from urllib.parse import quote
from xml.etree import ElementTree as ET

import aiohttp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("apollo_tree")

NS = {
    "": "http://linux.duke.edu/metadata/repo",
    "rpm": "http://linux.duke.edu/metadata/rpm"
}


@dataclass
class Repository:
    base_repomd: str = None
    source_repomd: str = None
    debug_repomd: str = None
    arch: str = None


async def scan_path(
    base_path: str,
    fmt: str,
    ignore_repos: list[str],
    ignore_arches: list[str],
):
    """
    Scan base path for repositories
    The format string can contain $reponame and $arch
    When we reach $reponame, that means we have found a repository
    Follow the path further into the tree until $arch is found
    That determines the architecture of the repository
    """

    repos = {}

    # First we need to find the root.
    # Construct root by prepending base_path and all parts until $reponame
    # Then we can walk the tree from there
    root = base_path
    parts = fmt.split("/")
    repo_first = True
    if "$reponame" in parts:
        for part in parts:
            parts.pop(0)
            if part == "$reponame":
                break
            if part == "$arch":
                repo_first = False
                break
            root = os.path.join(root, part)

    logger.info("Found root: %s", root)

    # Walk the base path
    for directory in os.listdir(root):
        current_parts = parts
        if repo_first:
            repo_name = directory
            if repo_name in ignore_repos:
                logger.info("Ignoring repo: %s", repo_name)
                continue
            logger.info("Found repo: %s", repo_name)
        else:
            arch = directory
            if arch in ignore_arches:
                logger.info("Ignoring arch: %s", arch)
                continue
            logger.info("Found arch: %s", arch)
        repo_base = os.path.join(root, directory)

        if repo_first:
            repos[repo_name] = []

        # Construct repo base until we reach $arch
        if "$arch" in current_parts:
            for part in current_parts:
                if (part == "$arch" and repo_first) or part == "$reponame":
                    break
                repo_base = os.path.join(repo_base, part)
                current_parts.pop(0)

        logger.warning("Searching for arches in %s", repo_base)

        if not os.path.isdir(repo_base):
            logger.warning("Path is not a directory: %s, skipping", repo_base)
            continue

        # All dirs in repo_base is an architecture
        for arch_ in os.listdir(repo_base):
            if repo_first:
                arch = arch_
            else:
                repo_name = arch_
            # Now append each combination + rest of parts as repo_info
            if repo_first:
                logger.info("Found arch: %s", arch)
            else:
                logger.info("Found repo: %s", repo_name)

            if repo_first:
                found_path = f"{repo_base}/{arch}/{'/'.join(current_parts[1:])}"
            else:
                found_path = f"{repo_base}/{repo_name}/{'/'.join(current_parts[1:])}"

            # Verify that the path exists
            if not os.path.exists(found_path):
                logger.warning("Path does not exist: %s, skipping", found_path)
                continue

            repo = {
                "name": repo_name,
                "arch": arch,
                "found_path": found_path,
            }
            if repo_name not in repos:
                repos[repo_name] = []
            repos[repo_name].append(repo)

    return repos


async def fetch_updateinfo_from_apollo(
    repo: dict,
    product_name: str,
    api_base: str = None,
) -> str:
    pname_arch = product_name.replace("$arch", repo["arch"])
    if not api_base:
        api_base = "https://apollo.build.resf.org/api/v3/updateinfo"
    api_url = f"{api_base}/{quote(pname_arch)}/{quote(repo['name'])}/updateinfo.xml"
    api_url += f"?req_arch={repo['arch']}"

    logger.info("Fetching updateinfo from %s", api_url)
    async with aiohttp.ClientSession() as session:
        async with session.get(api_url) as resp:
            if resp.status != 200 and resp.status != 404:
                logger.warning(
                    "Failed to fetch updateinfo from %s, skipping", api_url
                )
                return None
            if resp.status != 200:
                raise Exception(f"Failed to fetch updateinfo from {api_url}")
            return await resp.text()


async def gzip_updateinfo(updateinfo: str) -> dict:
    # Gzip updateinfo, get both open and closed size as
    # well as the sha256sum for both

    # First get the sha256sum and size of the open updateinfo
    sha256sum = hashlib.sha256(updateinfo.encode("utf-8")).hexdigest()
    size = len(updateinfo)

    # Then gzip it and get hash and size
    gzipped = gzip.compress(updateinfo.encode("utf-8"), mtime=0)
    gzipped_sha256sum = hashlib.sha256(gzipped).hexdigest()
    gzipped_size = len(gzipped)

    return {
        "sha256sum": sha256sum,
        "size": size,
        "gzipped_sha256sum": gzipped_sha256sum,
        "gzipped_size": gzipped_size,
        "gzipped": gzipped,
    }


async def write_updateinfo_to_file(
    repomd_xml_path: str, updateinfo: dict
) -> str:
    # Write updateinfo to file
    repomd_dir = os.path.dirname(repomd_xml_path)
    gzipped_sum = updateinfo["gzipped_sha256sum"]
    updateinfo_path = os.path.join(
        repomd_dir, f"{gzipped_sum}-updateinfo.xml.gz"
    )
    with open(updateinfo_path, "wb") as f:
        f.write(updateinfo["gzipped"])

    return updateinfo_path


async def update_repomd_xml(repomd_xml_path: str, updateinfo: dict):
    # Update repomd.xml with new updateinfo
    gzipped_sum = updateinfo["gzipped_sha256sum"]
    updateinfo_path = f"{gzipped_sum}-updateinfo.xml.gz"

    # Parse repomd.xml
    ET.register_namespace("", NS[""])
    repomd_xml = ET.parse(repomd_xml_path).getroot()

    # Iterate over data and find type="updateinfo" and delete it
    existing_updateinfo_path = None
    for data in repomd_xml.findall("data", NS):
        data_type = data.attrib["type"]
        if not data_type:
            logger.warning("No type found in data, skipping")
            continue
        if data_type == "updateinfo":
            # Get the location of the updateinfo file
            location = data.find("location", NS)
            location_href = location.attrib["href"]
            existing_updateinfo_path = os.path.abspath(
                os.path.join(repomd_xml_path, "../..", location_href)
            )

            # Delete the data element
            repomd_xml.remove(data)

            break

    # Create new data element and set type to updateinfo
    data = ET.Element("data")
    data.set("type", "updateinfo")

    # Add checksum, open-checksum, location, timestamp, size and open-size
    checksum = ET.SubElement(data, "checksum")
    checksum.set("type", "sha256")
    checksum.text = updateinfo["gzipped_sha256sum"]

    open_checksum = ET.SubElement(data, "open-checksum")
    open_checksum.set("type", "sha256")
    open_checksum.text = updateinfo["sha256sum"]

    location = ET.SubElement(data, "location")
    location.set("href", f"repodata/{updateinfo_path}")

    timestamp = ET.SubElement(data, "timestamp")
    timestamp.text = str(int(time.time()))

    size = ET.SubElement(data, "size")
    size.text = str(updateinfo["gzipped_size"])

    open_size = ET.SubElement(data, "open-size")
    open_size.text = str(updateinfo["size"])

    # Add data to repomd.xml
    repomd_xml.append(data)

    # Create string
    ET.indent(repomd_xml)
    xml_str = ET.tostring(
        repomd_xml,
        xml_declaration=True,
        encoding="utf-8",
        short_empty_elements=True,
    )

    # Prepend declaration with double quotes
    xml_str = xml_str.decode("utf-8")
    xml_str = xml_str.replace("'", "\"")
    xml_str = xml_str.replace("utf-8", "UTF-8")

    # "Fix" closing tags to not have a space
    xml_str = xml_str.replace(" />", "/>")

    # Add xmlns:rpm
    xml_str = xml_str.replace(
        "repo\">",
        f"repo\" xmlns:rpm=\"{NS['rpm']}\">",
    )

    # Write to repomd.xml
    logger.info("Writing to %s", repomd_xml_path)
    with open(repomd_xml_path, "w", encoding="utf-8") as f:
        f.write(xml_str)

    # Delete old updateinfo file if not the same as the new one
    updinfo_base = os.path.basename(existing_updateinfo_path)
    if existing_updateinfo_path and updinfo_base != updateinfo_path:
        try:
            logger.info("Deleting %s", existing_updateinfo_path)
            os.remove(existing_updateinfo_path)
        except FileNotFoundError:
            logger.warning("File %s not found", existing_updateinfo_path)


async def run_apollo_tree(
    base_format: str,
    manual: bool,
    auto_scan: bool,
    path: str,
    ignore: list[str],
    ignore_arch: list[str],
    product_name: str,
):
    if manual:
        raise Exception("Manual mode not implemented yet")

    if auto_scan:
        repos = await scan_path(
            path,
            base_format,
            ignore,
            ignore_arch,
        )

        for _, repo_variants in repos.items():
            for repo in repo_variants:
                updateinfo = await fetch_updateinfo_from_apollo(
                    repo,
                    product_name,
                )
                if not updateinfo:
                    logger.warning("No updateinfo found for %s", repo["name"])
                    continue

                gzipped = await gzip_updateinfo(updateinfo)
                await write_updateinfo_to_file(
                    repo["found_path"],
                    gzipped,
                )
                await update_repomd_xml(
                    repo["found_path"],
                    gzipped,
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="apollo_tree",
        description="Apollo updateinfo.xml publisher (Local file tree)",
        epilog="(C) 2023 Rocky Enterprise Software Foundation, Inc.",
    )
    parser.add_argument(
        "-b",
        "--base-format",
        default="$reponame/$arch/os/repodata/repomd.xml",
        help="Format for main repo.xml file",
    )
    parser.add_argument(
        "-m",
        "--manual",
        action="store_true",
        help="Manual mode",
    )
    parser.add_argument(
        "-r",
        "--repos",
        nargs="+",
        action="append",
        default=[],
        help="Repositories to publish (manual mode), format: <arch>:<repomd>",
    )
    parser.add_argument(
        "-a",
        "--auto-scan",
        default=True,
        action="store_true",
        help="Automatically scan for repos",
    )
    parser.add_argument(
        "-p",
        "--path",
        help="Default path to scan for repos",
    )
    parser.add_argument(
        "-i",
        "--ignore",
        nargs="+",
        action="append",
        default=[],
        help="Repos to ignore in auto-scan mode",
    )
    parser.add_argument(
        "-x",
        "--ignore-arch",
        nargs="+",
        action="append",
        default=[],
        help="Arches to ignore in auto-scan mode",
    )
    parser.add_argument(
        "-n",
        "--product-name",
        required=True,
        help="Product name",
    )

    p_args = parser.parse_args()
    if p_args.auto_scan and p_args.manual:
        parser.error("Cannot use --auto-scan and --manual together")

    if p_args.manual and not p_args.repos:
        parser.error("Must specify repos to publish in manual mode")

    if p_args.auto_scan and not p_args.path:
        parser.error("Must specify path to scan for repos in auto-scan mode")

    asyncio.run(
        run_apollo_tree(
            p_args.base_format,
            p_args.manual,
            p_args.auto_scan,
            p_args.path,
            [y for x in p_args.ignore for y in x],
            [y for x in p_args.ignore_arch for y in x],
            p_args.product_name,
        )
    )
