import gzip
import lzma
import re
from xml.etree import ElementTree as ET
from urllib.parse import urlparse
from os import path

from apollo.rpm_helpers import parse_nevra

import aiohttp
import yaml

NVRA_RE = re.compile(
    r"^(\S+)-([\w~%.+^]+)-([\w~^]+(?:\.[\w~%+^]+)+?)(?:\.(\w+))?(?:\.rpm)?$"
)
NEVRA_RE = re.compile(
    r"^(\S+)-(?:(\d)+:)([\w~%.+^]+)-([\w~^]+(?:\.[\w~%+^]+)+?)(?:\.(\w+))?(?:\.rpm)?$"
)
EPOCH_RE = re.compile(r"(\d+):")
DIST_RE = re.compile(r"(\.el\d+(?:_\d+|))")
# ``.module+el8.7.0+1155+5163394a.1`` — strip NSVC, keep trailing ``.1``.
_MODULE_NSVC_RE = re.compile(r"\.module\+[^+]+\+\d+\+[0-9a-fA-F]+")
_MODULE_DIST_RE = re.compile(r"\.module.+$")


def strip_module_dist(release: str) -> str:
    """Drop ``.module+dist+build+context``; keep a trailing ``.N`` rebuild.

    RHEL vs Rocky module hashes are not comparable. Trailing ``.1`` / ``.5``
    after the context is a later snapshot (issue 8). Greedy ``.module.+$``
    collapsed ``httpd-2.4.37-51.module+…+126e9251`` with ``…+5163394a.1``.
    """
    stripped, n = _MODULE_NSVC_RE.subn("", release, count=1)
    if n:
        return stripped
    return _MODULE_DIST_RE.sub("", release)


def nvr_is_rebuild_of(pkg_nvr: str, cleaned_nvr: str) -> bool:
    """True for an exact NVR or a ``.rocky`` rebuild, not a later ``.N`` snapshot.

    ``httpd-2.4.37-51.1`` is not a rebuild of ``httpd-2.4.37-51``.
    ``openssh-8.7p1-49.rocky.0.1`` is a rebuild of ``openssh-8.7p1-49``.
    """
    if pkg_nvr == cleaned_nvr:
        return True
    if not pkg_nvr.startswith(cleaned_nvr + "."):
        return False
    first = pkg_nvr[len(cleaned_nvr) + 1:].split(".", 1)[0]
    return not first.isdigit()


def clean_nvra_pkg(matching_pkg: ET.Element) -> tuple[str, str]:
    name = matching_pkg.find("{http://linux.duke.edu/metadata/common}name").text
    version = matching_pkg.find(
        "{http://linux.duke.edu/metadata/common}version"
    ).attrib["ver"]
    release = matching_pkg.find(
        "{http://linux.duke.edu/metadata/common}version"
    ).attrib["rel"]
    arch = matching_pkg.find("{http://linux.duke.edu/metadata/common}arch").text

    clean_release = strip_module_dist(DIST_RE.sub("", release))

    cleaned = f"{name}-{version}-{clean_release}.{arch}"
    raw = f"{name}-{version}-{release}.{arch}"
    if ".module+" in release:
        cleaned = f"module.{cleaned}"
        raw = f"module.{raw}"

    return cleaned, raw


def clean_nvra(nvra_raw: str) -> tuple[str, str]:
    try:
        results = parse_nevra(nvra_raw)
    except ValueError as e:
        return nvra_raw, nvra_raw
    name = results["name"]
    version = results["version"]
    release = results["release"]
    arch = results["arch"]

    clean_release = strip_module_dist(DIST_RE.sub("", release))

    cleaned = f"{name}-{version}-{clean_release}.{arch}"
    raw = f"{name}-{version}-{release}.{arch}"
    if ".module+" in release:
        cleaned = f"module.{cleaned}"
        raw = f"module.{raw}"

    return cleaned, raw


async def download_xml(
    url: str, gz: bool = False, xz: bool = False
) -> ET.Element:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to get {url}: {resp.status}")
            # Do an in memory gzip decompression if gz is set
            if gz:
                return ET.fromstring(
                    gzip.decompress(await resp.read()).decode("utf-8")
                )
            elif xz:
                return ET.fromstring(
                    lzma.decompress(await resp.read()).decode("utf-8")
                )
            return ET.fromstring(await resp.text())


async def download_yaml(url: str, gz: bool = False, xz: bool = False) -> any:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to get {url}: {resp.status}")
            # Do an in memory gzip decompression if gz is set
            if gz:
                return yaml.full_load_all(
                    gzip.decompress(await resp.read()).decode("utf-8")
                )
            elif xz:
                return yaml.full_load_all(
                    lzma.decompress(await resp.read()).decode("utf-8")
                )

            return yaml.full_load_all(await resp.text())


async def get_data_from_repomd(
    url: str,
    data_type: str,
    el: ET.Element,
    is_yaml=False,
):
    # There is a top-most repomd element in repomd
    # Under there is revision and multiple data elements
    # We want the data element with type="data_type"
    # Under that is location with href
    # That href is the location of the data
    for data in el.findall("{http://linux.duke.edu/metadata/repo}data"):
        if data.attrib["type"] == data_type:
            location = data.find(
                "{http://linux.duke.edu/metadata/repo}location"
            )
            parsed_url = urlparse(url)
            new_path = path.abspath(
                path.join(parsed_url.path, "../..", location.attrib["href"])
            )
            data_url = parsed_url._replace(path=new_path).geturl()
            if is_yaml:
                return await download_yaml(
                    data_url,
                    gz=data_url.endswith(".gz"),
                    xz=data_url.endswith(".xz"),
                )
            return await download_xml(
                data_url,
                gz=data_url.endswith(".gz"),
                xz=data_url.endswith(".xz"),
            )

    return None
