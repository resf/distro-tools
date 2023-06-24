# pylint: disable=invalid-name
"""
This module provides a Python interface to the Red Hat Errata API.
"""
from __future__ import annotations
from enum import Enum
from dataclasses import dataclass
from urllib.parse import quote

import aiohttp
from dataclass_wizard import JSONWizard
from yarl import URL

DEFAULT_URL = "https://access.redhat.com/hydra/rest/search/kcs"


class DocumentKind(str, Enum):
    """
    The kind of document.
    """

    ERRATA = "Errata"


class Distro(str, Enum):
    """
    The distribution.
    """

    RHEL = "Red Hat Enterprise Linux"


class Architecture(str, Enum):
    """
    The architecture.
    """

    X86_64 = "x86_64"
    AARCH64 = "aarch64"
    PPC64 = "ppc64"
    PPC64LE = "ppc64le"
    S390X = "s390x"


@dataclass
class PortalProduct:
    """
    Red Hat advisory product
    """

    variant: str
    name: str
    major_version: int
    minor_version: int
    arch: str


@dataclass
class Advisory(JSONWizard):
    """
    An advisory.
    """

    documentKind: str = None
    uri: str = None
    view_uri: str = None
    language: str = None
    id: str = None
    portal_description: str = None
    abstract: str = None
    allTitle: str = None
    sortTitle: str = None
    portal_title: list[str] = None
    lastModifiedDate: str = None
    displayDate: str = None
    portal_advisory_type: str = None
    portal_synopsis: str = None
    portal_severity: str = None
    portal_type: str = None
    portal_package: list[str] = None
    portal_CVE: list[str] = None
    portal_BZ: list[str] = None
    portal_publication_date: str = None
    portal_requires_subscription: str = None
    portal_product_names: list[str] = None
    title: str = None
    portal_child_ids: list[str] = None
    portal_product_filter: list[str] = None
    boostProduct: str = None
    boostVersion: int | list[str] = None
    detectedProducts: list[str] = None
    caseCount: int = None
    caseCount_365: int = None
    timestamp: str = None
    body: list[str] = None
    _version_: int = None

    __products: list[PortalProduct] = None

    def get_products(self) -> list[PortalProduct]:
        if self.__products:
            return self.__products

        self.__products = []
        for product in self.portal_product_filter:
            try:
                if product.startswith("Red Hat Enterprise Linux"):
                    variant, name, version, arch = product.split("|")
                    major_version = version
                    if "." in version:
                        version_split = version.split(".")
                        major_version = int(version_split[0])
                        minor_version = int(version_split[1])
                    else:
                        major_version = int(version)
                        minor_version = None
                    self.__products.append(
                        PortalProduct(variant, name, major_version, minor_version, arch)
                    )
            except ValueError:
                pass

        return self.__products

    def affects_rhel_version_arch(
        self, major_version: int, minor_version: int | None, arch: Architecture
    ) -> bool:
        """
        Returns whether this advisory affects the given RHEL version and architecture.
        """
        for product in self.get_products():
            is_variant = product.variant == "Red Hat Enterprise Linux"
            is_major_version = product.major_version == major_version
            is_minor_version = product.minor_version == minor_version
            is_arch = product.arch == arch.value
            if is_variant and is_major_version and is_minor_version and is_arch:
                return True

        return False


class API:
    """
    The Red Hat Errata API.
    """

    url = None

    def __init__(self, url=DEFAULT_URL):
        if not url:
            url = DEFAULT_URL
        self.url = url

    async def search(
        self,
        kind: DocumentKind = DocumentKind.ERRATA,
        sort_asc: bool = False,
        rows: int = 10,
        query: str = "*:*",
        distro: str = "Red%5C+Hat%5C+Enterprise%5C+Linux%7C%2A%7C%2A%7C%2A",
        detected_product: str = "rhel",
        from_date: str = None,
    ) -> list[Advisory]:
        params = ""

        # Set query
        params += f"q={query}"

        # Set rows
        params += f"&rows={rows}"

        # Set sorting
        sorting = (
            "portal_publication_date+asc"
            if sort_asc
            else "portal_publication_date+desc"
        )
        params += f"&sort={sorting}"

        # Set start
        params += "&start=0"

        # Set distribution
        params += f"&fq=portal_product_filter:{distro}"

        # Set from-to
        if from_date:
            params += (
                f"&fq=portal_publication_date%3A%5B{quote(from_date)}%20TO%20NOW%5D"
            )

        # Set document kind
        params += f"&fq=documentKind:{kind.value}"

        # Set detected product
        if detected_product:
            params += f"&fq=detectedProducts:{detected_product}"

        async with aiohttp.ClientSession() as session:
            async with session.get(
                URL(f"{self.url}?{params}", encoded=True),
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0"
                },
            ) as response:
                body = await response.json()
                if response.status != 200:
                    raise Exception((await response.text()))
                elif body.get("response", {}).get("numFound", 0) == 0:
                    return []
                advisory_list = list(body["response"]["docs"])
                return Advisory.from_list(advisory_list)
