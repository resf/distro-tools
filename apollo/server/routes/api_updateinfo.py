import datetime
from typing import Optional
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Response
from slugify import slugify

from apollo.db import AdvisoryAffectedProduct, SupportedProduct
from tortoise.exceptions import DoesNotExist
from apollo.server.settings import COMPANY_NAME, MANAGING_EDITOR, UI_URL, get_setting
from apollo.server.validation import Architecture

from apollo.rpmworker.repomd import NEVRA_RE, NVRA_RE, EPOCH_RE

from common.fastapi import RenderErrorTemplateException

router = APIRouter(tags=["updateinfo"])


PRODUCT_SLUG_MAP = {
    "rocky-linux": "Rocky Linux",
    "rocky-linux-sig-cloud": "Rocky Linux SIG Cloud",
}


def resolve_product_slug(slug: str) -> Optional[str]:
    """Convert product slug to supported_product.name"""
    return PRODUCT_SLUG_MAP.get(slug.lower())


def get_source_package_name(pkg) -> str:
    """
    Extract source package name from package for grouping with source RPM.

    Returns a consistent key for grouping binary packages with their source RPM.
    For module packages, includes module context for proper identification.
    """
    if pkg.module_name:
        return f"{pkg.module_name}:{pkg.package_name}:{pkg.module_stream}"
    return pkg.package_name


def build_source_rpm_mapping(packages: list) -> dict:
    """
    Build mapping from source package name to source RPM filename.

    Groups packages by source package name, then finds the source RPM
    (arch=="src") within each group.

    Returns:
        dict: Mapping of source_package_name -> source_rpm_filename
    """
    pkg_name_map = {}
    for pkg in packages:
        name = get_source_package_name(pkg)
        if name not in pkg_name_map:
            pkg_name_map[name] = []
        pkg_name_map[name].append(pkg)

    pkg_src_rpm = {}
    for name, pkgs in pkg_name_map.items():
        if name in pkg_src_rpm:
            continue

        for pkg in pkgs:
            nvra_no_epoch = EPOCH_RE.sub("", pkg.nevra)
            nvra = NVRA_RE.search(nvra_no_epoch)
            if nvra:
                nvr_name = nvra.group(1)
                nvr_arch = nvra.group(4)

                if pkg.package_name == nvr_name and nvr_arch == "src":
                    src_rpm = nvra_no_epoch
                    if not src_rpm.endswith(".rpm"):
                        src_rpm += ".rpm"
                    pkg_src_rpm[name] = src_rpm
                    break

    return pkg_src_rpm


def generate_updateinfo_xml(
    affected_products: list,
    repo_name: str,
    product_arch: str,
    ui_url: str,
    managing_editor: str,
    company_name: str,
    supported_product_id: int = None,
    product_name_for_packages: str = None,
) -> str:
    """
    Generate updateinfo.xml from affected products.

    Args:
        affected_products: List of AdvisoryAffectedProduct records with prefetched
                          advisory, cves, fixes, packages, supported_product
        repo_name: Repository name for package filtering
        product_arch: Architecture for package filtering
        ui_url: Base URL for UI references
        managing_editor: Editor email for XML header
        company_name: Company name for copyright
        supported_product_id: Optional supported_product_id for FK-based filtering (v2)
        product_name_for_packages: Product_name used for legacy filtering (v1) and default_collection and naming XML elements

    Returns:
        XML string in updateinfo.xml format
    """
    advisories = {}
    for affected_product in affected_products:
        advisory = affected_product.advisory
        if advisory.name not in advisories:
            advisories[advisory.name] = {
                "advisory": advisory,
                "arch": affected_product.arch,
                "major_version": affected_product.major_version,
                "minor_version": affected_product.minor_version,
                "supported_product_name": affected_product.supported_product.name,
            }

    tree = ET.Element("updates")
    for _, adv in advisories.items():
        advisory = adv["advisory"]
        adv_arch = adv["arch"]
        major_version = adv["major_version"]
        minor_version = adv["minor_version"]
        supported_product_name = adv["supported_product_name"]

        update = ET.SubElement(tree, "update")

        update.set("from", managing_editor)
        update.set("status", "final")

        if advisory.kind == "Security":
            update.set("type", "security")
        elif advisory.kind == "Bug Fix":
            update.set("type", "bugfix")
        elif advisory.kind == "Enhancement":
            update.set("type", "enhancement")

        update.set("version", "2")

        ET.SubElement(update, "id").text = advisory.name
        ET.SubElement(update, "title").text = advisory.synopsis

        time_format = "%Y-%m-%d %H:%M:%S"
        issued = ET.SubElement(update, "issued")
        issued.set("date", advisory.published_at.strftime(time_format))
        updated = ET.SubElement(update, "updated")
        updated.set("date", advisory.updated_at.strftime(time_format))

        now = datetime.datetime.utcnow()
        ET.SubElement(
            update, "rights"
        ).text = f"Copyright {now.year} {company_name}"

        release_name = f"{supported_product_name} {major_version}"
        if minor_version:
            release_name += f".{minor_version}"
        ET.SubElement(update, "release").text = release_name

        ET.SubElement(update, "pushcount").text = "1"
        ET.SubElement(update, "severity").text = advisory.severity
        ET.SubElement(update, "summary").text = advisory.topic
        ET.SubElement(update, "description").text = advisory.description
        ET.SubElement(update, "solution").text = ""

        references = ET.SubElement(update, "references")
        for cve in advisory.cves:
            reference = ET.SubElement(references, "reference")
            reference.set(
                "href",
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.cve}",
            )
            reference.set("id", cve.cve)
            reference.set("type", "cve")
            reference.set("title", cve.cve)

        for fix in advisory.fixes:
            reference = ET.SubElement(references, "reference")
            reference.set("href", fix.source)
            reference.set("id", fix.ticket_id)
            reference.set("type", "bugzilla")
            reference.set("title", fix.description)

        reference = ET.SubElement(references, "reference")
        reference.set("href", f"{ui_url}/{advisory.name}")
        reference.set("id", advisory.name)
        reference.set("type", "self")
        reference.set("title", advisory.name)

        packages_element = ET.SubElement(update, "pkglist")

        suffixes_to_skip = [
            "-debuginfo",
            "-debugsource",
            "-debuginfo-common",
            "-debugsource-common",
        ]

        if supported_product_id is not None:
            seen_nevras = set()
            filtered_packages = []
            for pkg in advisory.packages:
                if pkg.supported_product_id == supported_product_id and pkg.repo_name == repo_name:
                    if pkg.nevra not in seen_nevras:
                        seen_nevras.add(pkg.nevra)
                        filtered_packages.append(pkg)
        else:
            filtered_packages = [
                pkg for pkg in advisory.packages
                if pkg.product_name == product_name_for_packages and pkg.repo_name == repo_name
            ]

        pkg_src_rpm = build_source_rpm_mapping(filtered_packages)

        collections = {}
        no_default_collection = False
        default_collection_short = slugify(f"{product_name_for_packages}-{repo_name}-rpms")

        for pkg in filtered_packages:
            if pkg.module_name:
                collection_short = f"{default_collection_short}__{pkg.module_name}"
                if collection_short not in collections:
                    collections[collection_short] = {
                        "packages": [],
                        "module_context": pkg.module_context,
                        "module_name": pkg.module_name,
                        "module_stream": pkg.module_stream,
                        "module_version": pkg.module_version,
                    }
                    no_default_collection = True
                collections[collection_short]["packages"].append(pkg)
            else:
                if no_default_collection:
                    continue
                if default_collection_short not in collections:
                    collections[default_collection_short] = {
                        "packages": [],
                    }
                collections[default_collection_short]["packages"].append(pkg)

        if no_default_collection and default_collection_short in collections:
            del collections[default_collection_short]

        collections_added = 0

        for collection_short, info in collections.items():
            collection = ET.Element("collection")
            collection.set("short", collection_short)

            ET.SubElement(collection, "name").text = collection_short

            if "module_name" in info:
                module_element = ET.SubElement(collection, "module")
                module_element.set("name", info["module_name"])
                module_element.set("stream", info["module_stream"])
                module_element.set("version", info["module_version"])
                module_element.set("context", info["module_context"])
                module_element.set("arch", adv_arch)

            added_pkg_count = 0
            for pkg in info["packages"]:
                if pkg.nevra.endswith(".src.rpm"):
                    continue

                name = pkg.package_name
                epoch = "0"
                if NEVRA_RE.match(pkg.nevra):
                    nevra = NEVRA_RE.search(pkg.nevra)
                    name = nevra.group(1)
                    epoch = nevra.group(2)
                    version = nevra.group(3)
                    release = nevra.group(4)
                    arch = nevra.group(5)
                elif NVRA_RE.match(pkg.nevra):
                    nvra = NVRA_RE.search(pkg.nevra)
                    name = nvra.group(1)
                    version = nvra.group(2)
                    release = nvra.group(3)
                    arch = nvra.group(4)
                else:
                    continue

                p_name = get_source_package_name(pkg)

                if p_name not in pkg_src_rpm:
                    continue
                if arch != product_arch and arch != "noarch":
                    if product_arch != "x86_64":
                        continue
                    if product_arch == "x86_64" and arch != "i686":
                        continue

                skip = False
                for suffix in suffixes_to_skip:
                    if name.endswith(suffix):
                        skip = True
                        break
                if skip:
                    continue

                package = ET.SubElement(collection, "package")
                package.set("name", name)
                package.set("arch", arch)
                package.set("epoch", epoch)
                package.set("version", version)
                package.set("release", release)
                package.set("src", pkg_src_rpm[p_name])

                ET.SubElement(package,
                              "filename").text = EPOCH_RE.sub("", pkg.nevra)

                ET.SubElement(
                    package, "sum", type=pkg.checksum_type
                ).text = pkg.checksum

                added_pkg_count += 1

            if added_pkg_count > 0:
                packages_element.append(collection)
                collections_added += 1

        if collections_added == 0:
            tree.remove(update)

    ET.indent(tree)
    xml_str = ET.tostring(
        tree,
        encoding="unicode",
        method="xml",
        short_empty_elements=True,
    )

    return xml_str


@router.get("/{product_name}/{repo}/updateinfo.xml")
async def get_updateinfo(
    product_name: str,
    repo: str,
    req_arch: Optional[str] = None,
):
    filters = {
        "name": product_name,
        "advisory__packages__repo_name": repo,
    }
    if req_arch:
        filters["arch"] = req_arch

    affected_products = await AdvisoryAffectedProduct.filter(
        **filters
    ).prefetch_related(
        "advisory",
        "advisory__cves",
        "advisory__fixes",
        "advisory__packages",
        "supported_product",
    ).all()
    if not affected_products:
        raise RenderErrorTemplateException("No advisories found", 404)

    ui_url = await get_setting(UI_URL)
    managing_editor = await get_setting(MANAGING_EDITOR)
    company_name = await get_setting(COMPANY_NAME)

    product_arch = affected_products[0].arch

    xml_str = generate_updateinfo_xml(
        affected_products=affected_products,
        repo_name=repo,
        product_arch=product_arch,
        ui_url=ui_url,
        managing_editor=managing_editor,
        company_name=company_name,
        product_name_for_packages=product_name,
    )

    return Response(content=xml_str, media_type="application/xml")


@router.get("/{product}/{major_version}/{repo}/updateinfo.xml")
async def get_updateinfo_v2(
    product: str,
    major_version: int,
    repo: str,
    arch: str,
    minor_version: Optional[int] = None,
):
    """
    Get updateinfo.xml for a product major version and repository.

    This endpoint aggregates all advisories for the specified major version,
    including all minor versions, unless minor_version is specified.

    Architecture filtering is REQUIRED because:
    - Each advisory contains packages for multiple architectures
    - Repository structure is architecture-specific
    - DNF/YUM expects arch-specific updateinfo.xml files

    Args:
        product: Product slug (e.g., 'rocky-linux', 'rocky-linux-sig-cloud')
        major_version: Major version number (e.g., 8, 9, 10)
        repo: Repository name (e.g., 'BaseOS', 'AppStream')
        arch: Architecture (REQUIRED: 'x86_64', 'aarch64', 'ppc64le', 's390x')
        minor_version: Optional minor version filter (e.g., 6 for 8.6)

    Returns:
        updateinfo.xml file

    Raises:
        400: Invalid architecture or missing required parameter
        404: No advisories found or invalid product
    """
    product_name = resolve_product_slug(product)
    if not product_name:
        raise RenderErrorTemplateException(
            f"Unknown product: {product}. Valid: {', '.join(PRODUCT_SLUG_MAP.keys())}",
            404
        )

    try:
        supported_product = await SupportedProduct.get(name=product_name)
    except DoesNotExist:
        raise RenderErrorTemplateException(f"Product not found: {product_name}", 404)

    # Validate architecture using centralized validation
    try:
        Architecture(arch)
    except ValueError:
        valid_arches = [a.value for a in Architecture]
        raise RenderErrorTemplateException(
            f"Invalid architecture: {arch}. Must be one of {', '.join(valid_arches)}",
            400
        )

    filters = {
        "supported_product_id": supported_product.id,
        "major_version": major_version,
        "arch": arch,
        "advisory__packages__repo_name": repo,
        "advisory__packages__supported_product_id": supported_product.id,
    }

    if minor_version is not None:
        filters["minor_version"] = minor_version

    affected_products = await AdvisoryAffectedProduct.filter(
        **filters
    ).prefetch_related(
        "advisory",
        "advisory__cves",
        "advisory__fixes",
        "advisory__packages",
        "supported_product",
    ).all()

    if not affected_products:
        raise RenderErrorTemplateException(
            f"No advisories found for {product_name} {major_version} {repo} {arch}",
            404
        )

    ui_url = await get_setting(UI_URL)
    managing_editor = await get_setting(MANAGING_EDITOR)
    company_name = await get_setting(COMPANY_NAME)

    xml_str = generate_updateinfo_xml(
        affected_products=affected_products,
        repo_name=repo,
        product_arch=arch,
        ui_url=ui_url,
        managing_editor=managing_editor,
        company_name=company_name,
        supported_product_id=supported_product.id,
        product_name_for_packages=f"{product_name} {major_version} {arch}",
    )

    return Response(content=xml_str, media_type="application/xml")
