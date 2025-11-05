import datetime
import logging
from typing import Optional, List
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Response
from slugify import slugify
from tortoise.exceptions import DoesNotExist

from apollo.db import AdvisoryAffectedProduct, SupportedProduct
from apollo.server.settings import COMPANY_NAME, MANAGING_EDITOR, UI_URL, get_setting

from apollo.rpmworker.repomd import NEVRA_RE, NVRA_RE, EPOCH_RE

from common.fastapi import RenderErrorTemplateException

router = APIRouter(tags=["updateinfo"])
logger = logging.getLogger(__name__)

# Product slug to supported_product.name mapping
PRODUCT_SLUG_MAP = {
    "rocky-linux": "Rocky Linux",
    "rocky-linux-sig-cloud": "Rocky Linux SIG Cloud",
}


def resolve_product_slug(slug: str) -> Optional[str]:
    """
    Convert product slug to supported_product.name.

    Args:
        slug: Product slug (e.g., 'rocky-linux', 'rocky-linux-sig-cloud')

    Returns:
        Product name from supported_products table, or None if not found

    Examples:
        >>> resolve_product_slug('rocky-linux')
        'Rocky Linux'
        >>> resolve_product_slug('Rocky-Linux')  # Case insensitive
        'Rocky Linux'
        >>> resolve_product_slug('invalid')
        None
    """
    return PRODUCT_SLUG_MAP.get(slug.lower())


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

    advisories = {}
    for affected_product in affected_products:
        advisory = affected_product.advisory
        if advisory.name not in advisories:
            advisories[advisory.name] = {
                "advisory":
                    advisory,
                "arch":
                    affected_product.arch,
                "major_version":
                    affected_product.major_version,
                "minor_version":
                    affected_product.minor_version,
                "supported_product_name":
                    affected_product.supported_product.name,
            }

    tree = ET.Element("updates")
    for _, adv in advisories.items():
        advisory = adv["advisory"]
        product_arch = adv["arch"]
        major_version = adv["major_version"]
        minor_version = adv["minor_version"]
        supported_product_name = adv["supported_product_name"]

        update = ET.SubElement(tree, "update")

        # Set update attributes
        update.set("from", managing_editor)
        update.set("status", "final")

        if advisory.kind == "Security":
            update.set("type", "security")
        elif advisory.kind == "Bug Fix":
            update.set("type", "bugfix")
        elif advisory.kind == "Enhancement":
            update.set("type", "enhancement")

        update.set("version", "2")

        # Add id
        ET.SubElement(update, "id").text = advisory.name

        # Add title
        ET.SubElement(update, "title").text = advisory.synopsis

        # Add time
        time_format = "%Y-%m-%d %H:%M:%S"
        issued = ET.SubElement(update, "issued")
        issued.set("date", advisory.published_at.strftime(time_format))
        updated = ET.SubElement(update, "updated")
        updated.set("date", advisory.updated_at.strftime(time_format))

        # Add rights
        now = datetime.datetime.utcnow()
        ET.SubElement(
            update, "rights"
        ).text = f"Copyright {now.year} {company_name}"

        # Add release name
        release_name = f"{supported_product_name} {major_version}"
        if minor_version:
            release_name += f".{minor_version}"
        ET.SubElement(update, "release").text = release_name

        # Add pushcount
        ET.SubElement(update, "pushcount").text = "1"

        # Add severity
        ET.SubElement(update, "severity").text = advisory.severity

        # Add summary
        ET.SubElement(update, "summary").text = advisory.topic

        # Add description
        ET.SubElement(update, "description").text = advisory.description

        # Add solution
        ET.SubElement(update, "solution").text = ""

        # Add references
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

        # Add UI self reference
        reference = ET.SubElement(references, "reference")
        reference.set("href", f"{ui_url}/{advisory.name}")
        reference.set("id", advisory.name)
        reference.set("type", "self")
        reference.set("title", advisory.name)

        # Add packages
        packages = ET.SubElement(update, "pkglist")

        suffixes_to_skip = [
            "-debuginfo",
            "-debugsource",
            "-debuginfo-common",
            "-debugsource-common",
        ]

        pkg_name_map = {}
        for pkg in advisory.packages:
            name = pkg.package_name
            if pkg.module_name:
                name = f"{pkg.module_name}:{pkg.package_name}:{pkg.module_stream}"
            if name not in pkg_name_map:
                pkg_name_map[name] = []

            pkg_name_map[name].append(pkg)

        pkg_src_rpm = {}
        for top_pkg in advisory.packages:
            name = top_pkg.package_name
            if top_pkg.module_name:
                name = f"{top_pkg.module_name}:{top_pkg.package_name}:{top_pkg.module_stream}"
            if name not in pkg_src_rpm:
                for pkg in pkg_name_map[name]:
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

        # Collection list, may be more than one if module RPMs are involved
        collections = {}
        no_default_collection = False
        default_collection_short = slugify(f"{product_name}-{repo}-rpms")

        # Check if this is an actual module advisory, if so we need to split the
        # collections, and module RPMs need to go into their own collection based on
        # module name, while non-module RPMs go into the main collection (if any)
        for pkg in advisory.packages:
            if pkg.product_name != product_name:
                continue
            if pkg.repo_name != repo:
                continue
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
            # Create collection
            collection = ET.Element("collection")
            collection.set("short", collection_short)

            # Set short to name as well
            ET.SubElement(collection, "name").text = collection_short

            if "module_name" in info:
                module_element = ET.SubElement(collection, "module")
                module_element.set("name", info["module_name"])
                module_element.set("stream", info["module_stream"])
                module_element.set("version", info["module_version"])
                module_element.set("context", info["module_context"])
                module_element.set("arch", product_arch)

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

                p_name = pkg.package_name
                if pkg.module_name:
                    p_name = f"{pkg.module_name}:{pkg.package_name}:{pkg.module_stream}"

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

                # Add filename element
                ET.SubElement(package,
                              "filename").text = EPOCH_RE.sub("", pkg.nevra)

                # Add checksum
                ET.SubElement(
                    package, "sum", type=pkg.checksum_type
                ).text = pkg.checksum

                added_pkg_count += 1

            if added_pkg_count > 0:
                packages.append(collection)
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

    return Response(content=xml_str, media_type="application/xml")


def generate_updateinfo_xml(
    affected_products: List[AdvisoryAffectedProduct],
    ui_url: str,
    managing_editor: str,
    company_name: str,
    product_name_for_packages: Optional[str] = None,
    repo: Optional[str] = None,
    validate_product_consistency: bool = True,
) -> str:
    """
    Generate updateinfo.xml from affected products.

    This function creates XML content compatible with DNF/YUM package managers.
    It handles advisory deduplication, package filtering, module RPM handling,
    and data integrity validation.

    Args:
        affected_products: List of AdvisoryAffectedProduct records with prefetched
                         advisory, cves, fixes, packages, and supported_product
        ui_url: Base URL for UI references
        managing_editor: Editor email for XML header
        company_name: Company name for copyright
        product_name_for_packages: Product name to filter packages by.
                                   If None, uses affected_product.name
        repo: Repository name to filter packages by. Required for filtering.
        validate_product_consistency: If True, validate that all packages
                                     have matching supported_product_id to
                                     prevent cross-product contamination

    Returns:
        XML string in updateinfo.xml format
    """
    # Deduplicate advisories by name
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
                "supported_product_id": affected_product.supported_product_id,
            }

    tree = ET.Element("updates")

    for _, adv in advisories.items():
        advisory = adv["advisory"]
        product_arch = adv["arch"]
        major_version = adv["major_version"]
        minor_version = adv["minor_version"]
        supported_product_name = adv["supported_product_name"]
        supported_product_id = adv["supported_product_id"]

        update = ET.SubElement(tree, "update")

        # Set update attributes
        update.set("from", managing_editor)
        update.set("status", "final")

        if advisory.kind == "Security":
            update.set("type", "security")
        elif advisory.kind == "Bug Fix":
            update.set("type", "bugfix")
        elif advisory.kind == "Enhancement":
            update.set("type", "enhancement")

        update.set("version", "2")

        # Add id
        ET.SubElement(update, "id").text = advisory.name

        # Add title
        ET.SubElement(update, "title").text = advisory.synopsis

        # Add time
        time_format = "%Y-%m-%d %H:%M:%S"
        issued = ET.SubElement(update, "issued")
        issued.set("date", advisory.published_at.strftime(time_format))
        updated = ET.SubElement(update, "updated")
        updated.set("date", advisory.updated_at.strftime(time_format))

        # Add rights
        now = datetime.datetime.utcnow()
        ET.SubElement(
            update, "rights"
        ).text = f"Copyright {now.year} {company_name}"

        # Add release name
        release_name = f"{supported_product_name} {major_version}"
        if minor_version:
            release_name += f".{minor_version}"
        ET.SubElement(update, "release").text = release_name

        # Add pushcount
        ET.SubElement(update, "pushcount").text = "1"

        # Add severity
        ET.SubElement(update, "severity").text = advisory.severity

        # Add summary
        ET.SubElement(update, "summary").text = advisory.topic

        # Add description
        ET.SubElement(update, "description").text = advisory.description

        # Add solution
        ET.SubElement(update, "solution").text = ""

        # Add references
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

        # Add UI self reference
        reference = ET.SubElement(references, "reference")
        reference.set("href", f"{ui_url}/{advisory.name}")
        reference.set("id", advisory.name)
        reference.set("type", "self")
        reference.set("title", advisory.name)

        # Add packages
        packages = ET.SubElement(update, "pkglist")

        suffixes_to_skip = [
            "-debuginfo",
            "-debugsource",
            "-debuginfo-common",
            "-debugsource-common",
        ]

        pkg_name_map = {}
        for pkg in advisory.packages:
            name = pkg.package_name
            if pkg.module_name:
                name = f"{pkg.module_name}:{pkg.package_name}:{pkg.module_stream}"
            if name not in pkg_name_map:
                pkg_name_map[name] = []

            pkg_name_map[name].append(pkg)

        pkg_src_rpm = {}
        for top_pkg in advisory.packages:
            name = top_pkg.package_name
            if top_pkg.module_name:
                name = f"{top_pkg.module_name}:{top_pkg.package_name}:{top_pkg.module_stream}"
            if name not in pkg_src_rpm:
                for pkg in pkg_name_map[name]:
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

        # Determine the product name to use for package filtering
        filter_product_name = product_name_for_packages
        if filter_product_name is None:
            # Use the first affected_product's name as fallback
            filter_product_name = affected_products[0].name if affected_products else None

        # Collection list, may be more than one if module RPMs are involved
        collections = {}
        no_default_collection = False
        default_collection_short = slugify(f"{filter_product_name}-{repo}-rpms") if repo else slugify(f"{filter_product_name}-rpms")

        # Check if this is an actual module advisory, if so we need to split the
        # collections, and module RPMs need to go into their own collection based on
        # module name, while non-module RPMs go into the main collection (if any)
        for pkg in advisory.packages:
            # DATA INTEGRITY CHECK: Validate supported_product_id consistency
            if validate_product_consistency:
                if pkg.supported_product_id != supported_product_id:
                    logger.error(
                        f"Data integrity violation detected for advisory {advisory.name}: "
                        f"Package {pkg.nevra} (id={pkg.id}) has supported_product_id={pkg.supported_product_id} "
                        f"but affected_product has supported_product_id={supported_product_id}. "
                        f"Skipping this package to prevent cross-product contamination."
                    )
                    continue  # Skip this package - don't include it in updateinfo

            # Filter by product name
            if filter_product_name and pkg.product_name != filter_product_name:
                continue

            # Filter by repository
            if repo and pkg.repo_name != repo:
                continue

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
            # Create collection
            collection = ET.Element("collection")
            collection.set("short", collection_short)

            # Set short to name as well
            ET.SubElement(collection, "name").text = collection_short

            if "module_name" in info:
                module_element = ET.SubElement(collection, "module")
                module_element.set("name", info["module_name"])
                module_element.set("stream", info["module_stream"])
                module_element.set("version", info["module_version"])
                module_element.set("context", info["module_context"])
                module_element.set("arch", product_arch)

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

                p_name = pkg.package_name
                if pkg.module_name:
                    p_name = f"{pkg.module_name}:{pkg.package_name}:{pkg.module_stream}"

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

                # Add filename element
                ET.SubElement(package,
                              "filename").text = EPOCH_RE.sub("", pkg.nevra)

                # Add checksum
                ET.SubElement(
                    package, "sum", type=pkg.checksum_type
                ).text = pkg.checksum

                added_pkg_count += 1

            if added_pkg_count > 0:
                packages.append(collection)
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


@router.get("/{product}/{major_version}/{repo}/updateinfo.xml")
async def get_updateinfo_v2(
    product: str,
    major_version: int,
    repo: str,
    arch: str,
    minor_version: Optional[int] = None,
):
    """
    Get updateinfo.xml for a product major version and repository (v2 API).

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
    # Resolve product slug to name
    product_name = resolve_product_slug(product)
    if not product_name:
        raise RenderErrorTemplateException(
            f"Unknown product: {product}. Valid products: {', '.join(PRODUCT_SLUG_MAP.keys())}",
            404
        )

    # Get the supported_product record
    try:
        supported_product = await SupportedProduct.get(name=product_name)
    except DoesNotExist:
        raise RenderErrorTemplateException(
            f"Product not found in database: {product_name}",
            404
        )

    # Validate architecture
    valid_arches = ["x86_64", "aarch64", "ppc64le", "s390x"]
    if arch not in valid_arches:
        raise RenderErrorTemplateException(
            f"Invalid architecture: {arch}. Must be one of {', '.join(valid_arches)}",
            400
        )

    # Build filters using explicit supported_product_id
    # This prevents cross-contamination between products
    filters = {
        "supported_product_id": supported_product.id,  # Explicit FK - prevents cross-product contamination
        "major_version": major_version,
        "arch": arch,  # REQUIRED filter
        "advisory__packages__repo_name": repo,
        "advisory__packages__supported_product_id": supported_product.id,  # Double-check packages match
    }

    if minor_version is not None:
        filters["minor_version"] = minor_version

    # Query with prefetch
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
    company_name_value = await get_setting(COMPANY_NAME)

    # Generate the XML using the shared function
    # For v2 API, we use a generic product name format for package filtering
    # since we're aggregating across minor versions
    product_name_for_packages = f"{product_name} {major_version} {arch}"

    xml_str = generate_updateinfo_xml(
        affected_products=affected_products,
        ui_url=ui_url,
        managing_editor=managing_editor,
        company_name=company_name_value,
        product_name_for_packages=product_name_for_packages,
        repo=repo,
        validate_product_consistency=True,
    )

    return Response(content=xml_str, media_type="application/xml")
