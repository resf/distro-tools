"""Attribution for Red Hat-sourced advisory content.

Rocky advisories re-publish Red Hat advisory content, which Red Hat licenses
under CC BY 4.0. That license requires crediting the source, linking to the
original advisory and to the license, and indicating that changes were made.
These helpers keep that notice identical across every output format
(updateinfo.xml, the v2 API, OSV, and the web UI).
"""

SOURCE_VENDOR = "Red Hat"
SOURCE_LICENSE = "CC-BY-4.0"
LICENSE_NAME = "CC BY 4.0"
SOURCE_LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
RED_HAT_ERRATA_BASE_URL = "https://access.redhat.com/errata"


def red_hat_errata_url(red_hat_advisory_name: str) -> str:
    """Return the canonical Red Hat errata URL for a given advisory name."""
    return f"{RED_HAT_ERRATA_BASE_URL}/{red_hat_advisory_name}"


def source_fields(red_hat_advisory_name: str) -> dict:
    """Return the structured source/license fields for a Red Hat-derived advisory."""
    return {
        "name": red_hat_advisory_name,
        "url": red_hat_errata_url(red_hat_advisory_name),
        "vendor": SOURCE_VENDOR,
        "license": SOURCE_LICENSE,
        "licenseUrl": SOURCE_LICENSE_URL,
    }


def attribution_rights(
    red_hat_advisory_name: str, company_name: str, year: int
) -> str:
    """Build the per-advisory rights line crediting the Red Hat source under CC BY 4.0."""
    url = red_hat_errata_url(red_hat_advisory_name)
    return (
        f"Copyright {year} {company_name}. "
        f"Advisory content derived from {SOURCE_VENDOR} {red_hat_advisory_name} "
        f"({url}), © {SOURCE_VENDOR}, Inc., used under {LICENSE_NAME} "
        f"({SOURCE_LICENSE_URL}), with modifications."
    )


def attribution_notice() -> str:
    """Build a source-agnostic attribution line for feed and site-wide use."""
    return (
        f"Advisory content is derived from {SOURCE_VENDOR} advisories, "
        f"© {SOURCE_VENDOR}, Inc., used under {LICENSE_NAME} "
        f"({SOURCE_LICENSE_URL}), with modifications."
    )
