"""
NVRA matching helpers for RH → Rocky advisory cloning.

Matching order:
1. Exact cleaned NVRA (handled by callers via dict lookup). Exact cleaned
   equality intentionally skips EVR checks: dist tags are stripped, so
   raw RH ``.el9_2`` vs Rocky ``.el9`` can differ while still being the
   same cleaned package identity.
2. Prefix match (Rocky .rocky.* rebuild suffix on the same NVR), with a
   '.' boundary so release ``80`` does not match ``8``, plus EVR >= when
   package XML is available.
3. EVR >= : same name+arch, Rocky EVR at least the RH fixed EVR

(3) covers cases where Rocky already ships a newer release than the RHSA
fixed NEVRA (different release string, not a .rocky suffix), which the
prefix matcher cannot see.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from apollo.rpm_helpers import evr_gte, label_compare, parse_nevra

COMMON_NS = "http://linux.duke.edu/metadata/common"


def _pkg_evr(pkg: ET.Element) -> tuple[str, str, str] | None:
    version_tree = pkg.find(f"{{{COMMON_NS}}}version")
    if version_tree is None:
        return None
    ver = version_tree.attrib.get("ver")
    rel = version_tree.attrib.get("rel")
    if ver is None or rel is None:
        return None
    return (
        version_tree.attrib.get("epoch", "0"),
        ver,
        rel,
    )


def _is_rebuild_prefix(pkg_nvr: str, cleaned_nvr: str) -> bool:
    """
    True when pkg_nvr is cleaned_nvr or cleaned_nvr plus a dotted suffix.

    Requires a '.' boundary so release ``80`` does not prefix-match ``8``.
    """
    if pkg_nvr == cleaned_nvr:
        return True
    return pkg_nvr.startswith(cleaned_nvr + ".")


def find_nvra_alias(
    advisory_cleaned: str,
    name_pkgs: list[str],
    *,
    advisory_nevra: str | None = None,
    raw_pkg_nvras: dict[str, list] | None = None,
) -> str | None:
    """
    Map a cleaned advisory NVRA to a cleaned repo NVRA.

    Prefer a rebuild-prefix (.rocky) hit that still satisfies EVR >= when
    package XML is available. Otherwise pick the lowest Rocky EVR that is
    still >= the RH fixed EVR (same arch).
    """
    cleaned_parts = advisory_cleaned.rsplit(".", 1)
    if len(cleaned_parts) != 2:
        return None
    cleaned_nvr, cleaned_arch = cleaned_parts

    adv = None
    if advisory_nevra:
        try:
            adv = parse_nevra(advisory_nevra)
        except ValueError:
            adv = None

    for pkg_nvra in name_pkgs:
        pkg_parts = pkg_nvra.rsplit(".", 1)
        if len(pkg_parts) != 2:
            continue
        pkg_nvr, pkg_arch = pkg_parts
        if pkg_arch != cleaned_arch:
            continue
        if not _is_rebuild_prefix(pkg_nvr, cleaned_nvr):
            continue
        # When we can, reject rebuild prefixes that are still older than RH fixed.
        if adv is not None and raw_pkg_nvras:
            pkgs = raw_pkg_nvras.get(pkg_nvra) or []
            if pkgs:
                evr = _pkg_evr(pkgs[0])
                if evr is not None and not evr_gte(
                    evr[0], evr[1], evr[2],
                    adv["epoch"], adv["version"], adv["release"],
                ):
                    continue
        return pkg_nvra

    if adv is None or not raw_pkg_nvras:
        return None

    candidates: list[tuple[str, str, str, str]] = []
    for pkg_nvra in name_pkgs:
        pkg_parts = pkg_nvra.rsplit(".", 1)
        if len(pkg_parts) != 2:
            continue
        _, pkg_arch = pkg_parts
        if pkg_arch != cleaned_arch:
            continue

        pkgs = raw_pkg_nvras.get(pkg_nvra) or []
        if not pkgs:
            continue
        evr = _pkg_evr(pkgs[0])
        if evr is None:
            continue
        epoch, ver, rel = evr
        if evr_gte(epoch, ver, rel, adv["epoch"], adv["version"], adv["release"]):
            candidates.append((epoch, ver, rel, pkg_nvra))

    if not candidates:
        return None

    # Lowest satisfying Rocky EVR (closest fixed-in package).
    best = candidates[0]
    for cand in candidates[1:]:
        if label_compare(cand[0], cand[1], cand[2], best[0], best[1], best[2]) < 0:
            best = cand
    return best[3]
