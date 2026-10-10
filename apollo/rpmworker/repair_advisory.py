"""Recover a cloned advisory's package associations from historical repodata.

The normal matcher uses live repositories. It cannot reconstruct a fixed
build that has aged out of them. This command reuses the matcher with explicit
archive repositories and previews the resulting package replacement before
applying it. Publication dates, CVEs, mirror configuration and workflow state
are preserved.
"""
import argparse
import asyncio
from dataclasses import asdict, dataclass
import datetime
import json
from pathlib import Path
from types import SimpleNamespace

from tortoise import Tortoise
from tortoise.transactions import in_transaction

from apollo.db import Advisory, AdvisoryPackage, SupportedProductsRhMirror
from apollo.rpm_helpers import parse_nevra
from apollo.rpmworker import repomd
from apollo.rpmworker.rh_matcher_activities import (
    NewPackage, clone_advisory, create_or_update_advisory_packages, process_repomd,
)
from common.database import Database
from common.info import Info


@dataclass
class ArchiveRepository:
    mirror_id: int
    repo_name: str
    url: str
    debug_url: str
    source_url: str


@dataclass
class RepairPlan:
    advisory_id: int
    advisory_name: str
    before: list[NewPackage]
    after: list[NewPackage]

    def summary(self):
        before = {p.nevra for p in self.before}
        after = {p.nevra for p in self.after}
        return {
            "advisory": self.advisory_name,
            "add": sorted(after - before),
            "remove": sorted(before - after),
            "changed": _snapshot(self.before) != _snapshot(self.after),
        }


class _PreviewComplete(Exception):
    """Unwind the preview transaction, including the matcher's nested writes."""


def _snapshot(packages):
    return sorted(json.dumps(asdict(p), sort_keys=True) for p in packages)


async def _packages(advisory_id):
    rows = await AdvisoryPackage.filter(advisory_id=advisory_id).all()
    return [NewPackage(
        nevra=p.nevra, checksum=p.checksum, checksum_type=p.checksum_type,
        module_context=p.module_context, module_name=p.module_name,
        module_stream=p.module_stream, module_version=p.module_version,
        repo_name=p.repo_name, package_name=p.package_name,
        mirror_id=p.supported_products_rh_mirror_id,
        supported_product_id=p.supported_product_id, product_name=p.product_name,
    ) for p in rows]


def _binary_keys(packages):
    keys = set()
    for pkg in packages:
        parsed = parse_nevra(pkg.nevra)
        if parsed["arch"] != "src":
            keys.add((pkg.mirror_id, parsed["name"], parsed["arch"]))
    return keys


def _validate_source_matches(packages, source, mirrors):
    by_id = {m.id: m for m in mirrors}
    for pkg in packages:
        parsed = parse_nevra(pkg.nevra)
        mirror = by_id[pkg.mirror_id]
        arches = {mirror.match_arch, "src", "noarch"}
        if mirror.match_arch == "x86_64":
            arches.add("i686")
        if parsed["arch"] not in arches:
            raise ValueError("Archive package belongs to a different mirror architecture")
        if parsed["dist_major"] != mirror.match_major_version:
            raise ValueError("Archive package belongs to a different major version")
        cleaned, _ = repomd.clean_nvra(pkg.nevra)
        nvr = cleaned.rsplit(".", 1)[0]
        matched = False
        for rh_pkg in source.packages:
            rh = parse_nevra(rh_pkg.nevra)
            rh_cleaned, _ = repomd.clean_nvra(rh_pkg.nevra)
            if (parsed["name"] == rh["name"] and parsed["arch"] == rh["arch"]
                    and str(parsed["epoch"]) == str(rh["epoch"])
                    and parsed["dist_major"] == rh["dist_major"]
                    and repomd.nvr_is_rebuild_of(nvr, rh_cleaned.rsplit(".", 1)[0])):
                matched = True
                break
        if not matched:
            raise ValueError("Archive package does not match source advisory: " + pkg.nevra)


async def plan_archive_repair(advisory_name, archives):
    advisory = await Advisory.get(name=advisory_name).prefetch_related("red_hat_advisory")
    source = advisory.red_hat_advisory
    await source.fetch_related("packages", "cves", "bugzilla_tickets")
    before = await _packages(advisory.id)
    if not before:
        raise ValueError("Repair requires an existing advisory with packages")
    mirror_ids = {p.mirror_id for p in before}
    if {r.mirror_id for r in archives} != mirror_ids:
        raise ValueError("Archives must cover exactly the advisory's existing mirrors")
    mirrors = await SupportedProductsRhMirror.filter(id__in=list(mirror_ids)).all()
    if len(mirrors) != len(mirror_ids):
        raise ValueError("An advisory mirror no longer exists")
    product_ids = {m.supported_product_id for m in mirrors}
    if len(product_ids) != 1:
        raise ValueError("Repair requires mirrors of one supported product")
    await mirrors[0].fetch_related("supported_product", "supported_product__code")
    product = mirrors[0].supported_product
    by_id = {m.id: m for m in mirrors}
    all_pkgs, module_pkgs = [], {}
    for archive in archives:
        mirror = by_id[archive.mirror_id]
        config = SimpleNamespace(**asdict(archive), arch=mirror.match_arch, production=False)
        matches = await process_repomd(mirror, config, [source])
        match = matches.get(source.name)
        if match:
            all_pkgs.extend(match["packages"])
            module_pkgs.update(match["module_packages"])
    if not all_pkgs:
        raise ValueError("No source-advisory packages found in archive repositories")

    plan = None
    try:
        async with in_transaction():
            # clone_advisory operates under a nested transaction. Roll back its
            # writes after collecting the proposed package state, including its
            # CVE, topic, block and override updates.
            current = await Advisory.filter(id=advisory.id).select_for_update().get()
            if _snapshot(await _packages(current.id)) != _snapshot(before):
                raise ValueError("Advisory packages changed while downloading archives")
            await clone_advisory(product, mirrors, source, all_pkgs, module_pkgs,
                                 current.published_at)
            after = await _packages(current.id)
            _validate_source_matches(after, source, mirrors)
            if not _binary_keys(before).issubset(_binary_keys(after)):
                raise ValueError("Archive repositories would remove a binary package or architecture")
            plan = RepairPlan(current.id, current.name, before, after)
            raise _PreviewComplete()
    except _PreviewComplete:
        pass
    return plan


async def apply_archive_repair(plan):
    async with in_transaction():
        advisory = await Advisory.filter(id=plan.advisory_id).select_for_update().get()
        if _snapshot(await _packages(advisory.id)) != _snapshot(plan.before):
            raise ValueError("Advisory packages changed since this repair was planned")
        if _snapshot(plan.before) == _snapshot(plan.after):
            return False
        await create_or_update_advisory_packages(advisory, plan.after, update_advisory=True)
        if _snapshot(await _packages(advisory.id)) != _snapshot(plan.after):
            raise ValueError("Package replacement did not produce the planned state")
        advisory.updated_at = datetime.datetime.now(datetime.timezone.utc)
        await advisory.save(update_fields=["updated_at"])
    return True


async def _run(args):
    await Database(True).init(["apollo.db"])
    try:
        archives = [ArchiveRepository(**r) for r in
                    json.loads(Path(args.archives).read_text(encoding="utf-8"))]
        plan = await plan_archive_repair(args.advisory, archives)
        summary = plan.summary()
        summary["applied"] = await apply_archive_repair(plan) if args.apply else False
        print(json.dumps(summary, indent=2))
    finally:
        await Tortoise.close_connections()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--advisory", required=True)
    parser.add_argument("--archives", required=True, help="JSON archive repository manifest")
    parser.add_argument("--apply", action="store_true", help="Commit the planned package replacement")
    args = parser.parse_args()
    Info("apollo-repair-advisory", "apollo2")
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
