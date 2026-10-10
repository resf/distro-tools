"""Historical advisory recovery, including database rollback and OSV output.

SQLite is used by default. APOLLO_REPAIR_TEST_DB can select a dedicated local
PostgreSQL test database. Only records created by each test are removed.
"""
import datetime
import os
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

from tortoise import Tortoise

from apollo.db import (
    Advisory, AdvisoryCVE, AdvisoryPackage, Code, RedHatAdvisory,
    RedHatAdvisoryPackage, SupportedProduct, SupportedProductsRhBlock,
    SupportedProductsRhMirror,
)
from apollo.rpmworker import repomd
from apollo.rpmworker import repair_advisory
from apollo.rpmworker.repair_advisory import (
    ArchiveRepository, apply_archive_repair, plan_archive_repair,
)
from apollo.server.routes.api_osv import to_osv_advisory
from common.info import Info

NS = "http://linux.duke.edu/metadata/common"
RPM_NS = "http://linux.duke.edu/metadata/rpm"


def primary(release="1.el9", arch="x86_64", epoch="0"):
    root = ET.Element(f"{{{NS}}}metadata")
    pkg = ET.SubElement(root, f"{{{NS}}}package")
    ET.SubElement(pkg, f"{{{NS}}}name").text = "krb5-libs"
    ET.SubElement(pkg, f"{{{NS}}}arch").text = arch
    ET.SubElement(pkg, f"{{{NS}}}version", epoch=epoch, ver="1.21.1", rel=release)
    ET.SubElement(pkg, f"{{{NS}}}checksum", type="sha256").text = "historical-checksum"
    fmt = ET.SubElement(pkg, f"{{{NS}}}format")
    ET.SubElement(fmt, f"{{{RPM_NS}}}sourcerpm").text = f"krb5-1.21.1-{release}.src.rpm"
    return root


class TestArchiveRepair(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        try:
            Info()
        except ValueError:
            Info("apollo-repair-tests", "apollo2")
        await Tortoise.init(
            db_url=os.environ.get("APOLLO_REPAIR_TEST_DB", "sqlite://:memory:"),
            modules={"models": ["apollo.db"]}, use_tz=True,
        )
        await Tortoise.generate_schemas()
        self.code = await Code.create(code="RL204TEST", description="test fixture")
        self.product = await SupportedProduct.create(
            name="Rocky Linux repair test", variant="Rocky Linux", code=self.code,
            vendor="Rocky Enterprise Software Foundation",
        )
        self.mirror = await SupportedProductsRhMirror.create(
            supported_product=self.product, name="Rocky Linux 9 x86_64",
            match_variant="Red Hat Enterprise Linux", match_major_version=9,
            match_arch="x86_64",
        )
        self.source = await RedHatAdvisory.create(
            name="RHSA-2023:6699", red_hat_issued_at=datetime.datetime(2023, 11, 7,
                tzinfo=datetime.timezone.utc), synopsis="Important: krb5 update",
            description="fixture", kind="Security", severity="Important", topic="fixture",
        )
        await RedHatAdvisoryPackage.create(
            red_hat_advisory=self.source, nevra="krb5-libs-0:1.21.1-1.el9.x86_64",
        )
        self.advisory = await Advisory.create(
            name="RL204TESTSA-2023:6699", red_hat_advisory=self.source,
            published_at=datetime.datetime(2026, 5, 28, tzinfo=datetime.timezone.utc),
            synopsis="Important: krb5 update", description="fixture", topic="original-topic",
            kind="Security", severity="Important",
        )
        await AdvisoryCVE.create(advisory=self.advisory, cve="CVE-2023-39975")
        self.stale = await self.add_package("krb5-libs-0:1.21.1-10.el9_8.x86_64.rpm")
        self.archive = ArchiveRepository(
            self.mirror.id, "BaseOS", "https://example.test/archive/repodata/repomd.xml",
            "https://example.test/debug/repodata/repomd.xml",
            "https://example.test/source/repodata/repomd.xml",
        )
        self.root = primary()
        self.patches = [
            patch.object(repomd, "download_xml", side_effect=self.download),
            patch.object(repomd, "get_data_from_repomd", side_effect=self.get_data),
        ]
        for p in self.patches:
            p.start()

    async def asyncTearDown(self):
        for p in self.patches:
            p.stop()
        await self.source.delete()
        await self.product.delete()
        await self.code.delete()
        await Tortoise.close_connections()

    async def add_package(self, nevra, mirror=None):
        return await AdvisoryPackage.create(
            advisory=self.advisory, nevra=nevra, checksum="stale-checksum",
            checksum_type="sha256", repo_name="BaseOS", package_name="krb5",
            product_name="Rocky Linux 9 x86_64", supported_product=self.product,
            supported_products_rh_mirror=mirror or self.mirror,
        )

    async def download(self, url, **_kwargs):
        return ET.Element("repomd", source=url)

    async def get_data(self, url, kind, element, **_kwargs):
        self.assertEqual(element.get("source"), url)
        return self.root if kind == "primary" else None

    async def osv(self):
        advisory = await Advisory.get(id=self.advisory.id).prefetch_related(
            "packages", "packages__supported_product", "packages__supported_products_rh_mirror",
            "cves", "fixes", "red_hat_advisory",
        )
        return to_osv_advisory("https://example.test", advisory)

    async def test_preview_rolls_back_all_matcher_writes(self):
        before = await Advisory.get(id=self.advisory.id)
        plan = await plan_archive_repair(self.advisory.name, [self.archive])
        self.assertEqual(plan.summary()["add"], ["krb5-libs-0:1.21.1-1.el9.x86_64.rpm"])
        self.assertEqual(await AdvisoryPackage.filter(advisory=self.advisory).values_list("nevra", flat=True),
                         [self.stale.nevra])
        after = await Advisory.get(id=self.advisory.id)
        self.assertEqual(after.updated_at, before.updated_at)
        self.assertEqual(after.topic, "original-topic")
        self.assertEqual(await SupportedProductsRhBlock.all().count(), 0)
        self.assertEqual(await AdvisoryCVE.filter(advisory=self.advisory).count(), 1)

    async def test_apply_restores_osv_and_is_idempotent(self):
        self.assertEqual((await self.osv()).affected[0].ranges[0].events[1].fixed,
                         "0:1.21.1-10.el9_8")
        plan = await plan_archive_repair(self.advisory.name, [self.archive])
        self.assertTrue(await apply_archive_repair(plan))
        osv = await self.osv()
        self.assertEqual(osv.affected[0].ranges[0].events[1].fixed, "0:1.21.1-1.el9")
        self.assertEqual(osv.upstream, ["CVE-2023-39975"])
        row = await AdvisoryPackage.get(advisory=self.advisory)
        self.assertEqual(row.checksum, "historical-checksum")
        current = await Advisory.get(id=self.advisory.id)
        self.assertEqual(current.published_at, self.advisory.published_at)
        self.assertEqual(current.topic, "original-topic")
        again = await plan_archive_repair(self.advisory.name, [self.archive])
        self.assertFalse(await apply_archive_repair(again))
        self.assertEqual((await Advisory.get(id=self.advisory.id)).updated_at, current.updated_at)

    async def test_live_newer_build_cannot_repair_original_fix(self):
        self.root = primary(release="10.el9_8")
        with self.assertRaisesRegex(ValueError, "No source-advisory packages"):
            await plan_archive_repair(self.advisory.name, [self.archive])
        self.assertEqual(await AdvisoryPackage.filter(advisory=self.advisory).count(), 1)

    async def test_incomplete_binary_coverage_rolls_back(self):
        await self.add_package("krb5-workstation-0:1.21.1-10.el9_8.x86_64.rpm")
        with self.assertRaisesRegex(ValueError, "remove a binary package"):
            await plan_archive_repair(self.advisory.name, [self.archive])
        self.assertEqual(await AdvisoryPackage.filter(advisory=self.advisory).count(), 2)

    async def test_missing_mirror_is_rejected(self):
        other = await SupportedProductsRhMirror.create(
            supported_product=self.product, name="Rocky Linux 9 aarch64",
            match_variant="Red Hat Enterprise Linux", match_major_version=9, match_arch="aarch64",
        )
        await self.add_package("krb5-libs-0:1.21.1-10.el9_8.aarch64.rpm", other)
        with self.assertRaisesRegex(ValueError, "existing mirrors"):
            await plan_archive_repair(self.advisory.name, [self.archive])

    async def test_epoch_mismatch_is_rejected(self):
        self.root = primary(epoch="1")
        with self.assertRaisesRegex(ValueError, "does not match source advisory"):
            await plan_archive_repair(self.advisory.name, [self.archive])
        self.assertTrue(await AdvisoryPackage.filter(id=self.stale.id).exists())

    async def test_cross_major_archive_is_rejected(self):
        self.root = primary(release="1.el8")
        with self.assertRaisesRegex(ValueError, "different major version"):
            await plan_archive_repair(self.advisory.name, [self.archive])
        self.assertTrue(await AdvisoryPackage.filter(id=self.stale.id).exists())

    async def test_changed_data_after_preview_is_rejected(self):
        plan = await plan_archive_repair(self.advisory.name, [self.archive])
        await AdvisoryPackage.filter(id=self.stale.id).update(checksum="concurrent-update")
        with self.assertRaisesRegex(ValueError, "changed since"):
            await apply_archive_repair(plan)
        self.assertEqual((await AdvisoryPackage.get(id=self.stale.id)).checksum, "concurrent-update")

    async def test_failed_apply_rolls_back_package_replacement(self):
        plan = await plan_archive_repair(self.advisory.name, [self.archive])
        replace = repair_advisory.create_or_update_advisory_packages

        async def fail_after_replacement(*args, **kwargs):
            await replace(*args, **kwargs)
            raise RuntimeError("interrupted replacement")

        with patch.object(repair_advisory, "create_or_update_advisory_packages",
                          side_effect=fail_after_replacement):
            with self.assertRaisesRegex(RuntimeError, "interrupted replacement"):
                await apply_archive_repair(plan)
        self.assertEqual(await AdvisoryPackage.filter(advisory=self.advisory).values_list("nevra", flat=True),
                         [self.stale.nevra])

    async def test_real_rocky_rebuild_is_preserved(self):
        self.root = primary(release="1.el9.rocky.0.1")
        plan = await plan_archive_repair(self.advisory.name, [self.archive])
        await apply_archive_repair(plan)
        self.assertEqual((await self.osv()).affected[0].ranges[0].events[1].fixed,
                         "0:1.21.1-1.el9.rocky.0.1")


if __name__ == "__main__":
    unittest.main()
