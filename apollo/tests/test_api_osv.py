"""
Tests for OSV API CVE filtering functionality
"""

import unittest
import datetime
from unittest.mock import Mock

from apollo.server.routes.api_osv import to_osv_advisory


class MockSupportedProduct:
    """Mock SupportedProduct model"""

    def __init__(self, variant="Rocky Linux", vendor="Rocky Enterprise Software Foundation"):
        self.variant = variant
        self.vendor = vendor


class MockSupportedProductsRhMirror:
    """Mock SupportedProductsRhMirror model"""

    def __init__(self, match_major_version=9):
        self.match_major_version = match_major_version


class MockPackage:
    """Mock Package model"""

    def __init__(
        self,
        nevra,
        product_name="Rocky Linux 9",
        repo_name="BaseOS",
        supported_product=None,
        supported_products_rh_mirror=None,
    ):
        self.nevra = nevra
        self.product_name = product_name
        self.repo_name = repo_name
        self.supported_product = supported_product or MockSupportedProduct()
        self.supported_products_rh_mirror = supported_products_rh_mirror


class MockCVE:
    """Mock CVE model"""

    def __init__(
        self,
        cve="CVE-2024-1234",
        cvss3_base_score="7.5",
        cvss3_scoring_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ):
        self.cve = cve
        self.cvss3_base_score = cvss3_base_score
        self.cvss3_scoring_vector = cvss3_scoring_vector


class MockFix:
    """Mock Fix model"""

    def __init__(self, source="https://bugzilla.redhat.com/show_bug.cgi?id=1234567"):
        self.source = source


class MockAdvisory:
    """Mock Advisory model"""

    def __init__(
        self,
        name="RLSA-2024:1234",
        synopsis="Important: test security update",
        description="A security update for test package",
        published_at=None,
        updated_at=None,
        packages=None,
        cves=None,
        fixes=None,
        red_hat_advisory=None,
    ):
        self.name = name
        self.synopsis = synopsis
        self.description = description
        self.published_at = published_at or datetime.datetime.now(
            datetime.timezone.utc
        )
        self.updated_at = updated_at or datetime.datetime.now(datetime.timezone.utc)
        self.packages = packages or []
        self.cves = cves or []
        self.fixes = fixes or []
        self.red_hat_advisory = red_hat_advisory


class TestOSVCVEFiltering(unittest.TestCase):
    """Test CVE filtering logic in OSV API"""

    def test_advisory_with_cve_has_upstream_references(self):
        """Test that advisories with CVEs have upstream references populated"""
        packages = [
            MockPackage(
                nevra="pcs-0:0.11.8-2.el9_5.src",
                supported_products_rh_mirror=MockSupportedProductsRhMirror(9),
            ),
        ]
        cves = [MockCVE(cve="CVE-2024-1234")]

        advisory = MockAdvisory(packages=packages, cves=cves)
        result = to_osv_advisory("https://errata.rockylinux.org", advisory)

        self.assertIsNotNone(result.upstream)
        self.assertEqual(len(result.upstream), 1)
        self.assertIn("CVE-2024-1234", result.upstream)

    def test_advisory_with_multiple_cves(self):
        """Test that advisories with multiple CVEs include all in upstream"""
        packages = [
            MockPackage(
                nevra="openssl-1:3.0.7-28.el9_5.src",
                supported_products_rh_mirror=MockSupportedProductsRhMirror(9),
            ),
        ]
        cves = [
            MockCVE(cve="CVE-2024-1111"),
            MockCVE(cve="CVE-2024-2222"),
            MockCVE(cve="CVE-2024-3333"),
        ]

        advisory = MockAdvisory(packages=packages, cves=cves)
        result = to_osv_advisory("https://errata.rockylinux.org", advisory)

        self.assertIsNotNone(result.upstream)
        self.assertEqual(len(result.upstream), 3)
        self.assertIn("CVE-2024-1111", result.upstream)
        self.assertIn("CVE-2024-2222", result.upstream)
        self.assertIn("CVE-2024-3333", result.upstream)

    def test_advisory_without_cves_has_empty_upstream(self):
        """Test that advisories without CVEs have empty upstream list"""
        packages = [
            MockPackage(
                nevra="kernel-0:5.14.0-427.el9.src",
                supported_products_rh_mirror=MockSupportedProductsRhMirror(9),
            ),
        ]

        advisory = MockAdvisory(packages=packages, cves=[])
        result = to_osv_advisory("https://errata.rockylinux.org", advisory)

        self.assertIsNotNone(result.upstream)
        self.assertEqual(len(result.upstream), 0)

    def test_source_packages_only(self):
        """Test that only source packages are processed, not binary packages"""
        packages = [
            MockPackage(
                nevra="httpd-0:2.4.57-8.el9.src",
                supported_products_rh_mirror=MockSupportedProductsRhMirror(9),
            ),
            MockPackage(
                nevra="httpd-0:2.4.57-8.el9.x86_64",
                supported_products_rh_mirror=MockSupportedProductsRhMirror(9),
            ),
            MockPackage(
                nevra="httpd-0:2.4.57-8.el9.aarch64",
                supported_products_rh_mirror=MockSupportedProductsRhMirror(9),
            ),
        ]
        cves = [MockCVE()]

        advisory = MockAdvisory(packages=packages, cves=cves)
        result = to_osv_advisory("https://errata.rockylinux.org", advisory)

        # Should only have 1 affected package (the source package)
        self.assertEqual(len(result.affected), 1)
        self.assertEqual(result.affected[0].package.name, "httpd")

    def test_severity_from_highest_cvss(self):
        """Test that severity uses the highest CVSS score from multiple CVEs"""
        packages = [
            MockPackage(
                nevra="vim-2:9.0.1592-1.el9.src",
                supported_products_rh_mirror=MockSupportedProductsRhMirror(9),
            ),
        ]
        cves = [
            MockCVE(
                cve="CVE-2024-1111",
                cvss3_base_score="5.5",
                cvss3_scoring_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            ),
            MockCVE(
                cve="CVE-2024-2222",
                cvss3_base_score="9.8",
                cvss3_scoring_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ),
            MockCVE(
                cve="CVE-2024-3333",
                cvss3_base_score="7.5",
                cvss3_scoring_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            ),
        ]

        advisory = MockAdvisory(packages=packages, cves=cves)
        result = to_osv_advisory("https://errata.rockylinux.org", advisory)

        self.assertIsNotNone(result.severity)
        self.assertEqual(len(result.severity), 1)
        self.assertEqual(result.severity[0].type, "CVSS_V3")
        self.assertEqual(
            result.severity[0].score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )

    def test_ecosystem_format(self):
        """Test that ecosystem field is formatted correctly"""
        packages = [
            MockPackage(
                nevra="bash-0:5.1.8-9.el9.src",
                product_name="Rocky Linux 9",
                supported_products_rh_mirror=MockSupportedProductsRhMirror(9),
            ),
        ]
        cves = [MockCVE()]

        advisory = MockAdvisory(packages=packages, cves=cves)
        result = to_osv_advisory("https://errata.rockylinux.org", advisory)

        self.assertEqual(len(result.affected), 1)
        self.assertEqual(result.affected[0].package.ecosystem, "Rocky Linux:9")

    def test_version_format_with_epoch(self):
        """Test that fixed version includes epoch in epoch:version-release format"""
        packages = [
            MockPackage(
                nevra="systemd-0:252-38.el9_5.src",
                supported_products_rh_mirror=MockSupportedProductsRhMirror(9),
            ),
        ]
        cves = [MockCVE()]

        advisory = MockAdvisory(packages=packages, cves=cves)
        result = to_osv_advisory("https://errata.rockylinux.org", advisory)

        fixed_version = result.affected[0].ranges[0].events[1].fixed
        self.assertEqual(fixed_version, "0:252-38.el9_5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
