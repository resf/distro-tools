"""
Tests for updateinfo API endpoints and helper functions
"""

import unittest
import sys
import os
import datetime
from xml.etree import ElementTree as ET
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.routes.api_updateinfo import (
    resolve_product_slug,
    get_source_package_name,
    build_source_rpm_mapping,
    generate_updateinfo_xml,
    PRODUCT_SLUG_MAP,
)


class TestProductSlugResolution(unittest.TestCase):
    """Test product slug resolution"""

    def test_valid_slug_rocky_linux(self):
        """Test resolving rocky-linux slug"""
        result = resolve_product_slug("rocky-linux")
        self.assertEqual(result, "Rocky Linux")

    def test_valid_slug_case_insensitive(self):
        """Test slug resolution is case-insensitive"""
        result = resolve_product_slug("ROCKY-LINUX")
        self.assertEqual(result, "Rocky Linux")

    def test_invalid_slug(self):
        """Test invalid slug returns None"""
        result = resolve_product_slug("invalid-product")
        self.assertIsNone(result)

    def test_sig_cloud_slug(self):
        """Test resolving sig-cloud slug"""
        result = resolve_product_slug("rocky-linux-sig-cloud")
        self.assertEqual(result, "Rocky Linux SIG Cloud")


class TestGetSourcePackageName(unittest.TestCase):
    """Test get_source_package_name helper"""

    def test_regular_package(self):
        """Test regular package without module"""
        pkg = Mock()
        pkg.package_name = "kernel"
        pkg.module_name = None

        result = get_source_package_name(pkg)
        self.assertEqual(result, "kernel")

    def test_module_package_without_prefix(self):
        """Test module package without module. prefix"""
        pkg = Mock()
        pkg.package_name = "python-markupsafe"
        pkg.module_name = "python27"
        pkg.module_stream = "el8"

        result = get_source_package_name(pkg)
        self.assertEqual(result, "python27:python-markupsafe:el8")

    def test_module_package_cleaned_by_orm(self):
        """Test module package (ORM strips module. prefix automatically)"""
        pkg = Mock()
        pkg.package_name = "python-markupsafe"  # ORM already cleaned
        pkg.module_name = "python27"
        pkg.module_stream = "el8"

        result = get_source_package_name(pkg)
        self.assertEqual(result, "python27:python-markupsafe:el8")

    def test_regular_package_cleaned_by_orm(self):
        """Test regular package (ORM strips module. prefix automatically)"""
        pkg = Mock()
        pkg.package_name = "delve"  # ORM already cleaned
        pkg.module_name = None

        result = get_source_package_name(pkg)
        self.assertEqual(result, "delve")


class TestBuildSourceRpmMapping(unittest.TestCase):
    """Test build_source_rpm_mapping helper"""

    def test_simple_source_rpm_mapping(self):
        """Test mapping for simple package"""
        src_pkg = Mock()
        src_pkg.package_name = "kernel"
        src_pkg.module_name = None
        src_pkg.nevra = "kernel-4.18.0-425.el8.src.rpm"

        bin_pkg = Mock()
        bin_pkg.package_name = "kernel"
        bin_pkg.module_name = None
        bin_pkg.nevra = "kernel-4.18.0-425.el8.x86_64.rpm"

        packages = [src_pkg, bin_pkg]

        result = build_source_rpm_mapping(packages)

        self.assertEqual(result, {"kernel": "kernel-4.18.0-425.el8.src.rpm"})

    def test_multi_binary_source_rpm_mapping(self):
        """Test mapping when multiple binaries share one source"""
        src_pkg = Mock()
        src_pkg.package_name = "python-markupsafe"
        src_pkg.module_name = None
        src_pkg.nevra = "python-markupsafe-0.23-19.el8.src.rpm"

        bin_pkg1 = Mock()
        bin_pkg1.package_name = "python-markupsafe"
        bin_pkg1.module_name = None
        bin_pkg1.nevra = "python2-markupsafe-0.23-19.el8.x86_64.rpm"

        bin_pkg2 = Mock()
        bin_pkg2.package_name = "python-markupsafe"
        bin_pkg2.module_name = None
        bin_pkg2.nevra = "python3-markupsafe-0.23-19.el8.x86_64.rpm"

        packages = [src_pkg, bin_pkg1, bin_pkg2]

        result = build_source_rpm_mapping(packages)

        self.assertEqual(result, {"python-markupsafe": "python-markupsafe-0.23-19.el8.src.rpm"})

    def test_module_package_cleaned_by_orm(self):
        """Test module package (ORM strips module. prefix automatically)"""
        src_pkg = Mock()
        src_pkg.package_name = "python-markupsafe"  # ORM already cleaned
        src_pkg.module_name = "python27"
        src_pkg.module_stream = "el8"
        src_pkg.nevra = "python-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.src.rpm"

        bin_pkg = Mock()
        bin_pkg.package_name = "python-markupsafe"  # ORM already cleaned
        bin_pkg.module_name = "python27"
        bin_pkg.module_stream = "el8"
        bin_pkg.nevra = "python2-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.x86_64.rpm"

        packages = [src_pkg, bin_pkg]

        result = build_source_rpm_mapping(packages)

        expected_key = "python27:python-markupsafe:el8"
        self.assertIn(expected_key, result)
        self.assertEqual(result[expected_key], "python-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.src.rpm")

    def test_no_source_rpm(self):
        """Test when no source RPM is present"""
        bin_pkg = Mock()
        bin_pkg.package_name = "kernel"
        bin_pkg.module_name = None
        bin_pkg.nevra = "kernel-4.18.0-425.el8.x86_64.rpm"

        packages = [bin_pkg]

        result = build_source_rpm_mapping(packages)

        self.assertEqual(result, {})


class TestProductSlugMapping(unittest.TestCase):
    """Test product slug mapping configuration"""

    def test_slug_map_contains_rocky_linux(self):
        """Test slug map contains rocky-linux"""
        self.assertIn("rocky-linux", PRODUCT_SLUG_MAP)
        self.assertEqual(PRODUCT_SLUG_MAP["rocky-linux"], "Rocky Linux")

    def test_slug_map_contains_sig_cloud(self):
        """Test slug map contains sig-cloud"""
        self.assertIn("rocky-linux-sig-cloud", PRODUCT_SLUG_MAP)
        self.assertEqual(PRODUCT_SLUG_MAP["rocky-linux-sig-cloud"], "Rocky Linux SIG Cloud")


class TestGenerateUpdateinfoXMLDeduplication(unittest.TestCase):
    """Test deduplication logic in generate_updateinfo_xml for V2 API"""

    def _create_mock_package(self, nevra, package_name, repo_name,
                            supported_product_id=None, product_name=None,
                            checksum="abc123", checksum_type="sha256",
                            module_name=None, module_stream=None,
                            module_version=None, module_context=None):
        pkg = Mock()
        pkg.nevra = nevra
        pkg.package_name = package_name
        pkg.repo_name = repo_name
        pkg.supported_product_id = supported_product_id
        pkg.product_name = product_name
        pkg.checksum = checksum
        pkg.checksum_type = checksum_type
        pkg.module_name = module_name
        pkg.module_stream = module_stream
        pkg.module_version = module_version
        pkg.module_context = module_context
        return pkg

    def _create_mock_advisory(self, packages):
        advisory = Mock()
        advisory.name = "RLSA-2024:0001"
        advisory.synopsis = "Important: kernel security update"
        advisory.description = "An update for kernel is now available."
        advisory.kind = "Security"
        advisory.severity = "Important"
        advisory.topic = "An update is available"
        advisory.published_at = datetime.datetime(2024, 1, 15, 10, 0, 0)
        advisory.updated_at = datetime.datetime(2024, 1, 15, 10, 0, 0)
        advisory.packages = packages
        advisory.cves = []
        advisory.fixes = []
        return advisory

    def _create_mock_affected_product(self, advisory):
        supported_product = Mock()
        supported_product.id = 1
        supported_product.name = "Rocky Linux"

        affected_product = Mock()
        affected_product.advisory = advisory
        affected_product.arch = "x86_64"
        affected_product.major_version = 8
        affected_product.minor_version = None
        affected_product.supported_product = supported_product
        return affected_product

    def _generate_xml(self, advisory, supported_product_id=None, product_name_for_packages="Rocky Linux"):
        affected_product = self._create_mock_affected_product(advisory)
        xml_str = generate_updateinfo_xml(
            affected_products=[affected_product],
            repo_name="BaseOS",
            product_arch="x86_64",
            ui_url="https://errata.rockylinux.org",
            managing_editor="editor@rockylinux.org",
            company_name="Rocky Enterprise Software Foundation",
            supported_product_id=supported_product_id,
            product_name_for_packages=product_name_for_packages
        )
        return ET.fromstring(xml_str)

    def test_v2_vs_v1_deduplication_behavior(self):
        """V2 deduplicates same NEVRA from multiple mirrors; V1 filters by mirror"""
        packages = [
            self._create_mock_package(
                nevra="kernel-4.18.0-425.el8.src.rpm",
                package_name="kernel",
                repo_name="BaseOS",
                supported_product_id=1,
                product_name="rocky-linux-mirror-1"
            ),
            self._create_mock_package(
                nevra="kernel-4.18.0-425.el8.x86_64.rpm",
                package_name="kernel",
                repo_name="BaseOS",
                supported_product_id=1,
                product_name="rocky-linux-mirror-1"
            ),
            self._create_mock_package(
                nevra="kernel-4.18.0-425.el8.x86_64.rpm",
                package_name="kernel",
                repo_name="BaseOS",
                supported_product_id=1,
                product_name="rocky-linux-mirror-2"
            ),
        ]
        advisory = self._create_mock_advisory(packages)

        tree_v2 = self._generate_xml(advisory, supported_product_id=1)
        kernel_pkgs_v2 = tree_v2.findall(".//package[@name='kernel']")
        self.assertEqual(len(kernel_pkgs_v2), 1, "V2 should deduplicate to 1 package")

        tree_v1 = self._generate_xml(advisory, supported_product_id=None,
                                     product_name_for_packages="rocky-linux-mirror-1")
        kernel_pkgs_v1 = tree_v1.findall(".//package[@name='kernel']")
        self.assertEqual(len(kernel_pkgs_v1), 1, "V1 gets 1 package via mirror filter")

    def test_v2_deduplication_edge_cases(self):
        """V2 handles unique packages, all duplicates, and mixed scenarios"""
        # Test 1: Mix of unique and duplicate packages
        packages = [
            self._create_mock_package("kernel-4.18.0-425.el8.src.rpm", "kernel", "BaseOS", 1),
            self._create_mock_package("kernel-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),
            self._create_mock_package("kernel-core-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),
            self._create_mock_package("kernel-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),  # Dup
            self._create_mock_package("kernel-modules-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),
        ]
        tree = self._generate_xml(self._create_mock_advisory(packages), supported_product_id=1)
        all_pkgs = tree.findall(".//package")
        self.assertEqual(len(all_pkgs), 3, "Should have 3 unique packages")
        pkg_names = [p.get("name") for p in all_pkgs]
        self.assertIn("kernel-core", pkg_names)
        self.assertIn("kernel-modules", pkg_names)

        # Test 2: All duplicates (5 identical from different mirrors)
        dup_packages = [self._create_mock_package("kernel-4.18.0-425.el8.src.rpm", "kernel", "BaseOS", 1)]
        for i in range(5):
            dup_packages.append(self._create_mock_package(
                "kernel-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1,
                product_name=f"mirror-{i}", checksum=f"cs{i}"
            ))
        tree = self._generate_xml(self._create_mock_advisory(dup_packages), supported_product_id=1)
        self.assertEqual(len(tree.findall(".//package[@name='kernel']")), 1)

        # Test 3: Empty package list
        tree = self._generate_xml(self._create_mock_advisory([]), supported_product_id=1)
        self.assertEqual(len(tree.findall(".//package")), 0)

    def test_v2_different_architectures_and_modules(self):
        """V2 handles different architectures (x86_64/noarch) and module packages"""
        # Test 1: Different architectures aren't duplicates
        arch_packages = [
            self._create_mock_package("python3-3.6.8-45.el8.src.rpm", "python3", "BaseOS", 1),
            self._create_mock_package("python3-3.6.8-45.el8.x86_64.rpm", "python3", "BaseOS", 1),
            self._create_mock_package("python3-3.6.8-45.el8.noarch.rpm", "python3", "BaseOS", 1),
        ]
        tree = self._generate_xml(self._create_mock_advisory(arch_packages), supported_product_id=1)
        self.assertEqual(len(tree.findall(".//package[@name='python3']")), 2)

        # Test 2: Module packages deduplicate
        mod_packages = [
            self._create_mock_package(
                "python-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.src.rpm",
                "python-markupsafe", "AppStream", 1, module_name="python27",
                module_stream="el8", module_version="8050020211112174310", module_context="866afabc"
            ),
            self._create_mock_package(
                "python-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.x86_64.rpm",
                "python-markupsafe", "AppStream", 1, product_name="mirror-1",
                module_name="python27", module_stream="el8",
                module_version="8050020211112174310", module_context="866afabc"
            ),
            self._create_mock_package(
                "python-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.x86_64.rpm",
                "python-markupsafe", "AppStream", 1, product_name="mirror-2",
                module_name="python27", module_stream="el8",
                module_version="8050020211112174310", module_context="866afabc"
            ),
        ]
        affected_product = self._create_mock_affected_product(self._create_mock_advisory(mod_packages))
        xml_str = generate_updateinfo_xml(
            affected_products=[affected_product],
            repo_name="AppStream",
            product_arch="x86_64",
            ui_url="https://errata.rockylinux.org",
            managing_editor="editor@rockylinux.org",
            company_name="Rocky Enterprise Software Foundation",
            supported_product_id=1,
            product_name_for_packages="Rocky Linux"
        )
        tree = ET.fromstring(xml_str)
        self.assertEqual(len(tree.findall(".//package[@name='python-markupsafe']")), 1)

    def test_v2_collection_naming_with_version_and_arch(self):
        """V2 collection names should include version and arch, not 'none'"""
        packages = [
            self._create_mock_package("kernel-4.18.0-425.el8.src.rpm", "kernel", "BaseOS", 1),
            self._create_mock_package("kernel-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),
        ]
        advisory = self._create_mock_advisory(packages)

        tree = self._generate_xml(advisory, supported_product_id=1,
                                  product_name_for_packages="Rocky Linux 8 x86_64")

        collection = tree.find(".//collection")
        self.assertIsNotNone(collection)

        collection_short = collection.get("short")
        self.assertEqual(collection_short, "rocky-linux-8-x86-64-baseos-rpms")
        self.assertNotIn("none", collection_short, "Collection should not contain 'none'")


if __name__ == "__main__":
    unittest.main()
