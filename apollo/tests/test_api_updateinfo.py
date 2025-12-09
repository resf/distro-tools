"""
Tests for updateinfo API endpoints and helper functions
"""

import unittest
import sys
import os
import datetime
import asyncio
from xml.etree import ElementTree as ET
from unittest.mock import Mock, patch, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.routes.api_updateinfo import (
    resolve_product_slug,
    get_source_package_name,
    build_source_rpm_mapping,
    generate_updateinfo_xml,
    get_updateinfo,
    get_updateinfo_v2,
    PRODUCT_SLUG_MAP,
)
from common.fastapi import RenderErrorTemplateException
from tortoise.exceptions import DoesNotExist


def create_mock_package(nevra, package_name, repo_name,
                       supported_product_id=None, product_name=None,
                       checksum="abc123", checksum_type="sha256",
                       module_name=None, module_stream=None,
                       module_version=None, module_context=None):
    """Create a mock package with all required attributes"""
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


def create_mock_advisory(packages, name="RLSA-2024:0001",
                        synopsis="Important: kernel security update",
                        description="An update for kernel is now available.",
                        kind="Security", severity="Important",
                        topic="An update is available"):
    """Create a mock advisory with packages"""
    advisory = Mock()
    advisory.name = name
    advisory.synopsis = synopsis
    advisory.description = description
    advisory.kind = kind
    advisory.severity = severity
    advisory.topic = topic
    advisory.published_at = datetime.datetime(2024, 1, 15, 10, 0, 0)
    advisory.updated_at = datetime.datetime(2024, 1, 15, 10, 0, 0)
    advisory.packages = packages
    advisory.cves = []
    advisory.fixes = []
    return advisory


def create_mock_supported_product(id=1, name="Rocky Linux"):
    """Create a mock supported product"""
    supported_product = Mock()
    supported_product.id = id
    supported_product.name = name
    return supported_product


def create_mock_affected_product(advisory, arch="x86_64", major_version=8,
                                minor_version=None, supported_product=None):
    """Create a mock affected product with all relationships"""
    if supported_product is None:
        supported_product = create_mock_supported_product()

    affected_product = Mock()
    affected_product.advisory = advisory
    affected_product.arch = arch
    affected_product.major_version = major_version
    affected_product.minor_version = minor_version
    affected_product.supported_product = supported_product
    return affected_product


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

    def _generate_xml(self, advisory, supported_product_id=None, product_name_for_packages="Rocky Linux"):
        affected_product = create_mock_affected_product(advisory)
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
            create_mock_package(
                nevra="kernel-4.18.0-425.el8.src.rpm",
                package_name="kernel",
                repo_name="BaseOS",
                supported_product_id=1,
                product_name="rocky-linux-mirror-1"
            ),
            create_mock_package(
                nevra="kernel-4.18.0-425.el8.x86_64.rpm",
                package_name="kernel",
                repo_name="BaseOS",
                supported_product_id=1,
                product_name="rocky-linux-mirror-1"
            ),
            create_mock_package(
                nevra="kernel-4.18.0-425.el8.x86_64.rpm",
                package_name="kernel",
                repo_name="BaseOS",
                supported_product_id=1,
                product_name="rocky-linux-mirror-2"
            ),
        ]
        advisory = create_mock_advisory(packages)

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
            create_mock_package("kernel-4.18.0-425.el8.src.rpm", "kernel", "BaseOS", 1),
            create_mock_package("kernel-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),
            create_mock_package("kernel-core-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),
            create_mock_package("kernel-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),  # Dup
            create_mock_package("kernel-modules-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),
        ]
        tree = self._generate_xml(create_mock_advisory(packages), supported_product_id=1)
        all_pkgs = tree.findall(".//package")
        self.assertEqual(len(all_pkgs), 3, "Should have 3 unique packages")
        pkg_names = [p.get("name") for p in all_pkgs]
        self.assertIn("kernel-core", pkg_names)
        self.assertIn("kernel-modules", pkg_names)

        # Test 2: All duplicates (5 identical from different mirrors)
        dup_packages = [create_mock_package("kernel-4.18.0-425.el8.src.rpm", "kernel", "BaseOS", 1)]
        for i in range(5):
            dup_packages.append(create_mock_package(
                "kernel-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1,
                product_name=f"mirror-{i}", checksum=f"cs{i}"
            ))
        tree = self._generate_xml(create_mock_advisory(dup_packages), supported_product_id=1)
        self.assertEqual(len(tree.findall(".//package[@name='kernel']")), 1)

        # Test 3: Empty package list
        tree = self._generate_xml(create_mock_advisory([]), supported_product_id=1)
        self.assertEqual(len(tree.findall(".//package")), 0)

    def test_v2_different_architectures_and_modules(self):
        """V2 handles different architectures (x86_64/noarch) and module packages"""
        # Test 1: Different architectures aren't duplicates
        arch_packages = [
            create_mock_package("python3-3.6.8-45.el8.src.rpm", "python3", "BaseOS", 1),
            create_mock_package("python3-3.6.8-45.el8.x86_64.rpm", "python3", "BaseOS", 1),
            create_mock_package("python3-3.6.8-45.el8.noarch.rpm", "python3", "BaseOS", 1),
        ]
        tree = self._generate_xml(create_mock_advisory(arch_packages), supported_product_id=1)
        self.assertEqual(len(tree.findall(".//package[@name='python3']")), 2)

        # Test 2: Module packages deduplicate
        mod_packages = [
            create_mock_package(
                "python-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.src.rpm",
                "python-markupsafe", "AppStream", 1, module_name="python27",
                module_stream="el8", module_version="8050020211112174310", module_context="866afabc"
            ),
            create_mock_package(
                "python-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.x86_64.rpm",
                "python-markupsafe", "AppStream", 1, product_name="mirror-1",
                module_name="python27", module_stream="el8",
                module_version="8050020211112174310", module_context="866afabc"
            ),
            create_mock_package(
                "python-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.x86_64.rpm",
                "python-markupsafe", "AppStream", 1, product_name="mirror-2",
                module_name="python27", module_stream="el8",
                module_version="8050020211112174310", module_context="866afabc"
            ),
        ]
        affected_product = create_mock_affected_product(create_mock_advisory(mod_packages))
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
            create_mock_package("kernel-4.18.0-425.el8.src.rpm", "kernel", "BaseOS", 1),
            create_mock_package("kernel-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1),
        ]
        advisory = create_mock_advisory(packages)

        tree = self._generate_xml(advisory, supported_product_id=1,
                                  product_name_for_packages="Rocky Linux 8 x86_64")

        collection = tree.find(".//collection")
        self.assertIsNotNone(collection)

        collection_short = collection.get("short")
        self.assertEqual(collection_short, "rocky-linux-8-x86-64-baseos-rpms")
        self.assertNotIn("none", collection_short, "Collection should not contain 'none'")


class TestUpdateinfoEndpoints(unittest.TestCase):
    """Test updateinfo endpoint functions with database mocking"""

    def _create_mock_query_chain(self, return_value):
        """Helper to mock .filter().prefetch_related().all() chain"""
        mock_queryset = Mock()
        mock_queryset.all = AsyncMock(return_value=return_value)
        mock_prefetch = Mock(return_value=mock_queryset)
        return mock_prefetch

    async def _mock_get_setting(self, key):
        """Mock settings retrieval"""
        settings = {
            "ui-url": "https://errata.rockylinux.org",
            "managing-editor": "editor@rockylinux.org",
            "company-name": "Rocky Enterprise Software Foundation",
        }
        return settings.get(key)

    def _create_mock_affected_product_for_endpoint(self):
        """Create mock with all relationships for endpoint testing"""
        src_pkg = create_mock_package("kernel-4.18.0-425.el8.src.rpm", "kernel", "BaseOS", 1, "Rocky Linux")
        bin_pkg = create_mock_package("kernel-4.18.0-425.el8.x86_64.rpm", "kernel", "BaseOS", 1, "Rocky Linux", checksum="def456")
        advisory = create_mock_advisory([src_pkg, bin_pkg])
        return create_mock_affected_product(advisory)

    @patch("apollo.server.routes.api_updateinfo.get_setting")
    @patch("apollo.server.routes.api_updateinfo.AdvisoryAffectedProduct")
    def test_get_updateinfo_success(self, mock_aap, mock_get_setting):
        """V1 endpoint returns valid XML when advisories exist"""
        mock_get_setting.side_effect = self._mock_get_setting

        mock_affected = self._create_mock_affected_product_for_endpoint()
        mock_filter = Mock()
        mock_filter.prefetch_related = self._create_mock_query_chain([mock_affected])
        mock_aap.filter.return_value = mock_filter

        response = asyncio.run(get_updateinfo("Rocky Linux", "BaseOS"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.media_type, "application/xml")
        self.assertIn(b"<updates>", response.body)

    @patch("apollo.server.routes.api_updateinfo.AdvisoryAffectedProduct")
    def test_get_updateinfo_not_found(self, mock_aap):
        """V1 endpoint raises 404 when no advisories found"""
        mock_filter = Mock()
        mock_filter.prefetch_related = self._create_mock_query_chain([])
        mock_aap.filter.return_value = mock_filter

        with self.assertRaises(RenderErrorTemplateException) as ctx:
            asyncio.run(get_updateinfo("Rocky Linux", "BaseOS"))

        self.assertEqual(ctx.exception.status_code, 404)

    @patch("apollo.server.routes.api_updateinfo.get_setting")
    @patch("apollo.server.routes.api_updateinfo.AdvisoryAffectedProduct")
    def test_get_updateinfo_with_arch_filter(self, mock_aap, mock_get_setting):
        """V1 endpoint filters by optional req_arch parameter"""
        mock_get_setting.side_effect = self._mock_get_setting

        mock_affected = self._create_mock_affected_product_for_endpoint()
        mock_affected.arch = "aarch64"
        mock_filter = Mock()
        mock_filter.prefetch_related = self._create_mock_query_chain([mock_affected])
        mock_aap.filter.return_value = mock_filter

        response = asyncio.run(get_updateinfo("Rocky Linux", "BaseOS", req_arch="aarch64"))

        self.assertEqual(response.status_code, 200)
        mock_aap.filter.assert_called_once()
        call_args = mock_aap.filter.call_args[1]
        self.assertEqual(call_args["arch"], "aarch64")

    @patch("apollo.server.routes.api_updateinfo.get_setting")
    @patch("apollo.server.routes.api_updateinfo.SupportedProduct")
    @patch("apollo.server.routes.api_updateinfo.AdvisoryAffectedProduct")
    def test_get_updateinfo_v2_success(self, mock_aap, mock_sp, mock_get_setting):
        """V2 endpoint returns valid XML with proper collection naming"""
        mock_get_setting.side_effect = self._mock_get_setting

        mock_product = Mock()
        mock_product.id = 1
        mock_product.name = "Rocky Linux"
        mock_sp.get = AsyncMock(return_value=mock_product)

        mock_affected = self._create_mock_affected_product_for_endpoint()
        mock_filter = Mock()
        mock_filter.prefetch_related = self._create_mock_query_chain([mock_affected])
        mock_aap.filter.return_value = mock_filter

        response = asyncio.run(get_updateinfo_v2("rocky-linux", 8, "BaseOS", "x86_64"))

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"rocky-linux-8-x86-64", response.body)

    def test_get_updateinfo_v2_invalid_slug(self):
        """V2 endpoint raises 404 for invalid product slug"""
        with self.assertRaises(RenderErrorTemplateException) as ctx:
            asyncio.run(get_updateinfo_v2("invalid-product", 8, "BaseOS", "x86_64"))

        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("Unknown product", str(ctx.exception))

    @patch("apollo.server.routes.api_updateinfo.SupportedProduct")
    def test_get_updateinfo_v2_product_not_found(self, mock_sp):
        """V2 endpoint raises 404 when product doesn't exist"""
        mock_sp.get = AsyncMock(side_effect=DoesNotExist())

        with self.assertRaises(RenderErrorTemplateException) as ctx:
            asyncio.run(get_updateinfo_v2("rocky-linux", 8, "BaseOS", "x86_64"))

        self.assertEqual(ctx.exception.status_code, 404)

    @patch("apollo.server.routes.api_updateinfo.SupportedProduct")
    def test_get_updateinfo_v2_invalid_architecture(self, mock_sp):
        """V2 endpoint raises 400 for invalid architecture"""
        mock_product = Mock()
        mock_product.id = 1
        mock_sp.get = AsyncMock(return_value=mock_product)

        with self.assertRaises(RenderErrorTemplateException) as ctx:
            asyncio.run(get_updateinfo_v2("rocky-linux", 8, "BaseOS", "invalid-arch"))

        self.assertEqual(ctx.exception.status_code, 400)

    @patch("apollo.server.routes.api_updateinfo.SupportedProduct")
    @patch("apollo.server.routes.api_updateinfo.AdvisoryAffectedProduct")
    def test_get_updateinfo_v2_no_advisories(self, mock_aap, mock_sp):
        """V2 endpoint raises 404 when no advisories found"""
        mock_product = Mock()
        mock_product.id = 1
        mock_product.name = "Rocky Linux"
        mock_sp.get = AsyncMock(return_value=mock_product)

        mock_filter = Mock()
        mock_filter.prefetch_related = self._create_mock_query_chain([])
        mock_aap.filter.return_value = mock_filter

        with self.assertRaises(RenderErrorTemplateException) as ctx:
            asyncio.run(get_updateinfo_v2("rocky-linux", 8, "BaseOS", "x86_64"))

        self.assertEqual(ctx.exception.status_code, 404)

    @patch("apollo.server.routes.api_updateinfo.get_setting")
    @patch("apollo.server.routes.api_updateinfo.SupportedProduct")
    @patch("apollo.server.routes.api_updateinfo.AdvisoryAffectedProduct")
    def test_get_updateinfo_v2_with_minor_version(self, mock_aap, mock_sp, mock_get_setting):
        """V2 endpoint filters by optional minor_version parameter"""
        mock_get_setting.side_effect = self._mock_get_setting

        mock_product = Mock()
        mock_product.id = 1
        mock_product.name = "Rocky Linux"
        mock_sp.get = AsyncMock(return_value=mock_product)

        mock_affected = self._create_mock_affected_product_for_endpoint()
        mock_affected.minor_version = 6
        mock_filter = Mock()
        mock_filter.prefetch_related = self._create_mock_query_chain([mock_affected])
        mock_aap.filter.return_value = mock_filter

        response = asyncio.run(get_updateinfo_v2("rocky-linux", 8, "BaseOS", "x86_64", minor_version=6))

        self.assertEqual(response.status_code, 200)
        mock_aap.filter.assert_called_once()
        call_args = mock_aap.filter.call_args[1]
        self.assertEqual(call_args["minor_version"], 6)


if __name__ == "__main__":
    unittest.main()
