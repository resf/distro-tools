"""
Tests for updateinfo API endpoints and helper functions
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.routes.api_updateinfo import (
    resolve_product_slug,
    get_source_package_name,
    build_source_rpm_mapping,
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

    def test_module_package_with_prefix(self):
        """Test module package with module. prefix (bug case)"""
        pkg = Mock()
        pkg.package_name = "module.python-markupsafe"
        pkg.module_name = "python27"
        pkg.module_stream = "el8"

        result = get_source_package_name(pkg)
        self.assertEqual(result, "python27:python-markupsafe:el8")

    def test_regular_package_with_prefix(self):
        """Test regular package with module. prefix gets stripped"""
        pkg = Mock()
        pkg.package_name = "module.delve"
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

    def test_module_package_with_prefix(self):
        """Test module package with module. prefix"""
        src_pkg = Mock()
        src_pkg.package_name = "module.python-markupsafe"
        src_pkg.module_name = "python27"
        src_pkg.module_stream = "el8"
        src_pkg.nevra = "python-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3.src.rpm"

        bin_pkg = Mock()
        bin_pkg.package_name = "python-markupsafe"
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


if __name__ == "__main__":
    unittest.main()
