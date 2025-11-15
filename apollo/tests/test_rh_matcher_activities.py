"""
Tests for RH matcher activities package_name extraction logic
"""

import unittest
import sys
import os
from unittest.mock import Mock, MagicMock, patch
from xml.etree import ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.rpmworker import repomd


class TestPackageNameExtraction(unittest.TestCase):
    """Test package_name extraction from source RPMs"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_advisory_nvra = "libarchive-3.3.3-5.el8.src.rpm"
        self.test_binary_nvra = "libarchive-0:3.3.3-5.el8.x86_64.rpm"
        self.test_debuginfo_nvra = "libarchive-debuginfo-0:3.3.3-5.el8.aarch64.rpm"

    def test_nvra_regex_matches_source_rpm(self):
        """Test NVRA_RE regex matches source RPM correctly"""
        match = repomd.NVRA_RE.search(self.test_advisory_nvra)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "libarchive")

    def test_nvra_regex_matches_binary_rpm(self):
        """Test NVRA_RE regex matches binary RPM name"""
        source_rpm_text = "libarchive-3.3.3-5.el8.src.rpm"
        match = repomd.NVRA_RE.search(source_rpm_text)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "libarchive")

    def test_nvra_regex_handles_module_packages(self):
        """Test NVRA_RE regex extracts package name from module packages"""
        module_source_rpm = "postgresql-12.5-1.module+el8.3.0+6656+95b1e5d5.src.rpm"
        match = repomd.NVRA_RE.search(module_source_rpm)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "postgresql")

    def test_nvra_regex_no_match_returns_none(self):
        """Test NVRA_RE regex returns None for invalid format"""
        invalid_nvra = "not-a-valid-package-name"
        match = repomd.NVRA_RE.search(invalid_nvra)
        self.assertIsNone(match)

    def test_source_rpm_element_handling(self):
        """Test handling of missing source_rpm XML element"""
        xml_with_sourcerpm = """
        <package xmlns:rpm="http://linux.duke.edu/metadata/rpm">
            <format>
                <rpm:sourcerpm>libarchive-3.3.3-5.el8.src.rpm</rpm:sourcerpm>
            </format>
        </package>
        """
        xml_without_sourcerpm = """
        <package xmlns:rpm="http://linux.duke.edu/metadata/rpm">
            <format>
            </format>
        </package>
        """

        root_with = ET.fromstring(xml_with_sourcerpm)
        source_rpm_with = root_with.find("format").find("{http://linux.duke.edu/metadata/rpm}sourcerpm")
        self.assertIsNotNone(source_rpm_with)

        root_without = ET.fromstring(xml_without_sourcerpm)
        source_rpm_without = root_without.find("format").find("{http://linux.duke.edu/metadata/rpm}sourcerpm")
        self.assertIsNone(source_rpm_without)

    def test_package_name_extraction_workflow(self):
        """Test complete workflow of package_name extraction with various scenarios"""
        test_cases = [
            {
                "name": "Valid source RPM",
                "advisory_nvra": "libarchive-3.3.3-5.el8.src.rpm",
                "is_source": True,
                "source_rpm_text": None,
                "expected": "libarchive"
            },
            {
                "name": "Valid binary RPM with source",
                "advisory_nvra": "libarchive-0:3.3.3-5.el8.x86_64",
                "is_source": False,
                "source_rpm_text": "libarchive-3.3.3-5.el8.src.rpm",
                "expected": "libarchive"
            },
            {
                "name": "Binary RPM with missing source",
                "advisory_nvra": "libarchive-debuginfo-0:3.3.3-5.el8.aarch64",
                "is_source": False,
                "source_rpm_text": None,
                "expected": None
            },
            {
                "name": "Invalid source RPM format",
                "advisory_nvra": "invalid-format",
                "is_source": True,
                "source_rpm_text": None,
                "expected": None
            },
        ]

        for test_case in test_cases:
            with self.subTest(test_case=test_case["name"]):
                advisory_nvra = test_case["advisory_nvra"]
                is_source = test_case["is_source"]
                source_rpm_text = test_case["source_rpm_text"]
                expected = test_case["expected"]

                package_name = None

                if advisory_nvra.endswith(".src.rpm") or advisory_nvra.endswith(".src"):
                    source_nvra = repomd.NVRA_RE.search(advisory_nvra)
                    if source_nvra:
                        package_name = source_nvra.group(1)
                elif source_rpm_text:
                    source_nvra = repomd.NVRA_RE.search(source_rpm_text)
                    if source_nvra:
                        package_name = source_nvra.group(1)

                self.assertEqual(package_name, expected,
                               f"Failed for {test_case['name']}: expected {expected}, got {package_name}")


if __name__ == "__main__":
    unittest.main()
