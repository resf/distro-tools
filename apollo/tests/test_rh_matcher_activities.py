"""
Tests for RH matcher activities
"""

import unittest
import asyncio
import sys
import os
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from xml.etree import ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.rpmworker import repomd
from apollo.rpmworker.rh_matcher_activities import process_repomd, stream_product_name

NS = "http://linux.duke.edu/metadata/common"
RPM_NS = "http://linux.duke.edu/metadata/rpm"


def _make_pkg_element(name, version, release, arch, epoch="0"):
    """Build a minimal repomd <package> XML element."""
    pkg = ET.Element(f"{{{NS}}}package")
    name_el = ET.SubElement(pkg, f"{{{NS}}}name")
    name_el.text = name
    ver_el = ET.SubElement(pkg, f"{{{NS}}}version")
    ver_el.set("ver", version)
    ver_el.set("rel", release)
    ver_el.set("epoch", epoch)
    arch_el = ET.SubElement(pkg, f"{{{NS}}}arch")
    arch_el.text = arch
    checksum_el = ET.SubElement(pkg, f"{{{NS}}}checksum")
    checksum_el.set("type", "sha256")
    checksum_el.text = "abc123"
    fmt = ET.SubElement(pkg, f"{{{NS}}}format")
    src = ET.SubElement(fmt, f"{{{RPM_NS}}}sourcerpm")
    src.text = f"{name}-{version}-{release}.src.rpm"
    return pkg


def _make_advisory(name, nevra_list):
    """Build a mock RedHatAdvisory with packages."""
    advisory = Mock()
    advisory.name = name
    advisory.id = 1
    pkgs = []
    for nevra in nevra_list:
        pkg = Mock()
        pkg.nevra = nevra
        pkgs.append(pkg)
    advisory.packages = pkgs
    advisory.cves = []
    advisory.bugzilla_tickets = []
    advisory.synopsis = "Test advisory"
    advisory.description = "Test description"
    advisory.kind = "SECURITY"
    advisory.severity = "Important"
    advisory.topic = "Test topic"
    return advisory


def _make_mirror(mirror_id=1, name="Rocky Linux 9 x86_64"):
    mirror = Mock()
    mirror.id = mirror_id
    mirror.name = name
    mirror.match_arch = "x86_64"
    mirror.match_major_version = 9
    mirror.match_minor_version = 7
    mirror.match_variant = "BaseOS"
    mirror.supported_product_id = 1
    return mirror


def _make_rpm_repomd():
    rpm_repomd = Mock()
    rpm_repomd.url = "https://example.com/BaseOS/x86_64/os/repodata/repomd.xml"
    rpm_repomd.debug_url = "https://example.com/BaseOS/x86_64/debug/repodata/repomd.xml"
    rpm_repomd.source_url = "https://example.com/BaseOS/source/repodata/repomd.xml"
    rpm_repomd.repo_name = "baseos"
    rpm_repomd.arch = "x86_64"
    rpm_repomd.production = True
    return rpm_repomd


def _mock_repomd_downloads(repo_pkgs):
    """
    Create patches for repomd.download_xml and repomd.get_data_from_repomd.

    repo_pkgs: list of ET.Element package elements to return from primary XML.
    """
    primary_xml = ET.Element(f"{{{NS}}}metadata")
    for pkg in repo_pkgs:
        primary_xml.append(pkg)

    async def fake_download_xml(url, **kwargs):
        return ET.Element("repomd")

    async def fake_get_data(url, data_type, el, is_yaml=False):
        if data_type == "primary":
            return primary_xml
        return None

    return fake_download_xml, fake_get_data


class TestPackageNameExtraction(unittest.TestCase):
    """Test package_name extraction from source RPMs"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_advisory_nvra = "libarchive-3.3.3-5.el8.src.rpm"
        self.test_binary_nvra = "libarchive-0:3.3.3-5.el8.x86_64.rpm"
        self.test_debuginfo_nvra = (
            "libarchive-debuginfo-0:3.3.3-5.el8.aarch64.rpm"
        )

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
        module_source_rpm = (
            "postgresql-12.5-1.module+el8.3.0+6656+95b1e5d5.src.rpm"
        )
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
        source_rpm_with = root_with.find("format").find(
            "{http://linux.duke.edu/metadata/rpm}sourcerpm"
        )
        self.assertIsNotNone(source_rpm_with)

        root_without = ET.fromstring(xml_without_sourcerpm)
        source_rpm_without = root_without.find("format").find(
            "{http://linux.duke.edu/metadata/rpm}sourcerpm"
        )
        self.assertIsNone(source_rpm_without)

    def test_package_name_extraction_workflow(self):
        """Test complete workflow of package_name extraction"""
        test_cases = [
            {
                "name": "Valid source RPM",
                "advisory_nvra": "libarchive-3.3.3-5.el8.src.rpm",
                "is_source": True,
                "source_rpm_text": None,
                "expected": "libarchive",
            },
            {
                "name": "Valid binary RPM with source",
                "advisory_nvra": "libarchive-0:3.3.3-5.el8.x86_64",
                "is_source": False,
                "source_rpm_text": "libarchive-3.3.3-5.el8.src.rpm",
                "expected": "libarchive",
            },
            {
                "name": "Binary RPM with missing source",
                "advisory_nvra": (
                    "libarchive-debuginfo-0:3.3.3-5.el8.aarch64"
                ),
                "is_source": False,
                "source_rpm_text": None,
                "expected": None,
            },
            {
                "name": "Invalid source RPM format",
                "advisory_nvra": "invalid-format",
                "is_source": True,
                "source_rpm_text": None,
                "expected": None,
            },
        ]

        for test_case in test_cases:
            with self.subTest(test_case=test_case["name"]):
                advisory_nvra = test_case["advisory_nvra"]
                source_rpm_text = test_case["source_rpm_text"]
                expected = test_case["expected"]

                package_name = None

                if advisory_nvra.endswith(
                    ".src.rpm"
                ) or advisory_nvra.endswith(".src"):
                    source_nvra = repomd.NVRA_RE.search(advisory_nvra)
                    if source_nvra:
                        package_name = source_nvra.group(1)
                elif source_rpm_text:
                    source_nvra = repomd.NVRA_RE.search(source_rpm_text)
                    if source_nvra:
                        package_name = source_nvra.group(1)

                self.assertEqual(
                    package_name,
                    expected,
                    f"Failed for {test_case['name']}: "
                    f"expected {expected}, got {package_name}",
                )


class TestProcessRepomdMatching(unittest.TestCase):
    """Test the NVRA matching logic in process_repomd."""

    def setUp(self):
        self._logger_patcher = patch(
            "apollo.rpmworker.rh_matcher_activities.Logger"
        )
        self._logger_patcher.start()

    def tearDown(self):
        self._logger_patcher.stop()

    def _run(self, coro):
        return asyncio.run(coro)

    def test_exact_match(self):
        """Packages with identical release strings match directly."""
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "9.el9_7", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0001",
            ["bash-0:5.1.8-9.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0001", result)

    def test_prefix_match_rocky_suffix(self):
        """Rocky packages with .rocky.X.Y suffix match via prefix."""
        repo_pkgs = [
            _make_pkg_element(
                "openssh", "8.7p1", "49.el9_7.rocky.0.1", "x86_64"
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0002",
            ["openssh-0:8.7p1-49.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0002", result)

    def test_no_match(self):
        """Advisory packages not in repo produce no match."""
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "9.el9_7", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0003",
            ["curl-0:7.76.1-29.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2026:0003", result)

    def test_module_package_match(self):
        """Module packages with module+ in release match directly."""
        repo_pkgs = [
            _make_pkg_element(
                "postgresql",
                "12.5",
                "1.module+el9.3.0+6656+95b1e5d5",
                "x86_64",
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0004",
            ["postgresql-0:12.5-1.module+el9.3.0+6656+95b1e5d5.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0004", result)

    def test_arch_mismatch_no_match(self):
        """Packages with wrong arch don't match."""
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "9.el9_7", "aarch64"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0005",
            ["bash-0:5.1.8-9.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2026:0005", result)

    def test_prefix_match_version_mismatch_no_match(self):
        """Rocky package with different version doesn't prefix-match."""
        repo_pkgs = [
            _make_pkg_element(
                "openssh", "8.7p1", "48.el9_7.rocky.0.1", "x86_64"
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0006",
            ["openssh-0:8.7p1-49.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2026:0006", result)

    def test_multiple_advisories_independent_matching(self):
        """Each advisory matches independently against repo packages."""
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "9.el9_7", "x86_64"),
            _make_pkg_element(
                "openssh", "8.7p1", "49.el9_7.rocky.0.1", "x86_64"
            ),
        ]
        advisory_match = _make_advisory(
            "RHSA-2026:0007",
            ["bash-0:5.1.8-9.el9_7.x86_64.rpm"],
        )
        advisory_no_match = _make_advisory(
            "RHSA-2026:0008",
            ["curl-0:7.76.1-29.el9_7.x86_64.rpm"],
        )
        advisory_prefix = _make_advisory(
            "RHSA-2026:0009",
            ["openssh-0:8.7p1-49.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        advisories = [advisory_match, advisory_no_match, advisory_prefix]
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(
                    _make_mirror(), _make_rpm_repomd(), advisories
                )
            )
        self.assertIn("RHSA-2026:0007", result)
        self.assertNotIn("RHSA-2026:0008", result)
        self.assertIn("RHSA-2026:0009", result)


class TestStreamProductName(unittest.TestCase):
    """packages.product_name must match affected_products.name on the major stream."""

    def test_collapses_point_release_in_mirror_name(self):
        mirror = _make_mirror(name="Rocky Linux 9.6 aarch64")
        mirror.match_arch = "aarch64"
        mirror.match_minor_version = 6
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 9 aarch64")

    def test_stream_mirror_name_unchanged(self):
        mirror = _make_mirror(name="Rocky Linux 9 x86_64")
        mirror.match_minor_version = None
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 9 x86_64")

    def test_riscv64_name_without_minor_unchanged(self):
        mirror = _make_mirror(name="Rocky Linux 10 riscv64")
        mirror.match_major_version = 10
        mirror.match_minor_version = None
        mirror.match_arch = "x86_64"
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 10 riscv64")

    def test_zero_minor_collapsed(self):
        mirror = _make_mirror(name="Rocky Linux 10.0 riscv64")
        mirror.match_major_version = 10
        mirror.match_minor_version = 0
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 10 riscv64")


class TestModularFieldResolution(unittest.TestCase):
    """distro-tools#72: RH CSAF module fallback when modules.yaml misses Rocky NEVRA."""

    def test_rh_csaf_fallback_when_yaml_misses(self):
        from apollo.rpmworker.rh_matcher_activities import _resolve_modular_package_fields

        rocky_nevra = "nodejs-1:16.20.2-4.module+el8.9.0+1760+903d54b9.x86_64.rpm"
        cleaned_rh = "module.nodejs-1:16.20.2-4.el8.9.0.x86_64"
        module_pkgs = {}
        rh_modules = {
            cleaned_rh: {
                "module_name": "nodejs",
                "module_stream": "16",
                "module_version": "8060020220913080029",
                "module_context": "d63f516d",
            }
        }
        name, stream, version, context = _resolve_modular_package_fields(
            "4.module+el8.9.0+1760+903d54b9",
            rocky_nevra,
            cleaned_rh,
            module_pkgs,
            rh_modules,
        )
        self.assertEqual(name, "nodejs")
        self.assertEqual(stream, "16")
        self.assertEqual(version, "8060020220913080029")
        self.assertEqual(context, "d63f516d")

    def test_yaml_lookup_normalizes_rocky_suffix(self):
        from apollo.rpmworker.rh_matcher_activities import _resolve_modular_package_fields

        rocky_nevra = (
            "ocaml-libguestfs-1:1.44.0-5.module+el8.6.0+1052+ff61d164.rocky.aarch64.rpm"
        )
        yaml_key = "ocaml-libguestfs-1:1.44.0-5.module+el8.6.0+1052+ff61d164.aarch64"
        module_pkgs = {
            yaml_key: ("virt-devel", "rhel", "8060020220913080029", "d63f516d"),
        }
        name, stream, version, context = _resolve_modular_package_fields(
            "5.module+el8.6.0+1052+ff61d164.rocky",
            rocky_nevra,
            "module.ocaml-libguestfs-1:1.44.0-5.el8.6.0.aarch64",
            module_pkgs,
            {},
        )
        self.assertEqual(name, "virt-devel")
        self.assertEqual(stream, "rhel")


if __name__ == "__main__":
    unittest.main()
