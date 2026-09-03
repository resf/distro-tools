"""Unit tests for NVRA alias matching (prefix + EVR >=)."""

import unittest
from xml.etree import ElementTree as ET

from apollo.rpmworker.nvra_match import find_nvra_alias, _is_rebuild_prefix

NS = "http://linux.duke.edu/metadata/common"


def _pkg(name, version, release, arch, epoch="0"):
    pkg = ET.Element(f"{{{NS}}}package")
    ET.SubElement(pkg, f"{{{NS}}}name").text = name
    ver = ET.SubElement(pkg, f"{{{NS}}}version")
    ver.set("ver", version)
    ver.set("rel", release)
    ver.set("epoch", epoch)
    ET.SubElement(pkg, f"{{{NS}}}arch").text = arch
    return pkg


class TestFindNvraAlias(unittest.TestCase):
    def test_prefix_preferred_over_evr(self):
        rocky = "openssh-8.7p1-49.rocky.0.1.x86_64"
        raw = {rocky: [_pkg("openssh", "8.7p1", "49.el9_7.rocky.0.1", "x86_64")]}
        alias = find_nvra_alias(
            "openssh-8.7p1-49.x86_64",
            [rocky, "openssh-8.7p1-50.x86_64"],
            advisory_nevra="openssh-0:8.7p1-49.el9_7.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertEqual(alias, rocky)

    def test_prefix_requires_dot_boundary(self):
        """Release 80 must not prefix-match cleaned release 8."""
        self.assertFalse(_is_rebuild_prefix("openssh-8.7p1-80", "openssh-8.7p1-8"))
        self.assertTrue(
            _is_rebuild_prefix("openssh-8.7p1-8.rocky.0.1", "openssh-8.7p1-8")
        )
        # Without package XML, digit-extension must not alias via prefix.
        alias = find_nvra_alias(
            "openssh-8.7p1-8.x86_64",
            ["openssh-8.7p1-80.x86_64"],
            advisory_nevra="openssh-0:8.7p1-8.el9.x86_64.rpm",
            raw_pkg_nvras=None,
        )
        self.assertIsNone(alias)

    def test_module_rebuild_suffix_is_not_prefix(self):
        """httpd 51.1 is a later snapshot, not a .rocky rebuild of 51 (issue 8)."""
        self.assertFalse(
            _is_rebuild_prefix("httpd-2.4.37-51.1", "httpd-2.4.37-51")
        )
        self.assertTrue(
            _is_rebuild_prefix("httpd-2.4.37-51.rocky.0.1", "httpd-2.4.37-51")
        )
        alias = find_nvra_alias(
            "httpd-2.4.37-51.x86_64",
            ["httpd-2.4.37-51.1.x86_64"],
            advisory_nevra="httpd-0:2.4.37-51.module+el8.7.0+1059+126e9251.x86_64.rpm",
            raw_pkg_nvras=None,
        )
        self.assertIsNone(alias)

    def test_digit_extension_can_still_evr_match(self):
        """After boundary reject, EVR >= may still select a newer release."""
        rocky = "openssh-8.7p1-80.x86_64"
        raw = {rocky: [_pkg("openssh", "8.7p1", "80.el9", "x86_64")]}
        alias = find_nvra_alias(
            "openssh-8.7p1-8.x86_64",
            [rocky],
            advisory_nevra="openssh-0:8.7p1-8.el9.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertEqual(alias, rocky)

    def test_evr_picks_lowest_satisfying(self):
        older = "bash-5.1.8-6.x86_64"
        mid = "bash-5.1.8-9.x86_64"
        newer = "bash-5.1.8-10.x86_64"
        raw = {
            older: [_pkg("bash", "5.1.8", "6.el9", "x86_64")],
            mid: [_pkg("bash", "5.1.8", "9.el9", "x86_64")],
            newer: [_pkg("bash", "5.1.8", "10.el9", "x86_64")],
        }
        alias = find_nvra_alias(
            "bash-5.1.8-8.x86_64",
            [newer, older, mid],
            advisory_nevra="bash-0:5.1.8-8.el9.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertEqual(alias, mid)

    def test_older_rocky_no_match(self):
        rocky = "openssh-8.7p1-48.rocky.0.1.x86_64"
        raw = {rocky: [_pkg("openssh", "8.7p1", "48.el9_7.rocky.0.1", "x86_64")]}
        alias = find_nvra_alias(
            "openssh-8.7p1-49.x86_64",
            [rocky],
            advisory_nevra="openssh-0:8.7p1-49.el9_7.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertIsNone(alias)


if __name__ == "__main__":
    unittest.main()
