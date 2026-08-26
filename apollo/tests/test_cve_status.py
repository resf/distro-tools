"""Unit tests for CVE product status helpers (distro-tools#73)."""

import unittest

from apollo.rpmworker.cve_status_activities import (
    package_name_from_nevra,
    STATUS_FIXED,
    STATUS_NOT_SHIPPED,
    STATUS_UNDER_INVESTIGATION,
)


class TestPackageNameFromNevra(unittest.TestCase):
    def test_with_epoch_and_dist(self):
        self.assertEqual(
            package_name_from_nevra("bash-0:5.1.8-9.el9_7.x86_64.rpm"),
            "bash",
        )

    def test_modular(self):
        self.assertEqual(
            package_name_from_nevra(
                "nodejs-1:16.20.2-4.module+el8.9.0+1760+903d54b9.x86_64.rpm"
            ),
            "nodejs",
        )

    def test_hyphenated_name(self):
        self.assertEqual(
            package_name_from_nevra(
                "nginx-mod-http-image-filter-1:1.24.0-7.el9.x86_64"
            ),
            "nginx-mod-http-image-filter",
        )


class TestStatusConstants(unittest.TestCase):
    def test_status_values(self):
        self.assertEqual(STATUS_FIXED, "fixed")
        self.assertEqual(STATUS_NOT_SHIPPED, "not_shipped")
        self.assertEqual(STATUS_UNDER_INVESTIGATION, "under_investigation")


if __name__ == "__main__":
    unittest.main()
