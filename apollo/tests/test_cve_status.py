"""Unit tests for CVE product status helpers (distro-tools#73)."""

import unittest

from apollo.rpmworker.cve_status_activities import (
    package_name_from_nevra,
    STATUS_FIXED,
    STATUS_NOT_SHIPPED,
    STATUS_UNDER_INVESTIGATION,
    _STATUS_PRIORITY,
)
from apollo.server.routes.api_vex import _STATUS_TO_VEX
from apollo.server.routes.api_updateinfo import router as updateinfo_router


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

    def test_fixed_outranks_other_statuses(self):
        self.assertGreater(
            _STATUS_PRIORITY[STATUS_FIXED],
            _STATUS_PRIORITY[STATUS_UNDER_INVESTIGATION],
        )
        self.assertGreater(
            _STATUS_PRIORITY[STATUS_UNDER_INVESTIGATION],
            _STATUS_PRIORITY[STATUS_NOT_SHIPPED],
        )


class TestOpenVexMapping(unittest.TestCase):
    def test_not_shipped_is_not_affected_not_fixed(self):
        self.assertEqual(_STATUS_TO_VEX[STATUS_NOT_SHIPPED], "not_affected")
        self.assertEqual(_STATUS_TO_VEX[STATUS_FIXED], "fixed")
        self.assertEqual(
            _STATUS_TO_VEX[STATUS_UNDER_INVESTIGATION], "under_investigation"
        )
        self.assertNotIn("affected", _STATUS_TO_VEX.values())


class TestUpdateinfoExclusion(unittest.TestCase):
    def test_updateinfo_router_has_no_cve_status_routes(self):
        paths = [getattr(route, "path", "") for route in updateinfo_router.routes]
        self.assertTrue(all("/cves" not in path for path in paths))


if __name__ == "__main__":
    unittest.main()
