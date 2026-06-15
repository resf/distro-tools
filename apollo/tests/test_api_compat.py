"""
Tests for the v2 compatibility API serialization (advisory source attribution)
"""

import unittest
import datetime
from unittest.mock import Mock

from apollo.server.routes.api_compat import v3_advisory_to_v2
from apollo.server import attribution
from apollo.db.serialize import Advisory_Pydantic, Advisory_Pydantic_WithSource


def create_mock_advisory(red_hat_advisory_name="RHSA-2024:1234"):
    """Create a mock advisory sufficient for v3_advisory_to_v2 serialization"""
    advisory = Mock()
    advisory.id = 1
    advisory.name = "RLSA-2024:1234"
    advisory.synopsis = "Important: kernel security update"
    advisory.description = "An update for kernel is now available."
    advisory.kind = "Security"
    advisory.severity = "Important"
    advisory.topic = "An update is available"
    advisory.published_at = datetime.datetime(2024, 1, 15, 10, 0, 0)
    advisory.affected_products = []
    advisory.cves = []
    advisory.fixes = []
    advisory.packages = []
    if red_hat_advisory_name:
        red_hat_advisory = Mock()
        red_hat_advisory.name = red_hat_advisory_name
        advisory.red_hat_advisory = red_hat_advisory
        advisory.red_hat_advisory_id = 1
    else:
        advisory.red_hat_advisory = None
        advisory.red_hat_advisory_id = None
    return advisory


class TestV2AdvisorySource(unittest.TestCase):
    """Test that the v2 advisory payload carries Red Hat source attribution"""

    def test_source_populated_from_red_hat_advisory(self):
        """source carries the RHSA name/url, vendor, and CC BY 4.0 license"""
        result = v3_advisory_to_v2(
            create_mock_advisory(), include_rpms=False, fetch_related=True
        )
        self.assertIsNotNone(result.source)
        self.assertEqual(result.source.name, "RHSA-2024:1234")
        self.assertEqual(
            result.source.url, "https://access.redhat.com/errata/RHSA-2024:1234"
        )
        self.assertEqual(result.source.vendor, "Red Hat")
        self.assertEqual(result.source.license, "CC-BY-4.0")
        self.assertEqual(
            result.source.licenseUrl,
            "https://creativecommons.org/licenses/by/4.0/",
        )

    def test_source_absent_without_related_fetch(self):
        """The lightweight list path (fetchRelated=false) omits source"""
        result = v3_advisory_to_v2(
            create_mock_advisory(), include_rpms=False, fetch_related=False
        )
        self.assertIsNone(result.source)

    def test_source_absent_without_red_hat_advisory(self):
        """Advisories with no Red Hat source have no source block"""
        result = v3_advisory_to_v2(
            create_mock_advisory(red_hat_advisory_name=None),
            include_rpms=False,
            fetch_related=True,
        )
        self.assertIsNone(result.source)


class TestSourceFieldsAndModels(unittest.TestCase):
    """Test the shared source helper and the v3 JSON source-bearing model"""

    def test_source_fields(self):
        self.assertEqual(
            attribution.source_fields("RHSA-2026:1234"),
            {
                "name": "RHSA-2026:1234",
                "url": "https://access.redhat.com/errata/RHSA-2026:1234",
                "vendor": "Red Hat",
                "license": "CC-BY-4.0",
                "licenseUrl": "https://creativecommons.org/licenses/by/4.0/",
            },
        )

    def test_base_model_excludes_red_hat_advisory(self):
        self.assertNotIn("red_hat_advisory", Advisory_Pydantic.__fields__)

    def test_with_source_model_adds_source(self):
        self.assertIn("source", Advisory_Pydantic_WithSource.__fields__)


if __name__ == "__main__":
    unittest.main()
