"""
Tests for the v2 compatibility API serialization (advisory source attribution)
"""

import unittest
import datetime
from unittest.mock import Mock, patch

from apollo.server.routes.api_compat import v3_advisory_to_v2
from apollo.server import attribution
from apollo.db.serialize import Advisory_Pydantic, Advisory_Pydantic_WithSource
from apollo.db.advisory import fetch_advisories


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


class TestFetchAdvisoriesSql(unittest.IsolatedAsyncioTestCase):
    """List SQL must not join related tables (that path times out /v2/advisories)."""

    async def _sql(self, **overrides):
        kwargs = {
            "size": 10,
            "page_offset": 0,
            "keyword": None,
            "product": None,
            "before": None,
            "after": None,
            "cve": None,
            "synopsis": None,
            "severity": None,
            "kind": None,
        }
        kwargs.update(overrides)
        captured = {}

        async def execute_query(sql, params):
            captured["sql"] = sql
            captured["params"] = params
            return (0, [])

        connection = Mock()
        connection.execute_query = execute_query
        with patch("apollo.db.advisory.connections") as connections:
            connections.get.return_value = connection
            count, rows = await fetch_advisories(**kwargs)
        self.assertEqual(count, 0)
        self.assertEqual(rows, [])
        return captured["sql"]

    async def test_list_query_does_not_join_or_group_related_tables(self):
        sql = (await self._sql()).lower()
        self.assertNotIn("left outer join", sql)
        self.assertNotIn("group by", sql)
        self.assertIn("advisories a", sql)
        self.assertIn("count(a.*) over () as total", sql)

    async def test_keyword_filter_uses_exists_for_product_name(self):
        sql = (await self._sql(keyword="Rocky")).lower()
        self.assertIn("exists (select name from advisory_affected_products", sql)
        self.assertNotIn("ap.name", sql)
        self.assertNotIn("left outer join", sql)
        self.assertNotIn("group by", sql)

    async def test_product_filter_still_uses_exists(self):
        sql = (await self._sql(product="Rocky Linux 9")).lower()
        self.assertIn("exists (select name from advisory_affected_products", sql)


if __name__ == "__main__":
    unittest.main()
