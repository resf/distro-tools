"""Tests for fetch_advisories date binds, CVE requirement, and stable sort."""

import asyncio
import datetime
import unittest
from unittest.mock import Mock, patch

from apollo.db.advisory import naive_utc, fetch_advisories


class TestNaiveUtc(unittest.TestCase):
    def test_none_passthrough(self):
        self.assertIsNone(naive_utc(None))

    def test_naive_unchanged(self):
        dt = datetime.datetime(2026, 7, 19, 0, 0, 0)
        self.assertEqual(naive_utc(dt), dt)
        self.assertIsNone(naive_utc(dt).tzinfo)

    def test_aware_converted_to_naive_utc(self):
        dt = datetime.datetime(
            2026, 7, 19, 0, 0, 0, tzinfo=datetime.timezone.utc
        )
        converted = naive_utc(dt)
        self.assertEqual(converted, datetime.datetime(2026, 7, 19, 0, 0, 0))
        self.assertIsNone(converted.tzinfo)


class TestFetchAdvisoriesDateBinds(unittest.TestCase):
    def test_after_aware_datetime_is_bound_naive(self):
        captured = {}

        async def fake_execute_query(sql, args):
            captured["sql"] = sql
            captured["args"] = args
            return (0, [])

        async def run():
            conn = Mock()
            conn.execute_query = fake_execute_query
            fake_connections = Mock()
            fake_connections.get.return_value = conn
            with patch("apollo.db.advisory.connections", fake_connections):
                await fetch_advisories(
                    2,
                    0,
                    None,
                    None,
                    None,
                    datetime.datetime(
                        2026, 7, 19, 0, 0, 0, tzinfo=datetime.timezone.utc
                    ),
                    None,
                    None,
                    None,
                    None,
                    require_cves=True,
                )

        asyncio.run(run())
        bound_after = captured["args"][5]
        self.assertIsNone(bound_after.tzinfo)
        self.assertIn("timestamptz", captured["sql"])
        self.assertIn("exists (select 1 from advisory_cves", captured["sql"])
        self.assertIn("a.id desc", captured["sql"])


if __name__ == "__main__":
    unittest.main()
