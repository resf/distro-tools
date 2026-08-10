"""
Tests for the v3 advisories API source attribution helper and the
offset/limit pagination used by the advisory list endpoint.
"""

import datetime
import unittest
from unittest.mock import AsyncMock, Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi_pagination import add_pagination

from apollo.db.serialize import Advisory_Pydantic_WithSource
from apollo.server.routes import api_advisories
from apollo.server.routes.api_advisories import _advisory_source


def _mock_advisory(red_hat_advisory_name="RHSA-2026:18480"):
    advisory = Mock()
    if red_hat_advisory_name:
        red_hat_advisory = Mock()
        red_hat_advisory.name = red_hat_advisory_name
        advisory.red_hat_advisory = red_hat_advisory
        advisory.red_hat_advisory_id = 1
    else:
        advisory.red_hat_advisory = None
        advisory.red_hat_advisory_id = None
    return advisory


class TestAdvisorySource(unittest.TestCase):
    """Test the v3 JSON source object derivation"""

    def test_source_from_red_hat_advisory(self):
        source = _advisory_source(_mock_advisory("RHSA-2026:18480"))
        self.assertIsNotNone(source)
        self.assertEqual(source.name, "RHSA-2026:18480")
        self.assertEqual(
            source.url, "https://access.redhat.com/errata/RHSA-2026:18480"
        )
        self.assertEqual(source.vendor, "Red Hat")
        self.assertEqual(source.license, "CC-BY-4.0")
        self.assertEqual(
            source.licenseUrl, "https://creativecommons.org/licenses/by/4.0/"
        )

    def test_no_source_when_red_hat_advisory_absent(self):
        # red_hat_advisory_id is nullable in the DB, so this path is reachable.
        self.assertIsNone(_advisory_source(_mock_advisory(red_hat_advisory_name=None)))


TOTAL_ADVISORIES = 25
LAST_INDEXED_AT = datetime.datetime(
    2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc
)


class FakeQuerySet:
    """
    Stands in for a Tortoise queryset over a fixed list of rows.

    Mirrors the parts of the queryset API that the list endpoint uses:
    ``offset``/``limit`` return a new queryset (they do not mutate the
    receiver), awaiting the queryset yields the requested slice, and
    ``count`` reports the size of the unsliced result set.
    """

    def __init__(self, rows, offset=0, limit=None):
        self.rows = rows
        self._offset = offset
        self._limit = limit

    def prefetch_related(self, *_relations):
        return self

    def order_by(self, *_fields):
        return self

    def offset(self, offset):
        return FakeQuerySet(self.rows, offset, self._limit)

    def limit(self, limit):
        return FakeQuerySet(self.rows, self._offset, limit)

    async def count(self):
        return len(self.rows)

    def __await__(self):
        return self._fetch().__await__()

    async def _fetch(self):
        end = None if self._limit is None else self._offset + self._limit
        return self.rows[self._offset:end]


def _advisory_rows(count):
    rows = []
    for index in range(1, count + 1):
        row = Mock(id=index)
        row.name = f"RLSA-2026:{index:04d}"
        rows.append(row)
    return rows


async def _fake_advisory_with_source(advisory):
    return Advisory_Pydantic_WithSource(
        id=advisory.id,
        created_at=LAST_INDEXED_AT,
        published_at=LAST_INDEXED_AT,
        name=advisory.name,
        synopsis="synopsis",
        description="description",
        kind="Security Advisory",
        severity="Important",
        topic="topic",
    )


class TestListAdvisoriesPagination(unittest.TestCase):
    """Test the offset/limit pagination of the advisory list endpoint"""

    def setUp(self):
        self.rows = _advisory_rows(TOTAL_ADVISORIES)

        advisory_patch = patch.object(api_advisories, "Advisory")
        advisory_cls = advisory_patch.start()
        advisory_cls.all.return_value = FakeQuerySet(self.rows)
        self.addCleanup(advisory_patch.stop)

        state = Mock()
        state.last_indexed_at = LAST_INDEXED_AT
        state_patch = patch.object(api_advisories, "RedHatIndexState")
        state_patch.start().first = AsyncMock(return_value=state)
        self.addCleanup(state_patch.stop)

        serializer_patch = patch.object(
            api_advisories,
            "_advisory_with_source",
            side_effect=_fake_advisory_with_source,
        )
        serializer_patch.start()
        self.addCleanup(serializer_patch.stop)

        app = FastAPI()
        app.include_router(api_advisories.router)
        add_pagination(app)
        self.client = TestClient(app)

    def _get_page(self, **params):
        response = self.client.get("/", params=params)
        self.assertEqual(response.status_code, 200)
        return response.json()

    @staticmethod
    def _names(body):
        return [advisory["name"] for advisory in body["advisories"]]

    def test_default_params_return_first_page(self):
        body = self._get_page()

        self.assertEqual(body["page"], 1)
        self.assertEqual(body["size"], 50)
        self.assertEqual(body["total"], TOTAL_ADVISORIES)
        self.assertEqual(len(body["advisories"]), TOTAL_ADVISORIES)

    def test_first_page_starts_at_the_first_row(self):
        body = self._get_page(page=1, size=10)

        self.assertEqual(self._names(body), self._names_for(0, 10))
        self.assertEqual(body["page"], 1)
        self.assertEqual(body["size"], 10)

    def test_second_page_is_offset_by_one_page_size(self):
        body = self._get_page(page=2, size=10)

        self.assertEqual(self._names(body), self._names_for(10, 20))
        self.assertEqual(body["page"], 2)

    def test_final_page_is_partial(self):
        body = self._get_page(page=3, size=10)

        self.assertEqual(self._names(body), self._names_for(20, 25))
        self.assertEqual(len(body["advisories"]), 5)

    def test_page_past_the_end_is_empty(self):
        body = self._get_page(page=4, size=10)

        self.assertEqual(body["advisories"], [])
        self.assertEqual(body["total"], TOTAL_ADVISORIES)

    def test_total_counts_the_result_set_not_the_page(self):
        body = self._get_page(page=1, size=10)

        self.assertEqual(body["total"], TOTAL_ADVISORIES)
        self.assertEqual(len(body["advisories"]), 10)

    def test_paging_through_covers_every_advisory_exactly_once(self):
        size = 7
        seen = []
        for page in range(1, 5):
            seen.extend(self._names(self._get_page(page=page, size=size)))

        self.assertEqual(seen, [row.name for row in self.rows])
        self.assertEqual(len(set(seen)), TOTAL_ADVISORIES)

    def test_last_updated_at_reports_the_index_state(self):
        body = self._get_page(page=1, size=10)

        self.assertEqual(body["last_updated_at"], "2026-01-02T03:04:05Z")

    def _names_for(self, start, end):
        return [row.name for row in self.rows[start:end]]


if __name__ == "__main__":
    unittest.main()
