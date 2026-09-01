"""
Tests for the v3 advisories API source attribution helper, list pagination,
and filter query params (distro-tools#38).
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


def _advisory_rows(count):
    rows = []
    for index in range(1, count + 1):
        row = Mock(id=index)
        row.name = f"RLSA-2026:{index:04d}"
        # First 10 are Rocky Linux 8 + CVE-2023-44487; rest are RL9 + another CVE.
        if index <= 10:
            row.product = "Rocky Linux 8"
            row.cve = "CVE-2023-44487"
        else:
            row.product = "Rocky Linux 9"
            row.cve = "CVE-2025-21502"
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


class _ListAdvisoriesClient(unittest.TestCase):
    """Shared TestClient wired to list_advisories with fetch_advisories mocked."""

    def setUp(self):
        self.rows = _advisory_rows(TOTAL_ADVISORIES)
        self.fetch_calls = []

        async def fake_fetch(
            size,
            page_offset,
            keyword,
            product,
            before,
            after,
            cve,
            synopsis,
            severity,
            kind,
            fetch_related=False,
        ):
            matched = self.rows
            if product:
                matched = [row for row in matched if product in row.product]
            if cve:
                matched = [row for row in matched if cve in row.cve]
            if keyword:
                matched = [row for row in matched if keyword in row.cve]
            self.fetch_calls.append(
                {
                    "size": size,
                    "page_offset": page_offset,
                    "keyword": keyword,
                    "product": product,
                    "before": before,
                    "after": after,
                    "cve": cve,
                    "synopsis": synopsis,
                    "severity": severity,
                    "kind": kind,
                    "fetch_related": fetch_related,
                }
            )
            return (len(matched), matched[page_offset:page_offset + size])

        fetch_patch = patch.object(
            api_advisories, "fetch_advisories", side_effect=fake_fetch
        )
        fetch_patch.start()
        self.addCleanup(fetch_patch.stop)

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

    def _names_for(self, start, end):
        return [row.name for row in self.rows[start:end]]


class TestListAdvisoriesPagination(_ListAdvisoriesClient):
    """Test the offset/limit pagination of the advisory list endpoint"""

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

    def test_missing_index_state_omits_last_updated_at(self):
        api_advisories.RedHatIndexState.first = AsyncMock(return_value=None)
        body = self._get_page(page=1, size=10)
        self.assertIsNone(body.get("last_updated_at"))


class TestListAdvisoriesFilters(_ListAdvisoriesClient):
    """distro-tools#38: list_advisories must pass query filters into fetch_advisories."""

    def test_cve_and_product_from_issue_38_are_forwarded(self):
        # Reporter: /api/v3/advisories/?product=Rocky Linux 9&cve=CVE-2025-21502
        self._get_page(product="Rocky Linux 9", cve="CVE-2025-21502", size=10)

        self.assertEqual(len(self.fetch_calls), 1)
        call = self.fetch_calls[0]
        self.assertEqual(call["cve"], "CVE-2025-21502")
        self.assertEqual(call["product"], "Rocky Linux 9")
        self.assertTrue(call["fetch_related"])

    def test_keyword_filter_is_forwarded(self):
        self._get_page(keyword="CVE-2023-44487", size=10)

        self.assertEqual(self.fetch_calls[0]["keyword"], "CVE-2023-44487")

    def test_severity_and_kind_are_forwarded(self):
        self._get_page(severity="Important", kind="Security", size=10)

        call = self.fetch_calls[0]
        self.assertEqual(call["severity"], "Important")
        self.assertEqual(call["kind"], "Security")

    def test_synopsis_is_forwarded(self):
        self._get_page(synopsis="nodejs", size=10)

        self.assertEqual(self.fetch_calls[0]["synopsis"], "nodejs")

    def test_unfiltered_list_does_not_invent_filters(self):
        self._get_page(size=10)

        call = self.fetch_calls[0]
        self.assertIsNone(call["cve"])
        self.assertIsNone(call["keyword"])
        self.assertIsNone(call["product"])
        self.assertEqual(call["size"], 10)
        self.assertEqual(call["page_offset"], 0)

    def test_product_and_cve_are_anded_in_the_result_set(self):
        # Same CVE on RL8 vs RL9 must not return the other product (issue1.sh).
        body = self._get_page(
            product="Rocky Linux 8", cve="CVE-2023-44487", size=50
        )
        self.assertEqual(body["total"], 10)
        self.assertEqual(self._names(body), self._names_for(0, 10))

        body = self._get_page(
            product="Rocky Linux 9", cve="CVE-2023-44487", size=50
        )
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["advisories"], [])

    def test_cve_alone_is_a_subset_of_the_catalog(self):
        body = self._get_page(cve="CVE-2023-44487", size=50)
        self.assertEqual(body["total"], 10)
        self.assertEqual(len(body["advisories"]), 10)
        self.assertLess(body["total"], TOTAL_ADVISORIES)

    def test_invalid_before_raw_is_400(self):
        response = self.client.get("/", params={"before_raw": "not-a-date"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.fetch_calls, [])
        self.assertEqual(response.json()["detail"], "Invalid before date")

    def test_invalid_after_raw_is_400(self):
        response = self.client.get("/", params={"after_raw": "not-a-date"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.fetch_calls, [])
        self.assertEqual(response.json()["detail"], "Invalid after date")

    def test_empty_before_raw_is_400(self):
        response = self.client.get("/?before_raw=")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.fetch_calls, [])
        self.assertEqual(response.json()["detail"], "Invalid before date")

    def test_empty_after_raw_is_400(self):
        response = self.client.get("/?after_raw=")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.fetch_calls, [])
        self.assertEqual(response.json()["detail"], "Invalid after date")

    def test_valid_before_raw_is_parsed_and_forwarded(self):
        self._get_page(before_raw="2026-01-02T03:04:05Z", size=10)
        forwarded = self.fetch_calls[0]["before"]
        self.assertEqual(
            forwarded, datetime.datetime(2026, 1, 2, 3, 4, 5)
        )


if __name__ == "__main__":
    unittest.main()
