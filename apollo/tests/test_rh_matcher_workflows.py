"""
Tests for the rpmworker's resilience settings: activity heartbeats, bounded retries and
one activity at a time per worker.
"""

import asyncio
import datetime
import os
import sys
import unittest
from unittest.mock import AsyncMock, Mock, call, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.rpmworker import rh_matcher_activities
from apollo.rpmworker.rh_matcher_activities import (
    HEARTBEAT_EVERY_ADVISORIES,
    _heartbeat,
    block_remaining_rh_advisories,
    get_rh_mirror_major_versions,
    match_rh_repos,
    process_repomd,
)
from apollo.rpmworker.rh_matcher_workflows import (
    LONG_ACTIVITY_HEARTBEAT_TIMEOUT,
    LONG_ACTIVITY_RETRY_POLICY,
    RhDefunctWorkflow,
    RhDefunctWorkflowInput,
    RhMatcherWorkflow,
    RhMatcherWorkflowInput,
)
from apollo.rpmworker.temporal import TASK_QUEUE
from apollo.rpmworker.worker import build_worker


def _run(coro):
    return asyncio.run(coro)


def _mirror(name, active=True, major=9, arch="x86_64", repomds=None):
    mirror = Mock()
    mirror.id = hash(name) % 1000
    mirror.name = name
    mirror.active = active
    mirror.match_major_version = major
    mirror.match_arch = arch
    mirror.rpm_repomds = repomds if repomds is not None else []
    return mirror


def _repomd(repo_name="AppStream", arch="x86_64"):
    rpm_repomd = Mock()
    rpm_repomd.url = f"https://example.com/{repo_name}/{arch}/os/repodata/repomd.xml"
    rpm_repomd.debug_url = f"https://example.com/{repo_name}/{arch}/debug/repodata/repomd.xml"
    rpm_repomd.source_url = f"https://example.com/{repo_name}/source/repodata/repomd.xml"
    rpm_repomd.repo_name = repo_name
    rpm_repomd.arch = arch
    rpm_repomd.production = True
    return rpm_repomd


class TestWorkflowActivityOptions(unittest.TestCase):
    def test_long_activity_policy_values(self):
        self.assertEqual(LONG_ACTIVITY_HEARTBEAT_TIMEOUT, datetime.timedelta(minutes=10))
        self.assertEqual(LONG_ACTIVITY_RETRY_POLICY.maximum_attempts, 3)
        self.assertEqual(
            LONG_ACTIVITY_RETRY_POLICY.initial_interval, datetime.timedelta(minutes=1)
        )

    def test_matcher_runs_one_activity_per_requested_major(self):
        execute = AsyncMock(side_effect=[[7, 8], None, None, None, None])
        with patch("temporalio.workflow.execute_activity", execute):
            result = _run(RhMatcherWorkflow().run(RhMatcherWorkflowInput(major_versions=[9, 8])))

        self.assertEqual(result, [7, 8])
        lookup, *matches = execute.call_args_list
        self.assertEqual(lookup.args, ("get_supported_products_with_rh_mirrors", [9, 8]))
        self.assertNotIn("heartbeat_timeout", lookup.kwargs)
        self.assertEqual(
            [m.args for m in matches],
            [
                ("match_rh_repos", {"supported_product_id": 7, "filter_major_versions": [8]}),
                ("match_rh_repos", {"supported_product_id": 7, "filter_major_versions": [9]}),
                ("match_rh_repos", {"supported_product_id": 8, "filter_major_versions": [8]}),
                ("match_rh_repos", {"supported_product_id": 8, "filter_major_versions": [9]}),
            ],
        )
        for match in matches:
            self.assertEqual(match.kwargs["heartbeat_timeout"], LONG_ACTIVITY_HEARTBEAT_TIMEOUT)
            self.assertIs(match.kwargs["retry_policy"], LONG_ACTIVITY_RETRY_POLICY)
            self.assertEqual(
                match.kwargs["start_to_close_timeout"], datetime.timedelta(hours=12)
            )

    def test_matcher_without_input_splits_each_product_by_its_mirror_majors(self):
        execute = AsyncMock(side_effect=[[1, 2], [10, 8], None, None, [9], None])
        with patch("temporalio.workflow.execute_activity", execute):
            result = _run(RhMatcherWorkflow().run())

        self.assertEqual(result, [1, 2])
        self.assertEqual(
            [c.args for c in execute.call_args_list],
            [
                ("get_supported_products_with_rh_mirrors", None),
                ("get_rh_mirror_major_versions", 1),
                ("match_rh_repos", {"supported_product_id": 1, "filter_major_versions": [8]}),
                ("match_rh_repos", {"supported_product_id": 1, "filter_major_versions": [10]}),
                ("get_rh_mirror_major_versions", 2),
                ("match_rh_repos", {"supported_product_id": 2, "filter_major_versions": [9]}),
            ],
        )
        self.assertNotIn("heartbeat_timeout", execute.call_args_list[1].kwargs)

    def test_matcher_product_without_mirror_majors_matches_nothing(self):
        execute = AsyncMock(side_effect=[[1], []])
        with patch("temporalio.workflow.execute_activity", execute):
            _run(RhMatcherWorkflow().run())

        self.assertEqual(
            [c.args[0] for c in execute.call_args_list],
            ["get_supported_products_with_rh_mirrors", "get_rh_mirror_major_versions"],
        )

    def test_defunct_heartbeats_and_bounds_retries(self):
        execute = AsyncMock(return_value=None)
        with patch("temporalio.workflow.execute_activity", execute):
            _run(RhDefunctWorkflow().run(RhDefunctWorkflowInput(supported_product_id=3)))

        execute.assert_awaited_once()
        self.assertEqual(execute.call_args.args, ("block_remaining_rh_advisories", 3))
        self.assertEqual(
            execute.call_args.kwargs["heartbeat_timeout"], LONG_ACTIVITY_HEARTBEAT_TIMEOUT
        )
        self.assertIs(execute.call_args.kwargs["retry_policy"], LONG_ACTIVITY_RETRY_POLICY)


class TestHeartbeatHelper(unittest.TestCase):
    def test_no_heartbeat_outside_an_activity(self):
        with patch.object(rh_matcher_activities.activity, "in_activity", return_value=False), \
             patch.object(rh_matcher_activities.activity, "heartbeat") as heartbeat:
            _run(_heartbeat("mirror", "Rocky Linux 9 x86_64"))
        heartbeat.assert_not_called()

    def test_heartbeat_inside_an_activity(self):
        with patch.object(rh_matcher_activities.activity, "in_activity", return_value=True), \
             patch.object(rh_matcher_activities.activity, "heartbeat") as heartbeat:
            _run(_heartbeat("mirror", "Rocky Linux 9 x86_64"))
        heartbeat.assert_called_once_with("mirror", "Rocky Linux 9 x86_64")


class TestActivityHeartbeats(unittest.TestCase):
    def setUp(self):
        patcher = patch("apollo.rpmworker.rh_matcher_activities.Logger")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.heartbeat = AsyncMock()
        patcher = patch("apollo.rpmworker.rh_matcher_activities._heartbeat", self.heartbeat)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _kinds(self):
        return [c.args[0] for c in self.heartbeat.call_args_list]

    def test_process_repomd_heartbeats_per_fetch_and_advisory_batch(self):
        advisories = []
        for i in range(2 * HEARTBEAT_EVERY_ADVISORIES + 1):
            advisory = Mock()
            advisory.name = f"RHSA-2026:{i:04d}"
            advisory.packages = []
            advisories.append(advisory)

        async def fake_get_data(url, data_type, el, is_yaml=False):
            return Mock(findall=Mock(return_value=[])) if data_type == "primary" else None

        rpm_repomd = _repomd()
        with patch.object(rh_matcher_activities.repomd, "download_xml", AsyncMock()), \
             patch.object(rh_matcher_activities.repomd, "get_data_from_repomd",
                          side_effect=fake_get_data):
            _run(process_repomd(_mirror("Rocky Linux 9 x86_64"), rpm_repomd, advisories))

        self.assertEqual(
            self.heartbeat.call_args_list,
            [
                call("fetch", rpm_repomd.url),
                call("fetch", rpm_repomd.debug_url),
                call("fetch", rpm_repomd.source_url),
                call("match", "AppStream", 0),
                call("match", "AppStream", HEARTBEAT_EVERY_ADVISORIES),
                call("match", "AppStream", 2 * HEARTBEAT_EVERY_ADVISORIES),
            ],
        )

    def test_match_rh_repos_heartbeats_per_processed_mirror_and_clone(self):
        rhsa = Mock()
        rhsa.name = "RHSA-2026:0001"
        product = Mock()
        product.rh_mirrors = [
            _mirror("Rocky Linux 9 x86_64", repomds=[_repomd()]),
            _mirror("Rocky Linux 9 aarch64 (inactive)", active=False, repomds=[_repomd()]),
            _mirror("Rocky Linux 8 x86_64", major=8, repomds=[_repomd()]),
        ]
        query = Mock()
        query.first.return_value.prefetch_related = AsyncMock(return_value=product)
        advisory_map = {
            "RHSA-2026:0001": {"advisory": rhsa, "packages": [set()], "module_packages": {}},
        }

        with patch.object(rh_matcher_activities.SupportedProduct, "filter",
                          return_value=query), \
             patch.object(rh_matcher_activities, "get_matching_rh_advisories",
                          AsyncMock(return_value=[rhsa])), \
             patch.object(rh_matcher_activities, "process_repomd",
                          AsyncMock(return_value=advisory_map)), \
             patch.object(rh_matcher_activities, "clone_advisory", AsyncMock()) as clone:
            _run(match_rh_repos({"supported_product_id": 1, "filter_major_versions": [9]}))

        self.assertEqual(
            self.heartbeat.call_args_list,
            [call("mirror", "Rocky Linux 9 x86_64"), call("clone", "RHSA-2026:0001")],
        )
        clone.assert_awaited_once()

    def test_block_remaining_heartbeats_per_mirror(self):
        mirrors = [_mirror("Rocky Linux 9 x86_64"), _mirror("Rocky Linux 9 aarch64")]
        with patch.object(rh_matcher_activities.SupportedProductsRhMirror, "filter",
                          AsyncMock(return_value=mirrors)), \
             patch.object(rh_matcher_activities, "get_matching_rh_advisories",
                          AsyncMock(return_value=[])), \
             patch.object(rh_matcher_activities.SupportedProductsRhBlock, "bulk_create",
                          AsyncMock()):
            _run(block_remaining_rh_advisories(1))

        self.assertEqual(
            self.heartbeat.call_args_list,
            [call("block", "Rocky Linux 9 x86_64"), call("block", "Rocky Linux 9 aarch64")],
        )


class TestBuildWorker(unittest.TestCase):
    def test_runs_one_activity_at_a_time(self):
        client = Mock()
        with patch("apollo.rpmworker.worker.Worker") as worker_cls:
            worker = build_worker(client)

        self.assertIs(worker, worker_cls.return_value)
        args, kwargs = worker_cls.call_args
        self.assertEqual(args, (client,))
        self.assertEqual(kwargs["task_queue"], TASK_QUEUE)
        self.assertEqual(kwargs["max_concurrent_activities"], 1)
        self.assertEqual(kwargs["workflows"], [RhMatcherWorkflow, RhDefunctWorkflow])
        self.assertEqual(
            [a.__name__ for a in kwargs["activities"]],
            ["get_supported_products_with_rh_mirrors", "get_rh_mirror_major_versions",
             "match_rh_repos", "block_remaining_rh_advisories"],
        )


class TestGetRhMirrorMajorVersions(unittest.TestCase):
    def test_distinct_sorted_majors_of_active_mirrors_with_repomds(self):
        mirrors = [
            _mirror("Rocky Linux 10 x86_64", major=10, repomds=[_repomd()]),
            _mirror("Rocky Linux 8 x86_64", major=8, repomds=[_repomd()]),
            _mirror("Rocky Linux 10 aarch64", major=10, repomds=[_repomd(arch="aarch64")]),
            _mirror("Rocky Linux 9 x86_64 (no repos)", major=9, repomds=[]),
        ]
        query = Mock()
        query.prefetch_related = AsyncMock(return_value=mirrors)
        with patch.object(rh_matcher_activities.SupportedProductsRhMirror, "filter",
                          return_value=query) as mirror_filter:
            majors = _run(get_rh_mirror_major_versions(4))

        self.assertEqual(majors, [8, 10])
        mirror_filter.assert_called_once_with(supported_product_id=4, active=True)
        query.prefetch_related.assert_awaited_once_with("rpm_repomds")


if __name__ == "__main__":
    unittest.main()
