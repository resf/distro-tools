"""
Tests for the minor version rollover service.

Mirror and repomd fixtures are trimmed from a production configuration export so the
rewrite rules are exercised against real URL layouts.
"""

import asyncio
import os
from decimal import Decimal
import sys
import unittest
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from aiohttp import web

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.services import minor_version_rollover as rollover
from apollo.server.services.minor_version_rollover import (
    RolloverConflict,
    RolloverError,
    UrlCheckFailed,
    build_plan,
    rewrite_minor_segment,
    validate_versions,
)
from apollo.server.utils import templates

ROCKY = 1
SIG_CLOUD = 2
STG = "https://dl.rockylinux.org/stg/rocky"
PUB = "https://dl.rockylinux.org/pub/rocky"
YUMREPOFS = "https://yumrepofs.build.resf.org/v1/projects/15016370-1410-4459-a1a2-a1576041fd19/repo"


def _mirror(mirror_id, name, major, minor, product_id=ROCKY, active=True):
    # Version columns are numeric in Postgres, so real rows carry Decimal values.
    return SimpleNamespace(
        id=mirror_id,
        name=name,
        supported_product_id=product_id,
        match_major_version=Decimal(major),
        match_minor_version=None if minor is None else Decimal(minor),
        active=active,
        save=AsyncMock(),
    )


def _repomd(repomd_id, mirror_id, base, repo, arch, debug=True, source=True):
    return SimpleNamespace(
        id=repomd_id,
        supported_products_rh_mirror_id=mirror_id,
        repo_name=repo,
        arch=arch,
        url=f"{base}/{repo}/{arch}/os/repodata/repomd.xml",
        debug_url=f"{base}/{repo}/{arch}/debug/tree/repodata/repomd.xml" if debug else "",
        source_url=f"{base}/{repo}/source/tree/repodata/repomd.xml" if source else "",
        save=AsyncMock(),
    )


def prod_fixture():
    mirrors = [
        _mirror(2, "Rocky Linux 8 x86_64", 8, None),
        _mirror(4, "Rocky Linux 9 x86_64", 9, None),
        _mirror(31, "Rocky Linux 9.6 aarch64", 9, None, active=False),
        _mirror(26, "Rocky Linux 10.0 aarch64", 10, 0, active=False),
        _mirror(35, "Rocky Linux 10 aarch64", 10, 2),
        # RHEL has no riscv64, so this mirror matches x86_64 advisories but serves riscv64 trees.
        _mirror(37, "Rocky Linux 10 riscv64", 10, 2),
        _mirror(20, "Rocky Linux 9 SIG Cloud x86_64", 9, None, product_id=SIG_CLOUD),
    ]
    repomds = [
        _repomd(1, 2, f"{STG}/8", "BaseOS", "x86_64"),
        _repomd(10, 4, f"{STG}/9.8", "BaseOS", "x86_64"),
        _repomd(11, 4, f"{STG}/9.8", "AppStream", "x86_64"),
        _repomd(150, 31, f"{PUB}/9.6", "BaseOS", "aarch64"),
        _repomd(120, 26, f"{PUB}/10.0", "BaseOS", "aarch64"),
        _repomd(200, 35, f"{STG}/10.2", "AppStream", "aarch64"),
        _repomd(201, 35, f"{STG}/10.2", "BaseOS", "aarch64"),
        _repomd(210, 37, f"{STG}/10.2", "BaseOS", "riscv64"),
        _repomd(80, 20, YUMREPOFS, "cloud-kernel", "x86_64", debug=False),
    ]
    return mirrors, repomds


def run(coro):
    return asyncio.run(coro)


class TestRewriteMinorSegment(unittest.TestCase):

    def test_rewrites_segment(self):
        self.assertEqual(
            rewrite_minor_segment(f"{STG}/10.2/AppStream/aarch64/os/repodata/repomd.xml", 10, 2, 3),
            f"{STG}/10.3/AppStream/aarch64/os/repodata/repomd.xml",
        )

    def test_rewrites_two_digit_minor(self):
        self.assertEqual(rewrite_minor_segment(f"{STG}/8.9/BaseOS/x", 8, 9, 10), f"{STG}/8.10/BaseOS/x")

    def test_absent_segment_returns_none(self):
        self.assertIsNone(rewrite_minor_segment(f"{STG}/8/BaseOS/x86_64/os/repodata/repomd.xml", 8, 9, 10))
        self.assertIsNone(rewrite_minor_segment(f"{YUMREPOFS}/cloud-kernel/x86_64/repodata/repomd.xml", 9, 8, 9))

    def test_sibling_trees_do_not_match(self):
        for url in (
            f"{STG}/10.2-RC2/BaseOS/x86_64/os/repodata/repomd.xml",
            f"{STG}/10.20/BaseOS/x86_64/os/repodata/repomd.xml",
            f"{STG}/110.2/BaseOS/x86_64/os/repodata/repomd.xml",
            f"{STG}/9.10.2/BaseOS/x86_64/os/repodata/repomd.xml",
        ):
            with self.subTest(url=url):
                self.assertIsNone(rewrite_minor_segment(url, 10, 2, 3))

    def test_ambiguous_url_raises(self):
        with self.assertRaises(RolloverError) as ctx:
            rewrite_minor_segment(f"{STG}/10.2/mirror/10.2/BaseOS", 10, 2, 3)
        self.assertIn("more than once", str(ctx.exception))


class TestValidateVersions(unittest.TestCase):

    def test_valid(self):
        validate_versions(10, 2, 3)
        validate_versions(10, 3, 2)
        validate_versions(9, 0, 1)

    def test_invalid(self):
        for args in ((10, 2, 2), (10, -1, 3), (10, 2, -3), (0, 2, 3)):
            with self.subTest(args=args):
                with self.assertRaises(RolloverError):
                    validate_versions(*args)


class TestBuildPlan(unittest.TestCase):

    def test_major_10_moves_minor_and_urls_of_active_mirrors_only(self):
        mirrors, repomds = prod_fixture()
        plan = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)

        self.assertEqual([m.mirror_id for m in plan.mirrors], [35, 37])
        self.assertEqual([(m.minor_before, m.minor_after) for m in plan.mirrors], [(2, 3), (2, 3)])
        self.assertIs(type(plan.mirrors[0].minor_before), int)
        self.assertEqual(len(plan.plan_hash), 64)
        self.assertEqual(plan.minor_change_count, 2)
        self.assertEqual(plan.url_change_count, 9)
        self.assertEqual(plan.skipped, [])
        self.assertFalse(plan.is_empty)

        aarch64 = plan.mirrors[0]
        self.assertEqual(
            [(c.repomd_id, c.field) for c in aarch64.url_changes],
            [(200, "url"), (200, "debug_url"), (200, "source_url"),
             (201, "url"), (201, "debug_url"), (201, "source_url")],
        )
        first = aarch64.url_changes[0]
        self.assertEqual(first.before, f"{STG}/10.2/AppStream/aarch64/os/repodata/repomd.xml")
        self.assertEqual(first.after, f"{STG}/10.3/AppStream/aarch64/os/repodata/repomd.xml")
        self.assertEqual(plan.mirrors[1].url_changes[0].after, f"{STG}/10.3/BaseOS/riscv64/os/repodata/repomd.xml")

    def test_build_plan_does_not_mutate_inputs(self):
        mirrors, repomds = prod_fixture()
        build_plan(ROCKY, 10, 2, 3, mirrors, repomds)
        self.assertEqual(next(m for m in mirrors if m.id == 35).match_minor_version, 2)
        self.assertIn("/10.2/", next(r for r in repomds if r.id == 200).url)

    def test_major_9_rewrites_urls_without_touching_unpinned_minor(self):
        mirrors, repomds = prod_fixture()
        plan = build_plan(ROCKY, 9, 8, 9, mirrors, repomds)

        self.assertEqual([m.mirror_id for m in plan.mirrors], [4])
        mirror = plan.mirrors[0]
        self.assertIsNone(mirror.minor_before)
        self.assertIsNone(mirror.minor_after)
        self.assertFalse(mirror.changes_minor)
        self.assertEqual(plan.minor_change_count, 0)
        self.assertEqual(plan.url_change_count, 6)
        self.assertTrue(all("/9.9/" in c.after for c in mirror.url_changes))

    def test_major_8_has_nothing_to_change(self):
        mirrors, repomds = prod_fixture()
        plan = build_plan(ROCKY, 8, 9, 10, mirrors, repomds)

        self.assertTrue(plan.is_empty)
        self.assertEqual(len(plan.mirrors[0].unchanged_urls), 3)

    def test_other_products_are_out_of_scope(self):
        mirrors, repomds = prod_fixture()
        plan = build_plan(SIG_CLOUD, 9, 8, 9, mirrors, repomds)

        self.assertEqual([m.mirror_id for m in plan.mirrors], [20])
        self.assertTrue(plan.is_empty)
        # Empty debug_url is ignored rather than reported as unchanged.
        self.assertEqual([u.field for u in plan.mirrors[0].unchanged_urls], ["url", "source_url"])

    def test_mirror_pinned_to_other_minor_is_skipped(self):
        mirrors, repomds = prod_fixture()
        mirrors.append(_mirror(99, "Rocky Linux 10 x86_64", 10, 1))
        repomds.append(_repomd(990, 99, f"{STG}/10.1", "BaseOS", "x86_64"))
        plan = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)

        self.assertEqual([(s.mirror_id, s.minor, s.reason) for s in plan.skipped], [(99, 1, "pinned to minor 1")])
        self.assertNotIn(99, [m.mirror_id for m in plan.mirrors])

    def test_no_active_mirrors_raises(self):
        mirrors, repomds = prod_fixture()
        with self.assertRaises(RolloverError):
            build_plan(ROCKY, 7, 9, 10, mirrors, repomds)

    def test_ambiguous_url_fails_whole_plan(self):
        mirrors, repomds = prod_fixture()
        next(r for r in repomds if r.id == 200).url = f"{STG}/10.2/x/10.2/repomd.xml"
        with self.assertRaises(RolloverError):
            build_plan(ROCKY, 10, 2, 3, mirrors, repomds)

    def test_url_for_another_minor_is_flagged_but_unchanged(self):
        mirrors, repomds = prod_fixture()
        repomds.append(_repomd(202, 35, f"{STG}/10.1", "NFV", "aarch64", debug=False, source=False))
        plan = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)

        self.assertEqual(plan.url_change_count, 9)
        self.assertEqual(
            [(u.repomd_id, u.field, u.other_minor_segment) for u in plan.mismatched_urls],
            [(202, "url", "/10.1/")],
        )
        # Minor-free trees (Rocky 8, yumrepofs) are unchanged without being flagged.
        self.assertEqual(build_plan(ROCKY, 8, 9, 10, mirrors, repomds).mismatched_urls, [])

    def test_rerun_after_apply_is_empty_and_reverse_restores(self):
        mirrors, repomds = prod_fixture()
        original_urls = {r.id: r.url for r in repomds}
        plan = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)
        run(rollover._write_plan(plan, mirrors, repomds, connection=None))

        rerun = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)
        self.assertEqual([s.mirror_id for s in rerun.skipped], [35, 37])
        self.assertTrue(rerun.is_empty)

        reverse = build_plan(ROCKY, 10, 3, 2, mirrors, repomds)
        run(rollover._write_plan(reverse, mirrors, repomds, connection=None))
        self.assertEqual({r.id: r.url for r in repomds}, original_urls)
        self.assertEqual(next(m for m in mirrors if m.id == 35).match_minor_version, 2)


class TestPlanHash(unittest.TestCase):

    def test_hash_is_independent_of_input_order(self):
        mirrors, repomds = prod_fixture()
        forward = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)
        backward = build_plan(ROCKY, 10, 2, 3, list(reversed(mirrors)), list(reversed(repomds)))
        self.assertEqual(forward.plan_hash, backward.plan_hash)

    def test_hash_changes_when_writes_change(self):
        mirrors, repomds = prod_fixture()
        before = build_plan(ROCKY, 10, 2, 3, mirrors, repomds).plan_hash
        next(r for r in repomds if r.id == 201).source_url = f"{STG}/10.2/BaseOS/other/repomd.xml"
        self.assertNotEqual(before, build_plan(ROCKY, 10, 2, 3, mirrors, repomds).plan_hash)

    def test_hash_changes_with_target_minor(self):
        mirrors, repomds = prod_fixture()
        self.assertNotEqual(
            build_plan(ROCKY, 10, 2, 3, mirrors, repomds).plan_hash,
            build_plan(ROCKY, 10, 2, 4, mirrors, repomds).plan_hash,
        )


class TestCheckUrls(unittest.TestCase):

    async def _check_against_local_server(self, paths):
        async def ok(_):
            return web.Response(text="ok")

        async def slow(_):
            await asyncio.sleep(2)
            return web.Response(text="late")

        async def redirect(_):
            raise web.HTTPFound("/ok")

        app = web.Application()
        app.router.add_route("*", "/ok", ok)
        app.router.add_route("*", "/slow", slow)
        app.router.add_route("*", "/redirect", redirect)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]
        try:
            urls = [f"http://127.0.0.1:{port}{p}" for p in paths]
            return urls, await rollover.check_urls(urls)
        finally:
            await runner.cleanup()

    def test_statuses(self):
        with patch.object(rollover, "URL_CHECK_TIMEOUT_SECONDS", 0.5):
            urls, checks = run(self._check_against_local_server(["/ok", "/missing", "/slow"]))

        self.assertEqual(checks[urls[0]].status, rollover.URL_CHECK_OK)
        self.assertTrue(checks[urls[0]].ok)
        self.assertEqual(checks[urls[1]].status, rollover.URL_CHECK_FAILED)
        self.assertEqual(checks[urls[1]].detail, "HTTP 404")
        self.assertEqual(checks[urls[2]].status, rollover.URL_CHECK_UNVERIFIED)
        self.assertFalse(checks[urls[2]].ok)

    def test_redirects_are_reported_not_followed(self):
        urls, checks = run(self._check_against_local_server(["/redirect"]))
        check = checks[urls[0]]
        self.assertEqual(check.status, rollover.URL_CHECK_FAILED)
        self.assertEqual(check.detail, "HTTP 302 redirect to /ok")

    def test_batch_budget_marks_pending_urls_unverified(self):
        with patch.object(rollover, "URL_CHECK_BUDGET_SECONDS", 0.5):
            urls, checks = run(self._check_against_local_server(["/ok", "/slow"]))
        self.assertTrue(checks[urls[0]].ok)
        self.assertEqual(checks[urls[1]].status, rollover.URL_CHECK_UNVERIFIED)
        self.assertEqual(checks[urls[1]].detail, "Not checked within 0.5s")

    def test_duplicates_are_checked_once_and_empty_input_is_empty(self):
        urls, checks = run(self._check_against_local_server(["/ok", "/ok"]))
        self.assertEqual(list(checks), urls[:1])
        self.assertEqual(run(rollover.check_urls([])), {})

    def test_connection_error_is_unverified(self):
        checks = run(rollover.check_urls(["http://127.0.0.1:1/repomd.xml"]))
        check = checks["http://127.0.0.1:1/repomd.xml"]
        self.assertEqual(check.status, rollover.URL_CHECK_UNVERIFIED)
        self.assertTrue(check.detail.startswith("Client"))


def _ok_checks(urls):
    return {u: rollover.UrlCheck(u, rollover.URL_CHECK_OK, "HTTP 200") for u in urls}


class TestApplyRollover(unittest.TestCase):

    def setUp(self):
        self.mirrors, self.repomds = prod_fixture()
        self.connection = object()
        self.transaction_exits = []

        @asynccontextmanager
        async def fake_transaction():
            try:
                yield self.connection
            except BaseException as e:
                self.transaction_exits.append(e)
                raise
            self.transaction_exits.append(None)

        self.load_scope = AsyncMock(return_value=(self.mirrors, self.repomds))
        self.check_urls = AsyncMock(side_effect=_ok_checks)
        patches = [
            patch.object(rollover, "_load_scope", self.load_scope),
            patch.object(rollover, "check_urls", self.check_urls),
            patch.object(rollover, "in_transaction", fake_transaction),
            patch.object(rollover, "Logger"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _hash(self, from_minor=2, to_minor=3):
        return build_plan(ROCKY, 10, from_minor, to_minor, self.mirrors, self.repomds).plan_hash

    def _apply(self, expected_hash, **kwargs):
        return run(rollover.apply_rollover(
            ROCKY, 10, 2, 3, expected_hash=expected_hash, actor="admin@example.com", **kwargs
        ))

    def _saved(self):
        return [o.id for o in self.mirrors + self.repomds if o.save.await_count]

    def test_applies_previewed_plan_in_transaction(self):
        plan = self._apply(self._hash())

        self.assertEqual((plan.minor_change_count, plan.url_change_count), (2, 9))
        self.assertEqual(sorted(self._saved()), [35, 37, 200, 201, 210])
        self.assertEqual(self.transaction_exits, [None])
        for mirror in self.mirrors:
            if mirror.id in (35, 37):
                self.assertEqual(mirror.match_minor_version, 3)
                mirror.save.assert_awaited_once_with(
                    using_db=self.connection, update_fields=["match_minor_version", "updated_at"]
                )
        next(r for r in self.repomds if r.id == 210).save.assert_awaited_once_with(
            using_db=self.connection, update_fields=["url", "debug_url", "source_url", "updated_at"]
        )
        self.assertEqual(next(m for m in self.mirrors if m.id == 35).name, "Rocky Linux 10 aarch64")
        self.assertEqual(
            next(r for r in self.repomds if r.id == 210).source_url,
            f"{STG}/10.3/BaseOS/source/tree/repodata/repomd.xml",
        )
        # Inactive 10.0 mirror and its repos are untouched.
        self.assertEqual(next(m for m in self.mirrors if m.id == 26).match_minor_version, 0)
        self.assertIn("/10.0/", next(r for r in self.repomds if r.id == 120).url)
        # Second load happens inside the transaction with row locks.
        self.assertEqual(self.load_scope.await_args_list[-1].args, (ROCKY, 10, self.connection))

    def test_stale_preview_hash_is_rejected_before_any_write(self):
        with self.assertRaises(RolloverConflict):
            self._apply("not-the-previewed-hash")
        self.assertEqual(self._saved(), [])
        self.check_urls.assert_not_awaited()

    def test_change_between_preview_and_lock_is_rejected(self):
        expected = self._hash()
        changed_mirrors, changed_repomds = prod_fixture()
        next(r for r in changed_repomds if r.id == 200).url = f"{STG}/10.2/AppStream/aarch64/new/repomd.xml"
        self.load_scope.side_effect = [(self.mirrors, self.repomds), (changed_mirrors, changed_repomds)]

        with self.assertRaises(RolloverConflict):
            self._apply(expected)
        self.assertEqual(self._saved(), [])
        self.assertEqual([o.id for o in changed_mirrors + changed_repomds if o.save.await_count], [])
        self.assertIsInstance(self.transaction_exits[0], RolloverConflict)

    def test_failed_url_check_blocks_apply(self):
        def one_failure(urls):
            checks = _ok_checks(urls)
            checks[urls[0]] = rollover.UrlCheck(urls[0], rollover.URL_CHECK_FAILED, "HTTP 404")
            return checks
        self.check_urls.side_effect = one_failure

        with self.assertRaises(UrlCheckFailed) as ctx:
            self._apply(self._hash())
        self.assertEqual(ctx.exception.plan.url_change_count, 9)
        # Source trees are shared across arches, so riscv64 and aarch64 BaseOS check one URL.
        self.assertEqual(len(ctx.exception.checks), 8)
        self.assertIn("1 rewritten URL", str(ctx.exception))
        self.assertEqual(self._saved(), [])
        self.assertEqual(self.transaction_exits, [])

    def test_failed_url_check_can_be_explicitly_allowed(self):
        self.check_urls.side_effect = lambda urls: {
            u: rollover.UrlCheck(u, rollover.URL_CHECK_UNVERIFIED, "TimeoutError") for u in urls
        }
        plan = self._apply(self._hash(), allow_failed_url_checks=True)
        self.assertEqual(plan.url_change_count, 9)
        self.assertEqual(len(self._saved()), 5)

    def test_empty_plan_is_rejected(self):
        for mirror in self.mirrors:
            if mirror.id in (35, 37):
                mirror.match_minor_version = 3
        with self.assertRaises(RolloverError) as ctx:
            self._apply(self._hash())
        self.assertIn("Nothing to apply", str(ctx.exception))

    def test_write_failure_propagates_through_transaction(self):
        next(r for r in self.repomds if r.id == 201).save.side_effect = RuntimeError("db down")
        with self.assertRaises(RuntimeError):
            self._apply(self._hash())
        self.assertIsInstance(self.transaction_exits[0], RuntimeError)


class TestRolloverTemplate(unittest.TestCase):

    def _render(self, **context):
        request = SimpleNamespace(
            cookies={},
            session={},
            state=SimpleNamespace(settings=SimpleNamespace(serve_rh_advisories=False, is_admin=True)),
            url=SimpleNamespace(path="/admin/supported-products/1/rollover"),
        )
        product = SimpleNamespace(id=ROCKY, name="Rocky Linux")
        return templates.get_template("admin_supported_product_rollover.jinja").render(
            request=request, product=product, major_versions=[10, 9, 8], **context
        )

    def test_form_only(self):
        html = self._render()
        self.assertIn('action="/admin/supported-products/1/rollover/preview"', html)
        self.assertNotIn("rollover/apply", html)

    def test_preview_shows_changes_checks_and_apply_form(self):
        mirrors, repomds = prod_fixture()
        mirrors.append(_mirror(99, "Rocky Linux 10 x86_64", 10, 1))
        plan = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)
        checks = _ok_checks(plan.new_urls)
        failing = plan.new_urls[0]
        checks[failing] = rollover.UrlCheck(failing, rollover.URL_CHECK_FAILED, "HTTP 404")

        html = self._render(form={"major_version": 10, "from_minor": 2, "to_minor": 3}, plan=plan, url_checks=checks)

        self.assertIn(f'name="plan_hash" value="{plan.plan_hash}"', html)
        self.assertIn("<mark>/10.3/</mark>", html)
        self.assertIn("<mark>/10.2/</mark>", html)
        self.assertIn("Rocky Linux 10 x86_64 (pinned to minor 1)", html)
        self.assertIn("HTTP 404", html)
        self.assertIn('name="allow_failed_url_checks"', html)
        self.assertIn('<option value="10" selected>', html)

    def test_preview_warns_about_urls_for_another_minor(self):
        mirrors, repomds = prod_fixture()
        repomds.append(_repomd(202, 35, f"{STG}/10.1", "NFV", "aarch64", debug=False, source=False))
        plan = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)
        html = self._render(plan=plan, url_checks={})
        self.assertIn("URLs for another minor release", html)
        self.assertIn("NFV aarch64 url: https://dl.rockylinux.org/stg/rocky<mark>/10.1/</mark>NFV", html)
        self.assertIn("1 unchanged URL(s) pointing at another minor release", html)

    def test_empty_plan_has_no_apply_form(self):
        mirrors, repomds = prod_fixture()
        plan = build_plan(ROCKY, 8, 9, 10, mirrors, repomds)
        html = self._render(form={"major_version": 8, "from_minor": 9, "to_minor": 10}, plan=plan, url_checks={})
        self.assertIn("Nothing to apply.", html)
        self.assertNotIn("rollover/apply", html)

    def test_applied_result_links_to_workflows_without_forms(self):
        mirrors, repomds = prod_fixture()
        plan = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)
        html = self._render(form={"major_version": 10, "from_minor": 2, "to_minor": 3}, applied_plan=plan)
        self.assertIn("Rollover applied", html)
        self.assertIn('href="/admin/workflows"', html)
        self.assertNotIn("<form", html)

    def test_urls_are_escaped(self):
        mirrors, repomds = prod_fixture()
        next(r for r in repomds if r.id == 200).url = f"{STG}/10.2/<script>/repomd.xml"
        plan = build_plan(ROCKY, 10, 2, 3, mirrors, repomds)
        html = self._render(plan=plan, url_checks={})
        self.assertNotIn("<script>/repomd.xml", html)
        self.assertIn("</mark>&lt;script&gt;/repomd.xml", html)


if __name__ == "__main__":
    unittest.main()
