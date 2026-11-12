"""
Repoint a supported product's active mirrors from one Rocky minor release to another.

Mirrors that pin a minor (10.x) get match_minor_version moved, and every repomd URL has
its /{major}.{minor}/ path segment rewritten. Mirrors without a pinned minor (8/9) only
get their URLs rewritten. Mirror names are never changed.
"""
import asyncio
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

import aiohttp
from tortoise.transactions import in_transaction

from apollo.db import SupportedProductsRhMirror, SupportedProductsRpmRepomd
from common.logger import Logger

URL_FIELDS = ("url", "debug_url", "source_url")
# Preview and apply both check URLs inline, so the whole batch gets a budget that keeps
# the request well inside typical proxy timeouts. URLs not checked in time are unverified.
URL_CHECK_TIMEOUT_SECONDS = 10
URL_CHECK_BUDGET_SECONDS = 25
URL_CHECK_CONCURRENCY = 10

URL_CHECK_OK = "ok"
URL_CHECK_FAILED = "failed"
URL_CHECK_UNVERIFIED = "unverified"


class RolloverError(Exception):
    """The rollover request is invalid or cannot be applied."""


class RolloverConflict(RolloverError):
    """The configuration changed after the plan was previewed."""


class UrlCheckFailed(RolloverError):
    """At least one rewritten URL did not respond with HTTP 200."""

    def __init__(self, plan: "RolloverPlan", checks: Dict[str, "UrlCheck"]):
        self.plan = plan
        self.checks = checks
        failed = [c for c in checks.values() if not c.ok]
        super().__init__(f"{len(failed)} rewritten URL(s) did not return HTTP 200")


@dataclass(frozen=True)
class UrlChange:
    repomd_id: int
    repo_name: str
    arch: str
    field: str
    before: str
    after: str


@dataclass(frozen=True)
class UnchangedUrl:
    repomd_id: int
    repo_name: str
    arch: str
    field: str
    url: str
    # A /{major}.N/ segment for a minor other than the one being rolled over: the repo then
    # points at a different release than the mirror will match, which deserves a look.
    other_minor_segment: Optional[str] = None


@dataclass
class MirrorPlan:
    mirror_id: int
    mirror_name: str
    minor_before: Optional[int]
    minor_after: Optional[int]
    url_changes: List[UrlChange] = field(default_factory=list)
    unchanged_urls: List[UnchangedUrl] = field(default_factory=list)

    @property
    def changes_minor(self) -> bool:
        return self.minor_before != self.minor_after

    @property
    def mismatched_urls(self) -> List[UnchangedUrl]:
        return [u for u in self.unchanged_urls if u.other_minor_segment]


@dataclass(frozen=True)
class SkippedMirror:
    mirror_id: int
    mirror_name: str
    minor: int
    reason: str


@dataclass
class RolloverPlan:
    product_id: int
    major_version: int
    from_minor: int
    to_minor: int
    mirrors: List[MirrorPlan] = field(default_factory=list)
    skipped: List[SkippedMirror] = field(default_factory=list)

    @property
    def minor_change_count(self) -> int:
        return sum(1 for m in self.mirrors if m.changes_minor)

    @property
    def url_change_count(self) -> int:
        return sum(len(m.url_changes) for m in self.mirrors)

    @property
    def is_empty(self) -> bool:
        return self.minor_change_count == 0 and self.url_change_count == 0

    @property
    def new_urls(self) -> List[str]:
        return sorted({c.after for m in self.mirrors for c in m.url_changes})

    @property
    def mismatched_urls(self) -> List[UnchangedUrl]:
        return [u for m in self.mirrors for u in m.mismatched_urls]

    @property
    def plan_hash(self) -> str:
        """Fingerprint of every write the plan would make, so apply can prove it matches the preview."""
        writes = {
            "params": [self.product_id, self.major_version, self.from_minor, self.to_minor],
            "mirrors": [
                [m.mirror_id, m.minor_before, m.minor_after]
                for m in self.mirrors if m.changes_minor
            ],
            "urls": [
                [c.repomd_id, c.field, c.before, c.after]
                for m in self.mirrors for c in m.url_changes
            ],
        }
        encoded = json.dumps(writes, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()


@dataclass(frozen=True)
class UrlCheck:
    url: str
    status: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.status == URL_CHECK_OK


def validate_versions(major_version: int, from_minor: int, to_minor: int) -> None:
    if major_version < 1:
        raise RolloverError("Major version must be a positive integer")
    if from_minor < 0 or to_minor < 0:
        raise RolloverError("Minor versions must be non-negative integers")
    if from_minor == to_minor:
        raise RolloverError("From and to minor versions must differ")


def rewrite_minor_segment(url: str, major_version: int, from_minor: int, to_minor: int) -> Optional[str]:
    """
    Return url with the /{major}.{from}/ path segment moved to /{major}.{to}/, or None if absent.

    Both slashes are required so sibling trees such as /10.2-RC2/ or /10.20/ never match.
    """
    old_segment = f"/{major_version}.{from_minor}/"
    occurrences = url.count(old_segment)
    if occurrences == 0:
        return None
    if occurrences > 1:
        raise RolloverError(f"URL contains {old_segment} more than once, refusing to guess: {url}")
    return url.replace(old_segment, f"/{major_version}.{to_minor}/")


def _as_int(value) -> Optional[int]:
    # Version columns are numeric in Postgres, so asyncpg hands back Decimal despite IntField.
    return None if value is None else int(value)


def _plan_mirror(mirror, repomds, major_version: int, from_minor: int, to_minor: int) -> MirrorPlan:
    minor_before = _as_int(mirror.match_minor_version)
    plan = MirrorPlan(
        mirror_id=mirror.id,
        mirror_name=mirror.name,
        minor_before=minor_before,
        minor_after=None if minor_before is None else to_minor,
    )
    any_minor_segment = re.compile(rf"/{major_version}\.\d+/")
    for repomd in sorted(repomds, key=lambda r: (r.repo_name, r.arch, r.id)):
        for url_field in URL_FIELDS:
            before = getattr(repomd, url_field)
            if not before:
                continue
            after = rewrite_minor_segment(before, major_version, from_minor, to_minor)
            if after is not None:
                plan.url_changes.append(
                    UrlChange(repomd.id, repomd.repo_name, repomd.arch, url_field, before, after)
                )
                continue
            other = any_minor_segment.search(before)
            plan.unchanged_urls.append(
                UnchangedUrl(
                    repomd.id, repomd.repo_name, repomd.arch, url_field, before,
                    other.group(0) if other else None,
                )
            )
    return plan


def build_plan(
    product_id: int,
    major_version: int,
    from_minor: int,
    to_minor: int,
    mirrors: Iterable,
    repomds: Iterable,
) -> RolloverPlan:
    """Compute every change a rollover would make. Pure: performs no I/O."""
    validate_versions(major_version, from_minor, to_minor)

    repomds_by_mirror = defaultdict(list)
    for repomd in repomds:
        repomds_by_mirror[repomd.supported_products_rh_mirror_id].append(repomd)

    plan = RolloverPlan(product_id, major_version, from_minor, to_minor)
    in_scope = [
        m for m in mirrors
        if m.active and m.supported_product_id == product_id and _as_int(m.match_major_version) == major_version
    ]
    for mirror in sorted(in_scope, key=lambda m: (m.name, m.id)):
        # A mirror pinned to any other minor is stale or already rolled; moving it would
        # silently change which RHEL release it matches.
        minor = _as_int(mirror.match_minor_version)
        if minor is not None and minor != from_minor:
            plan.skipped.append(SkippedMirror(mirror.id, mirror.name, minor, f"pinned to minor {minor}"))
            continue
        plan.mirrors.append(
            _plan_mirror(mirror, repomds_by_mirror[mirror.id], major_version, from_minor, to_minor)
        )

    if not plan.mirrors and not plan.skipped:
        raise RolloverError(f"No active mirrors found for major version {major_version}")
    return plan


async def _load_scope(product_id: int, major_version: int, connection=None):
    mirrors_query = SupportedProductsRhMirror.filter(
        supported_product_id=product_id,
        match_major_version=major_version,
        active=True,
    )
    if connection is not None:
        mirrors_query = mirrors_query.select_for_update().using_db(connection)
    mirrors = await mirrors_query.all()

    repomds_query = SupportedProductsRpmRepomd.filter(
        supported_products_rh_mirror_id__in=[m.id for m in mirrors],
    )
    if connection is not None:
        repomds_query = repomds_query.select_for_update().using_db(connection)
    repomds = await repomds_query.all() if mirrors else []
    return mirrors, repomds


async def preview_rollover(product_id: int, major_version: int, from_minor: int, to_minor: int) -> RolloverPlan:
    validate_versions(major_version, from_minor, to_minor)
    mirrors, repomds = await _load_scope(product_id, major_version)
    return build_plan(product_id, major_version, from_minor, to_minor, mirrors, repomds)


async def _check_one(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, url: str) -> UrlCheck:
    async with semaphore:
        try:
            # Redirects are not followed: a configured repomd URL should answer directly, and
            # following them would let the server probe wherever a redirect points.
            async with session.head(url, allow_redirects=False) as response:
                if response.status == 200:
                    return UrlCheck(url, URL_CHECK_OK, "HTTP 200")
                location = response.headers.get("Location")
                detail = f"HTTP {response.status}" + (f" redirect to {location}" if location else "")
                return UrlCheck(url, URL_CHECK_FAILED, detail)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            return UrlCheck(url, URL_CHECK_UNVERIFIED, f"{type(e).__name__}: {e}".rstrip(": "))


def _task_result(url: str, task: "asyncio.Task", done) -> UrlCheck:
    if task not in done:
        return UrlCheck(url, URL_CHECK_UNVERIFIED, f"Not checked within {URL_CHECK_BUDGET_SECONDS}s")
    error = task.exception()
    if error is not None:
        return UrlCheck(url, URL_CHECK_UNVERIFIED, f"{type(error).__name__}: {error}")
    return task.result()


async def check_urls(urls: Iterable[str]) -> Dict[str, UrlCheck]:
    """HEAD every URL. Only HTTP 200 is ok; errors, timeouts and the batch budget are unverified."""
    urls = list(dict.fromkeys(urls))
    if not urls:
        return {}
    semaphore = asyncio.Semaphore(URL_CHECK_CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=URL_CHECK_TIMEOUT_SECONDS)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = {url: asyncio.ensure_future(_check_one(session, semaphore, url)) for url in urls}
        done, pending = await asyncio.wait(tasks.values(), timeout=URL_CHECK_BUDGET_SECONDS)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    return {url: _task_result(url, task, done) for url, task in tasks.items()}


async def _write_plan(plan: RolloverPlan, mirrors, repomds, connection) -> None:
    """Write exactly the plan's fields (plus the auto_now updated_at stamp) to the loaded rows."""
    mirrors_by_id = {m.id: m for m in mirrors}
    for mirror_plan in plan.mirrors:
        if mirror_plan.changes_minor:
            mirror = mirrors_by_id[mirror_plan.mirror_id]
            mirror.match_minor_version = mirror_plan.minor_after
            await mirror.save(using_db=connection, update_fields=["match_minor_version", "updated_at"])

    repomds_by_id = {r.id: r for r in repomds}
    changed_fields = defaultdict(list)
    for mirror_plan in plan.mirrors:
        for change in mirror_plan.url_changes:
            setattr(repomds_by_id[change.repomd_id], change.field, change.after)
            changed_fields[change.repomd_id].append(change.field)
    for repomd_id, fields in changed_fields.items():
        await repomds_by_id[repomd_id].save(using_db=connection, update_fields=[*fields, "updated_at"])


async def apply_rollover(
    product_id: int,
    major_version: int,
    from_minor: int,
    to_minor: int,
    *,
    expected_hash: str,
    actor: str,
    allow_failed_url_checks: bool = False,
) -> RolloverPlan:
    """
    Apply a previewed rollover atomically.

    Raises RolloverConflict if the configuration no longer produces the previewed plan,
    and UrlCheckFailed if any rewritten URL is not reachable unless explicitly allowed.
    """
    plan = await preview_rollover(product_id, major_version, from_minor, to_minor)
    if plan.plan_hash != expected_hash:
        raise RolloverConflict("Configuration changed since the preview was generated; preview again")
    if plan.is_empty:
        raise RolloverError("Nothing to apply: no mirror or URL changes")

    # URLs are checked before taking row locks so slow network calls never hold them.
    checks = await check_urls(plan.new_urls)
    if not allow_failed_url_checks and any(not c.ok for c in checks.values()):
        raise UrlCheckFailed(plan, checks)

    async with in_transaction() as connection:
        mirrors, repomds = await _load_scope(product_id, major_version, connection)
        locked_plan = build_plan(product_id, major_version, from_minor, to_minor, mirrors, repomds)
        if locked_plan.plan_hash != expected_hash:
            raise RolloverConflict("Configuration changed while applying; preview again")
        await _write_plan(locked_plan, mirrors, repomds, connection)

    Logger().info(
        "%s rolled over product %s major %s from minor %s to %s: %d mirror minor(s), %d URL(s)",
        actor, product_id, major_version, from_minor, to_minor,
        locked_plan.minor_change_count, locked_plan.url_change_count,
    )
    return locked_plan
