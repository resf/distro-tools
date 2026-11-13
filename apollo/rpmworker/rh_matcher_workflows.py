import datetime
from dataclasses import dataclass
from typing import Optional

from temporalio import workflow
from temporalio.common import RetryPolicy

# The worker heartbeats while matching, so an evicted or OOM-killed worker is noticed
# within this window and the activity is retried, instead of sitting "started" until
# the 12 h start_to_close timeout expires.
LONG_ACTIVITY_HEARTBEAT_TIMEOUT = datetime.timedelta(minutes=10)

# Bounded: an activity that keeps getting killed (for example by running out of memory)
# fails the workflow rather than retrying forever.
LONG_ACTIVITY_RETRY_POLICY = RetryPolicy(
    initial_interval=datetime.timedelta(minutes=1),
    maximum_attempts=3,
)


@dataclass
class RhMatcherWorkflowInput:
    major_versions: Optional[list[int]] = None


@dataclass
class RhDefunctWorkflowInput:
    supported_product_id: int


@workflow.defn
class RhMatcherWorkflow:
    @workflow.run
    async def run(self, input: Optional[RhMatcherWorkflowInput] = None) -> list[int]:
        # Extract major version filter from input (None means all versions for backward compatibility)
        filter_major_versions = input.major_versions if input else None
        
        supported_product_ids = await workflow.execute_activity(
            "get_supported_products_with_rh_mirrors",
            filter_major_versions,
            start_to_close_timeout=datetime.timedelta(seconds=20),
        )

        for supported_product_id in supported_product_ids:
            major_versions = filter_major_versions or await workflow.execute_activity(
                "get_rh_mirror_major_versions",
                supported_product_id,
                start_to_close_timeout=datetime.timedelta(seconds=20),
            )
            # One activity per major: match_rh_repos holds every matched package of
            # every mirror it processes until it clones, and the worker only returns that
            # memory when the activity ends (all majors ~22 GB, largest major ~10.5 GB).
            for major_version in sorted(major_versions):
                await workflow.execute_activity(
                    "match_rh_repos",
                    {"supported_product_id": supported_product_id, "filter_major_versions": [major_version]},
                    start_to_close_timeout=datetime.timedelta(hours=12),
                    heartbeat_timeout=LONG_ACTIVITY_HEARTBEAT_TIMEOUT,
                    retry_policy=LONG_ACTIVITY_RETRY_POLICY,
                )

        return supported_product_ids


@workflow.defn
class RhDefunctWorkflow:
    @workflow.run
    async def run(self, wf_in: RhDefunctWorkflowInput) -> None:
        await workflow.execute_activity(
            "block_remaining_rh_advisories",
            wf_in.supported_product_id,
            start_to_close_timeout=datetime.timedelta(hours=12),
            heartbeat_timeout=LONG_ACTIVITY_HEARTBEAT_TIMEOUT,
            retry_policy=LONG_ACTIVITY_RETRY_POLICY,
        )
