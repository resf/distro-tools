from temporalio.client import Client
from temporalio.worker import Worker

from apollo.rpmworker.rh_matcher_activities import (
    block_remaining_rh_advisories,
    get_rh_mirror_major_versions,
    get_supported_products_with_rh_mirrors,
    match_rh_repos,
)
from apollo.rpmworker.rh_matcher_workflows import RhDefunctWorkflow, RhMatcherWorkflow
from apollo.rpmworker.temporal import TASK_QUEUE


def build_worker(client: Client) -> Worker:
    return Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[
            RhMatcherWorkflow,
            RhDefunctWorkflow,
        ],
        activities=[
            get_supported_products_with_rh_mirrors,
            get_rh_mirror_major_versions,
            match_rh_repos,
            block_remaining_rh_advisories,
        ],
        # One matcher run needs several GB; concurrent runs in one pod add up until the
        # node evicts it. Queued activities wait; their start_to_close starts when they run.
        max_concurrent_activities=1,
    )
