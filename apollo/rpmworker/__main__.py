"""
Apollo RPM Temporal Worker

This worker only executes tasks that are related to RPMs.
"""
import asyncio

from temporalio.worker import Worker
import click

from apollo.rpmworker.rh_matcher_workflows import (
    RhMatcherWorkflow,
    RhDefunctWorkflow,
    RhRematchWorkflow,
)
from apollo.rpmworker.rh_matcher_activities import (
    get_supported_products_with_rh_mirrors,
    match_rh_repos,
    block_remaining_rh_advisories,
    clear_rh_blocks_for_product,
)
from apollo.rpmworker.cve_status_activities import classify_cve_statuses_for_product
from apollo.rpmworker.temporal import TASK_QUEUE

from common.database import Database
from common.info import Info
from common.temporal import Temporal
from common.logger import Logger


async def run():
    db = Database(True)
    await db.init(["apollo.db"])

    temporal = Temporal(True)
    await temporal.connect()

    worker = Worker(
        temporal.client,
        task_queue=TASK_QUEUE,
        workflows=[
            RhMatcherWorkflow,
            RhDefunctWorkflow,
            RhRematchWorkflow,
        ],
        activities=[
            get_supported_products_with_rh_mirrors,
            match_rh_repos,
            block_remaining_rh_advisories,
            clear_rh_blocks_for_product,
            classify_cve_statuses_for_product,
        ]
    )

    await worker.run()


@click.command()
def main():
    Info("apollorpmworker", "apollo2")
    Logger().info("Starting apollo-rpmworker")
    asyncio.run(run())


if __name__ == "__main__":
    main()
