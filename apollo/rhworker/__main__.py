"""
Apollo RH Temporal Worker

This worker only executes tasks that are related to Red Hat.
"""
import asyncio

from temporalio.worker import Worker
import click

from common.database import Database
from common.info import Info
from common.logger import Logger
from common.temporal import Temporal

from apollo.rhworker.temporal import TASK_QUEUE
from apollo.rhworker.poll_rh_workflow import PollRHAdvisoriesWorkflow
from apollo.rhworker.poll_rh_activities import get_last_indexed_date, get_rh_advisories


async def run():
    db = Database(True)
    await db.init(["apollo.db"])

    temporal = Temporal(True)
    await temporal.connect()

    worker = Worker(
        temporal.client,
        task_queue=TASK_QUEUE,
        workflows=[
            PollRHAdvisoriesWorkflow,
        ],
        activities=[
            get_last_indexed_date,
            get_rh_advisories,
        ]
    )

    await worker.run()


@click.command()
def main():
    Info("apollorhworker", "apollo2")
    Logger().info("Starting apollo-rhworker")
    asyncio.run(run())


if __name__ == "__main__":
    main()
