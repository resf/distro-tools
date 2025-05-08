"""
Apollo RH Temporal Worker

This worker only executes tasks that are related to Red Hat.
"""
import asyncio

from temporalio.worker import Worker
import click

from common.info import Info
from common.logger import Logger
Info("apollorhworker", "apollo2") # TODO: Dive into the logging for Apollo to see if we can clean this up at all. Currently this hack is required to get the RHWorker Temporal worker to start correctly. This has something to do with the way the Info class is initialized in common.info. It seems to be a singleton, and it is initialized before the logger is set up. This causes issues when the logger tries to log messages before it is fully configured. By calling Info("apollorhworker", "apollo2"), we ensure that the Info class is initialized with the correct parameters for this worker, allowing it to log messages correctly.
from common.database import Database
from common.temporal import Temporal

from apollo.rhworker.temporal import TASK_QUEUE
from apollo.rhworker.poll_rh_workflow import PollRHAdvisoriesWorkflow, PollRHCSAFAdvisoriesWorkflow
from apollo.rhworker.poll_rh_activities import get_last_indexed_date, get_rh_advisories, process_csaf_files


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
            PollRHCSAFAdvisoriesWorkflow,
        ],
        activities=[
            get_last_indexed_date,
            get_rh_advisories,
            process_csaf_files,
        ]
    )

    await worker.run()


@click.command()
def main():
    Logger().info("Starting apollo-rhworker")
    asyncio.run(run())


if __name__ == "__main__":
    main()
