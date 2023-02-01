"""
Apollo CVE Indexer

Only indexes Red Hat advisory CVEs for now.
"""
import asyncio

from temporalio.worker import Worker
import click

from common.database import Database
from common.info import Info
from common.temporal import Temporal

from apollo.cveindexer.temporal import TASK_QUEUE


async def run():
    db = Database(True)
    await db.init(["apollo.db"])

    temporal = Temporal(True)
    await temporal.connect()

    worker = Worker(
        temporal.client, task_queue=TASK_QUEUE, workflows=[], activities=[]
    )

    await worker.run()


@click.command()
def main():
    Info("apollocveindexer", "apollo2")
    asyncio.run(run())


if __name__ == "__main__":
    main()
