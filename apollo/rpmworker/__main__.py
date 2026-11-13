"""
Apollo RPM Temporal Worker

This worker only executes tasks that are related to RPMs.
"""
import asyncio

import click

from apollo.rpmworker.worker import build_worker

from common.database import Database
from common.info import Info
from common.temporal import Temporal
from common.logger import Logger


async def run():
    db = Database(True)
    await db.init(["apollo.db"])

    temporal = Temporal(True)
    await temporal.connect()

    await build_worker(temporal.client).run()


@click.command()
def main():
    Info("apollorpmworker", "apollo2")
    Logger().info("Starting apollo-rpmworker")
    asyncio.run(run())


if __name__ == "__main__":
    main()
