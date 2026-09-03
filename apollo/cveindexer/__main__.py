"""
Apollo CVE Indexer

Materializes cve_product_statuses from RHSA/RLSA state (distro-tools#73).
"""
import asyncio
import datetime
from typing import Optional

from temporalio import workflow
from temporalio.worker import Worker
import click

from common.database import Database
from common.info import Info
from common.temporal import Temporal

from apollo.cveindexer.temporal import TASK_QUEUE
from apollo.rpmworker.cve_status_activities import (
    classify_cve_statuses_all_products,
    classify_cve_statuses_for_product,
)


@workflow.defn
class CveStatusIndexWorkflow:
    @workflow.run
    async def run(self, supported_product_id: Optional[int] = None) -> dict:
        if supported_product_id is not None:
            return await workflow.execute_activity(
                "classify_cve_statuses_for_product",
                supported_product_id,
                start_to_close_timeout=datetime.timedelta(hours=2),
            )
        return await workflow.execute_activity(
            "classify_cve_statuses_all_products",
            start_to_close_timeout=datetime.timedelta(hours=6),
        )


async def run():
    db = Database(True)
    await db.init(["apollo.db"])

    temporal = Temporal(True)
    await temporal.connect()

    worker = Worker(
        temporal.client,
        task_queue=TASK_QUEUE,
        workflows=[CveStatusIndexWorkflow],
        activities=[
            classify_cve_statuses_for_product,
            classify_cve_statuses_all_products,
        ],
    )

    await worker.run()


@click.command()
def main():
    Info("apollocveindexer", "apollo2")
    asyncio.run(run())


if __name__ == "__main__":
    main()
