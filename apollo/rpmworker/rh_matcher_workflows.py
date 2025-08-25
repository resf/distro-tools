import datetime
from dataclasses import dataclass
from typing import Optional

from temporalio import workflow


@dataclass
class RhMatcherWorkflowInput:
    supported_product_ids: Optional[list[int]] = None


@dataclass
class RhDefunctWorkflowInput:
    supported_product_id: int


@workflow.defn
class RhMatcherWorkflow:
    @workflow.run
    async def run(self, input: Optional[RhMatcherWorkflowInput] = None) -> list[int]:
        # Extract product ID filter from input (None means all products for backward compatibility)
        filter_product_ids = input.supported_product_ids if input else None
        
        supported_product_ids = await workflow.execute_activity(
            "get_supported_products_with_rh_mirrors",
            filter_product_ids,
            start_to_close_timeout=datetime.timedelta(seconds=20),
        )

        for supported_product_id in supported_product_ids:
            await workflow.execute_activity(
                "match_rh_repos",
                supported_product_id,
                start_to_close_timeout=datetime.timedelta(hours=12),
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
        )
