import datetime

from temporalio import workflow


@workflow.defn
class PollRHAdvisoriesWorkflow:
    """
    Polls Red Hat Errata for new advisories.
    """
    @workflow.run
    async def run(self) -> None:
        from_timestamp = await workflow.execute_activity(
            "get_last_indexed_date",
            start_to_close_timeout=datetime.timedelta(seconds=20),
        )

        await workflow.execute_activity(
            "get_rh_advisories",
            from_timestamp,
            start_to_close_timeout=datetime.timedelta(hours=2),
        )

        return None
