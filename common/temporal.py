"""
Temporal helper methods
"""

from temporalio.client import Client

from common.info import Info


class Temporal(object):
    """
    Temporal helper singleton class
    """

    client = None

    def __init__(self, initialize=False):
        if Temporal.client is None and not initialize:
            raise Exception("Temporal client not initialized")

        self.client = Temporal.client

    async def connect(self):
        info = Info()
        Temporal.client = await Client.connect(
            info.temporal_host(),
            namespace=info.temporal_namespace(),
        )
        self.client = Temporal.client
