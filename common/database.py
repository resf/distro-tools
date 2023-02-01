"""
Database helper methods
"""
from tortoise import Tortoise
from tortoise.contrib.fastapi import register_tortoise

from common.info import Info


class Database(object):
    """
    Database connection singleton class
    """

    initialized = False

    def __init__(self, initialize=False, tortoise_app=None, models=None):
        if not Database.initialized and not initialize:
            raise Exception("Database connection not initialized")

        if tortoise_app:
            register_tortoise(
                tortoise_app,
                db_url=self.conn_str(),
                modules={"models": models},
                add_exception_handlers=True,
            )
            self.initialized = True

    def conn_str(self):
        info = Info()

        return f"postgres://{info.dbuser()}:{info.dbpassword()}@{info.dbhost()}:{info.dbport()}/{info.dbname()}"

    async def init(self, models):
        if Database.initialized:
            return
        await Tortoise.init(
            db_url=self.conn_str(), use_tz=True, modules={"models": models}
        )

        self.initialized = True
