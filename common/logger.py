"""
This module provides a logger class that
can be used to log messages to the console.
"""
import logging

from common.env import is_prod
from common.info import Info


class Logger(object):
    """
    This class provides a logger that can be used to log messages to the console.
    """

    logger = None

    def __init__(self):
        info = Info()

        if Logger.logger is None:
            level = logging.INFO
            if not is_prod():
                level = logging.DEBUG
            logging.basicConfig(
                level=level,
                format="[%(name)s:%(levelname)s:%(asctime)s] %(message)s"
            )
            Logger.logger = logging.getLogger(info.name())

        self.logger = Logger.logger

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        self.logger.exception(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)

    def fatal(self, msg, *args, **kwargs):
        self.logger.fatal(msg, *args, **kwargs)
