import datetime
import os
from typing import Any, Optional

from fastapi import Query
from fastapi.staticfiles import StaticFiles
from fastapi_pagination import Params as FastAPIParams

from pydantic import BaseModel, root_validator


class StaticFilesSym(StaticFiles):
    "subclass StaticFiles middleware to allow symlinks"
    def lookup_path(self, path):
        for directory in self.all_directories:
            full_path = os.path.realpath(os.path.join(directory, path))
            try:
                stat_result = os.stat(full_path)
                return (full_path, stat_result)
            except FileNotFoundError:
                pass
        return ("", None)


class RenderErrorTemplateException(Exception):
    def __init__(self, msg=None, status_code=404):
        self.msg = msg
        self.status_code = status_code


class Params(FastAPIParams):
    def get_size(self) -> int:
        return self.size

    def get_offset(self) -> int:
        return self.size * (self.page - 1)


class DateTimeParams(BaseModel):
    before: str = Query(default=None)
    after: str = Query(default=None)

    before_parsed: datetime.datetime = None
    after_parsed: datetime.datetime = None

    @root_validator(pre=True)
    def __root_validator__(cls, value: Any) -> Any:  # pylint: disable=no-self-argument
        if value["before"]:
            before = parse_rfc3339_date(value["before"])
            if not before:
                raise RenderErrorTemplateException("Invalid before date", 400)
            value["before_parsed"] = before

        if value["after"]:
            after = parse_rfc3339_date(value["after"])
            if not after:
                raise RenderErrorTemplateException("Invalid after date", 400)
            value["after_parsed"] = after

        return value

    def get_before(self) -> datetime.datetime:
        return self.before_parsed

    def get_after(self) -> datetime.datetime:
        return self.after_parsed


def parse_rfc3339_date(date: str) -> Optional[datetime.datetime]:
    if not date:
        return None

    try:
        parsed = datetime.datetime.fromisoformat(date.removesuffix("Z"))
        # Callers bind the result as naive UTC, the form a Z suffix already
        # yields; asyncpg refuses an aware datetime for a `timestamp` bind.
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError):
        # OverflowError: an offset that pushes the instant past year 1 or 9999.
        return None
    return parsed


def to_rfc3339_date(date: datetime.datetime) -> str:
    return date.isoformat("T").replace("+00:00", "") + "Z"
