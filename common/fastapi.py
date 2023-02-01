import os

from fastapi.staticfiles import StaticFiles


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
