"""
Application information
"""
import os

from common.env import get_env, is_k8s


class Info:
    """
    Application information singleton class
    """

    _name = None
    _dbname = None

    def __init__(self, name=None, dbname=None):
        if not self._name and not name:
            raise ValueError("Info.name is not set")
        if self._name and name:
            raise ValueError("Info.name is already set")
        if name:
            Info._name = name
            Info._dbname = dbname if dbname else name

        self._name = Info._name

    def name(self):
        return self._name

    def dbname(self):
        return f"{self._dbname}{get_env()}"

    def dbuser(self):
        return os.environ.get("DB_USER", "postgres")

    def dbpassword(self):
        return os.environ.get("DB_PASSWORD", "postgres")

    def dbhost(self):
        return os.environ.get("DB_HOST", "localhost")

    def dbport(self):
        return os.environ.get("DB_PORT", "5432")

    def dbsslmode(self):
        return os.environ.get("DB_SSLMODE", "disable")

    def temporal_host(self):
        if is_k8s():
            return "workflow-temporal-frontend.workflow.svc.cluster.local:7233"
        else:
            return os.environ.get("TEMPORAL_HOSTPORT", "localhost:7233")

    def temporal_namespace(self):
        return os.environ.get("TEMPORAL_NAMESPACE", "default")
