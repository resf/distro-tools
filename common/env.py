"""
Environment variables
"""
import os


def get_env():
    return os.environ.get("ENV", "development")


def is_prod():
    return get_env() == "1"


def is_k8s():
    return os.environ.get("KUBERNETES", "0") == "1"
