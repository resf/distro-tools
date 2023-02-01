load("@aspect_rules_py//py:defs.bzl", "py_binary")

def fastapi_binary(name, path, port, deps = [], tags = [], **kwargs):
    py_binary(
        name = name,
        srcs = ["@pypi_hypercorn//:rules_python_wheel_entry_point_hypercorn.py"],
        args = ["{}:app".format(path), "--reload", "--bind 127.0.0.1:{}".format(port)],
        visibility = ["//:__subpackages__"],
        deps = deps + [
            ":{}_lib".format(name),
            "@pypi_hypercorn//:pkg",
        ],
        tags = tags + [
            "ibazel_notify_changes",
        ],
        **kwargs
    )

    py_binary(
        name = "{}.prod".format(name),
        srcs = ["@pypi_hypercorn//:rules_python_wheel_entry_point_hypercorn.py"],
        args = ["{}:app".format(path), "--reload", "--bind 127.0.0.1:{}".format(port)],
        visibility = ["//:__subpackages__"],
        deps = deps + [
            ":{}_lib".format(name),
            "@pypi_hypercorn//:pkg",
        ],
        tags = tags + [
            "ibazel_notify_changes",
        ],
        **kwargs
    )
