load("@aspect_rules_py//py:defs.bzl", "py_binary")
load("@io_bazel_rules_docker//python3:image.bzl", "py3_image")
load("@io_bazel_rules_docker//container:container.bzl", "container_push")

def fastapi_binary(name, image_name, path, port, deps = [], tags = [], **kwargs):
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

    py3_image(
        name = "{}.image".format(name),
        srcs = ["@pypi_hypercorn//:rules_python_wheel_entry_point_hypercorn.py"],
        main = "@pypi_hypercorn//:rules_python_wheel_entry_point_hypercorn.py",
        args = ["{}:app".format(path), "--bind 127.0.0.1:{}".format(port)],
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

    container_push(
        name = "{}.push".format(name),
        format = "Docker",
        image = ":{}.image".format(name),
        registry = "ghcr.io",
        repository = "resf/{}".format(image_name),
        tag = "{BUILD_TAG}",
        visibility = ["//visibility:public"],
    )
