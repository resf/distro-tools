load("@aspect_rules_py//py:defs.bzl", _py_binary = "py_binary")
load("@io_bazel_rules_docker//python3:image.bzl", "py3_image")
load("@io_bazel_rules_docker//container:container.bzl", "container_push")

def py_binary(name, image_name, **kwargs):
    _py_binary(
        name = name,
        **kwargs
    )
    py3_image(
        name = "{}.image".format(name),
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
