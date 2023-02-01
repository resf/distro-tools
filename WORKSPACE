workspace(
    name = "depot",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Aspect Bazel Lib
http_archive(
    name = "aspect_bazel_lib",
    sha256 = "79623d656aa23ad3fd4692ab99786c613cd36e49f5566469ed97bc9b4c655f03",
    strip_prefix = "bazel-lib-1.23.3",
    url = "https://github.com/aspect-build/bazel-lib/archive/refs/tags/v1.23.3.tar.gz",
)

load("@aspect_bazel_lib//lib:repositories.bzl", "aspect_bazel_lib_dependencies", "register_copy_directory_toolchains", "register_copy_to_directory_toolchains")

aspect_bazel_lib_dependencies()

# Python
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "aspect_rules_py",
    sha256 = "66da30b09cf47ee40f2ae1c46346cc9a412940965d04899bd68d06a9d3380085",
    strip_prefix = "rules_py-0.1.0",
    url = "https://github.com/aspect-build/rules_py/archive/refs/tags/v0.1.0.tar.gz",
)

# Fetches the rules_py dependencies.
# If you want to have a different version of some dependency,
# you should fetch it *before* calling this.
# Alternatively, you can skip calling this function, so long as you've
# already fetched all the dependencies.
load("@aspect_rules_py//py:repositories.bzl", "rules_py_dependencies")

http_archive(
    name = "rules_python",
    patch_args = ["-p1"],
    patch_cmds = ["""\
cat >> python/BUILD.bazel <<EOF
load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
bzl_library(
name = "defs",
srcs = [
    ":bzl",
    "@bazel_tools//tools/python:srcs_version.bzl",
    "@bazel_tools//tools/python:utils.bzl",
    "@bazel_tools//tools/python:private/defs.bzl",
    "@bazel_tools//tools/python:toolchain.bzl",
],
visibility = ["//visibility:public"],
)
EOF
"""],
    patches = ["//build/patches:0001-Fix-Quart-and-Hypercorn-failing-to-install-with-rule.patch"],
    sha256 = "8c15896f6686beb5c631a4459a3aa8392daccaab805ea899c9d14215074b60ef",
    strip_prefix = "rules_python-0.17.3",
    url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.17.3.tar.gz",
)

http_archive(
    name = "rules_python_gazelle_plugin",
    sha256 = "8c15896f6686beb5c631a4459a3aa8392daccaab805ea899c9d14215074b60ef",
    strip_prefix = "rules_python-0.17.3/gazelle",
    url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.17.3.tar.gz",
)

rules_py_dependencies()

# Load the Python toolchain for rules_docker
register_toolchains("//:container_py_toolchain")

load("@rules_python//python:repositories.bzl", "python_register_toolchains")

python_register_toolchains(
    name = "python_toolchain",
    python_version = "3.9",
)

load("@rules_python//python:pip.bzl", "pip_parse")
load("@python_toolchain//:defs.bzl", "interpreter")

pip_parse(
    name = "pypi",
    python_interpreter_target = interpreter,
    requirements_lock = "//:requirements_lock.txt",
)

load("@pypi//:requirements.bzl", "install_deps")

install_deps()

# Go
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "56d8c5a5c91e1af73eca71a6fab2ced959b67c86d12ba37feedb0a2dfea441a6",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.37.0/rules_go-v0.37.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.37.0/rules_go-v0.37.0.zip",
    ],
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "448e37e0dbf61d6fa8f00aaa12d191745e14f07c31cabfa731f0c8e8a4f41b97",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.28.0/bazel-gazelle-v0.28.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.28.0/bazel-gazelle-v0.28.0.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

go_rules_dependencies()

go_register_toolchains(version = "1.19.5")

gazelle_dependencies()

# Python Gazelle

load("@rules_python//gazelle:deps.bzl", _py_gazelle_deps = "gazelle_deps")

_py_gazelle_deps()

# Docker
http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "b1e80761a8a8243d03ebca8845e9cc1ba6c82ce7c5179ce2b295cd36f7e394bf",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.25.0/rules_docker-v0.25.0.tar.gz"],
)

load(
    "@io_bazel_rules_docker//repositories:repositories.bzl",
    container_repositories = "repositories",
)

container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

load("@io_bazel_rules_docker//python3:image.bzl", _py_image_repos = "repositories")

_py_image_repos()

# esbuild
http_archive(
    name = "aspect_rules_esbuild",
    sha256 = "f05e9a53ae4b394ca45742ac35f7e658a8ba32cba14b5d531b79466ae86dc7f0",
    strip_prefix = "rules_esbuild-0.14.0",
    url = "https://github.com/aspect-build/rules_esbuild/archive/refs/tags/v0.14.0.tar.gz",
)

######################
# rules_esbuild setup #
######################

# Fetches the rules_esbuild dependencies.
# If you want to have a different version of some dependency,
# you should fetch it *before* calling this.
# Alternatively, you can skip calling this function, so long as you've
# already fetched all the dependencies.
load("@aspect_rules_esbuild//esbuild:dependencies.bzl", "rules_esbuild_dependencies")

rules_esbuild_dependencies()

# Fetch and register node, if you haven't already
load("@rules_nodejs//nodejs:repositories.bzl", "nodejs_register_toolchains")

nodejs_register_toolchains(
    name = "node",
    node_version = "18.11.0",
)

load("@aspect_rules_js//npm:npm_import.bzl", "npm_translate_lock")

npm_translate_lock(
    name = "npm",
    npmrc = "//:.npmrc",
    pnpm_lock = "//:pnpm-lock.yaml",
    verify_node_modules_ignored = "//:.bazelignore",
)

load("@npm//:repositories.bzl", "npm_repositories")

npm_repositories()

# Register a toolchain containing esbuild npm package and native bindings
load("@aspect_rules_esbuild//esbuild:repositories.bzl", "esbuild_register_toolchains")

esbuild_register_toolchains(
    name = "esbuild",
    esbuild_version = "0.16.7",
)

register_copy_directory_toolchains()

register_copy_to_directory_toolchains()

# Copybara
http_archive(
    name = "com_github_google_copybara",
    sha256 = "5ad1e07646025d69818cffd29a6b4869861242a0b4659570a222efe0a018c879",
    strip_prefix = "copybara-2fc63380448609af90b5c2a46fd0f8655377cba5",
    url = "https://github.com/google/copybara/archive/2fc63380448609af90b5c2a46fd0f8655377cba5.zip",
)

load("@com_github_google_copybara//:repositories.bzl", "copybara_repositories")

copybara_repositories()

load("@com_github_google_copybara//:repositories.maven.bzl", "copybara_maven_repositories")

copybara_maven_repositories()

load("@com_github_google_copybara//:repositories.go.bzl", "copybara_go_repositories")

copybara_go_repositories()
