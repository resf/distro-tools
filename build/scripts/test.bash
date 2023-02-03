#!/usr/bin/env bash

shopt -s globstar

python3 -m pytest --ignore node_modules --ignore .venv --ignore-glob "bazel-*" -v
