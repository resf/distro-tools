#!/usr/bin/env bash

shopt -s globstar

python3 -m pylint --rcfile=.pylintrc --ignore-patterns "re.compile(r'bazel-.*|node-modules|.venv')" **/*.py -v | tee /tmp/pytest.txt
score=$(sed -n 's/^Your code has been rated at \([-0-9.]*\)\/.*/\1/p' /tmp/pytest.txt)

echo "===================="
if (( $(echo "$score < 9.0" | bc -l) )); then
    echo "Pylint score is too low: $score"
    exit 1
else
    echo "Pylint score is good: $score"
fi
echo "===================="
