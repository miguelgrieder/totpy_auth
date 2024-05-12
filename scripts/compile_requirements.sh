#!/usr/bin/env bash

# Exit in case of error
set -e
set -x

pip install --upgrade pip pip-tools
pip-compile --upgrade --resolver=backtracking requirements/requirements.in
pip-compile --upgrade requirements/requirements-dev.in
