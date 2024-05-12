#!/usr/bin/env bash

# Exit in case of error
set -e
set -x

pip install --upgrade pip pip-tools
pip-sync requirements/*.txt
