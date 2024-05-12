#! /usr/bin/env sh

# Exit in case of error
set -e
set -x

pytest --cov=src --cov-report=term-missing tests
