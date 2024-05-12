#!/bin/sh -e
set -x

black .
isort .
