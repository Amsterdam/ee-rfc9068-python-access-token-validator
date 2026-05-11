#!/usr/bin/env sh
set -eux

uv sync --locked

exec "$@"
