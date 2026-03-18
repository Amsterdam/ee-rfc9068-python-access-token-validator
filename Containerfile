ARG PYTHON_VERSION
FROM ghcr.io/astral-sh/uv:0.10-python${PYTHON_VERSION:-3.11}-alpine

WORKDIR /app

ADD . /app

RUN uv sync --locked
