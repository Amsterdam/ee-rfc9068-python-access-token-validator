ARG PYTHON_VERSION
FROM ghcr.io/astral-sh/uv:0.9-python${PYTHON_VERSION:-3.11}-alpine

WORKDIR /app

ADD . /app

RUN uv sync --locked
