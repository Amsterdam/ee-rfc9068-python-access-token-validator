ARG PYTHON_VERSION
FROM ghcr.io/astral-sh/uv:0.8-python${PYTHON_VERSION:-3.13}-alpine

WORKDIR /app

ADD . /app

RUN uv sync --locked
