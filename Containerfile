FROM ghcr.io/astral-sh/uv:0.8-python3.13-alpine

WORKDIR /app

ADD . /app

RUN uv sync --locked
