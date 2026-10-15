ARG PYTHON_VERSION
FROM ghcr.io/astral-sh/uv:0.13-python${PYTHON_VERSION:-3.11}-alpine

WORKDIR /app

ADD . /app

RUN uv python install ${PYTHON_VERSION:-3.11}

RUN uv sync --locked

ENTRYPOINT ["/app/entrypoint.sh"]
