# syntax=docker/dockerfile:1

# ── Build stage: has a shell, pip and uv; never shipped ─────────────────────
FROM cgr.dev/chainguard/python:latest-dev@sha256:88d8715285b78746679a86fa126fe01e68b7940c3299ee3b4cf8245d4b17095f AS build

COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app
USER root

# dependencies only, from the lockfile, no dev group
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project \
 && mkdir -p /app/data && chown 65532:65532 /app/data

# ── Runtime stage: distroless, no shell, no package manager ─────────────────
FROM cgr.dev/chainguard/python:latest@sha256:d914788ef74519450a69bc5cce6a1cc747dbefb95a3d431daa4ff707767fea8a

LABEL org.opencontainers.image.source="https://github.com/KacemMathlouthi/batch-tp-devsecops" \
      org.opencontainers.image.description="tp-devsecops notes API, hardened image"

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/app/data/notes.db

WORKDIR /app

# code and venv owned by root, read-only for the app user; only data/ is writable
COPY --from=build /app/.venv /app/.venv
COPY --from=build --chown=65532:65532 /app/data /app/data
COPY main.py ./
COPY templates ./templates

USER 65532:65532
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

ENTRYPOINT ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
