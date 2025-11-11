FROM ghcr.io/astral-sh/uv:python3.11-bookworm
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
RUN uv pip install --system .
COPY src /app/src
COPY README.md /app/README.md
EXPOSE 8000
CMD ["uv", "run", "uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000"]
