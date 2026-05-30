FROM ghcr.io/astral-sh/uv:python3.11-bookworm
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
RUN uv pip install --system .
COPY src /app/src
COPY README.md /app/README.md
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000"]
