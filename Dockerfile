FROM python:3.11-slim

WORKDIR /app

# system deps (optional)
RUN pip install --no-cache-dir -U pip

COPY pyproject.toml setup.cfg README.md /app/
COPY src /app/src
COPY docs /app/docs
COPY policies /app/policies
COPY slack /app/slack
COPY workflows /app/workflows
COPY runbooks /app/runbooks
COPY .github /app/.github

RUN pip install --no-cache-dir -e ".[dev]" && pip cache purge

EXPOSE 8000
CMD ["uvicorn", "guardrails.app:app", "--host", "0.0.0.0", "--port", "8000"]
