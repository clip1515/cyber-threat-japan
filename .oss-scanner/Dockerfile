# Offline audit image for Anthropic OSS Scanner.
# Never copy the production SQLite database, generated reports, logs or secrets.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
WORKDIR /workspace
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CI_LATEST_MAIN_JSON=0
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt \
 && python -m pip install --no-cache-dir playwright==1.55.0 \
 && python -m pip check

# Safe, explicit allowlist. Runtime collection and publication never run here.
COPY .github/workflows/ .github/workflows/
COPY analyzers/ analyzers/
COPY collectors/ collectors/
COPY config/ config/
COPY dashboard/ dashboard/
COPY database/ database/
COPY parsers/ parsers/
COPY reporting/ reporting/
COPY scripts/ scripts/
COPY tests/ tests/
COPY docs/index.html docs/index.html
COPY app.py update.py ./
CMD ["python", "-m", "pytest", "-q", "tests/"]
