# Offline audit image for Anthropic OSS Scanner.
# Never copy the production SQLite database, generated reports, logs or secrets.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble@sha256:640d578aae63cfb632461d1b0aecb01414e4e020864ac3dd45a868dc0eff3078
WORKDIR /workspace
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CI_LATEST_MAIN_JSON=0
COPY requirements.txt ./
COPY .oss-scanner/requirements-lock.txt .oss-scanner/requirements-lock.txt
RUN python -m pip install --no-cache-dir -r requirements.txt \
    -r .oss-scanner/requirements-lock.txt \
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
COPY tests/ tests/
COPY docs/index.html docs/index.html
COPY app.py update.py ./
# The offline browser suite expects docs/data/dashboard_data.json.
# Generate a synthetic equivalent; NEVER include the production dashboard JSON.
RUN mkdir -p docs/data \
 && python -c "import json; from pathlib import Path; from tests.test_dashboard_browser import payload; Path('docs/data/dashboard_data.json').write_text(json.dumps(payload()), encoding='utf-8')"
CMD ["python", "-m", "pytest", "-q", "tests/"]
