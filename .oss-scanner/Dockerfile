# Offline audit environment for Anthropic OSS Scanner.
# No workflow or production data is executed or modified by this image.
FROM python:3.11-slim

WORKDIR /workspace
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CI_LATEST_MAIN_JSON=0

COPY requirements.txt /workspace/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt "playwright==1.55.0" \
    && python -m playwright install --with-deps chromium firefox webkit \
    && python -m pip check

COPY . /workspace/
# This deliberately does not run update.py or contact threat feeds.
# Security scanners should operate without any network after image build.
CMD ["python", "-m", "pytest", "tests/", "-q"]
