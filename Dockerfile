# ACGS-Lite Constitutional Sentinel — Cloud Run deployment
#
# Deploy from the repository root:
# gcloud run deploy acgs-sentinel --source . --region us-central1

FROM python:3.11-slim

WORKDIR /app

# Copy everything needed for pip install
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

# Install the package + server deps (uvicorn, starlette, httpx for GitLab API)
RUN pip install --no-cache-dir ".[google-cloud]" \
    uvicorn[standard] \
    starlette \
    httpx \
    pyyaml

# Create non-root user for Cloud Run security best practices
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "uvicorn acgs_lite.integrations.cloud_run_server:app --host 0.0.0.0 --port ${PORT} --workers 1 --log-level info"]
