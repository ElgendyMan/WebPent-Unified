# tests/ground_truth/Dockerfile
# =============================================================================
# V5 Sprint 7 — Ground-Truth Vulnerable Target Dockerfile
# =============================================================================
# Intentionally minimal: the vulnerable FastAPI app needs only Python +
# FastAPI + uvicorn + httpx. No Playwright, no Go tools, no torch —
# this keeps the image at ~120MB vs the framework image's ~2GB, so the
# test stack builds in seconds rather than minutes.
#
# WARNING: The resulting image is deliberately insecure. It must NEVER
# be pushed to a public registry or exposed to untrusted networks. It
# is intended solely for local evaluation via docker-compose.test.yml.
# =============================================================================

FROM python:3.11-slim

LABEL org.opencontainers.image.title="WebPent Ground-Truth Target" \
      org.opencontainers.image.description="Intentionally vulnerable target for framework evaluation — DO NOT DEPLOY" \
      org.opencontainers.image.version="0.1.0"

# Unbuffered Python so logs surface immediately in docker-compose logs.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first (Docker layer caching — source changes
# don't invalidate the pip install layer).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the vulnerable app source.
COPY app.py .

# Expose the port the app listens on. docker-compose.test.yml maps this
# to a host port for direct inspection if needed.
EXPOSE 8080

# Health check so docker-compose can detect a wedged target.
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=2)" || exit 1

# Run as a non-root user for defence-in-depth (the app is vulnerable
# enough already; no need to also give an attacker root if they break
# out via RCE).
RUN useradd -r -d /home/target -m -s /bin/bash target && \
    mkdir -p /tmp && chmod 1777 /tmp
USER target
ENV HOME=/home/target

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
