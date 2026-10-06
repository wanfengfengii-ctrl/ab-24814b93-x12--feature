FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    HOST=0.0.0.0

WORKDIR /app

# No third-party dependencies: the API, tests and smoke scripts run on the
# Python standard library alone.
COPY app ./app
COPY scripts ./scripts
COPY tests ./tests

EXPOSE 8080

# Readiness probe: only healthy once the HTTP server answers /health.
HEALTHCHECK --interval=5s --timeout=3s --start-period=1s --retries=20 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)" || exit 1

CMD ["python", "-m", "app.server"]
