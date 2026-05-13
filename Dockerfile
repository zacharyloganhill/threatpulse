FROM python:3.13-slim

# Prevent .pyc files, buffer stdout/stderr, and fix Windows-authored source
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1

WORKDIR /app

# System deps required by WeasyPrint (PDF generation).
# Remove this block if you only use ReportLab for PDFs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf2.0-0 \
        libcairo2 \
        libffi8 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (cached layer — only rebuilds when lock file changes)
COPY requirements-lock.txt .
RUN pip install --no-cache-dir -r requirements-lock.txt

# Copy application code
COPY . .

# Non-root user for the running process
RUN useradd --no-create-home --shell /bin/false appuser \
    && mkdir -p /data /app/uploads/temp \
    && chown -R appuser:appuser /app /data

USER appuser

# DB lives on a mounted volume at /data so it survives container restarts
ENV DB_PATH=/data/threatpulse.db \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

# Simple liveness probe — no auth required, just checks the process is alive
HEALTHCHECK --interval=30s --timeout=10s --start-period=45s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Single worker: SQLite does not support concurrent multi-process writes.
# If you migrate to Postgres, bump --workers to (2 * CPU) + 1.
CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", \
     "--log-level", "warning"]
