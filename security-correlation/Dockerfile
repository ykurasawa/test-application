# -----------------------------------------------------------------------
# Security Event Correlation App
# ArcSight ESM x Cybereason EDR
# -----------------------------------------------------------------------
FROM python:3.11-slim

# Prevent .pyc files and enable unbuffered output (important for logs)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY arcsight_client.py .
COPY correlator.py .
COPY main.py .

# Output directory for reports (can be mounted as a volume)
RUN mkdir -p /app/reports

# Default output path is inside /app/reports so it can be retrieved
# via a bind mount:  -v $(pwd)/reports:/app/reports
ENV CORRELATION_OUTPUT_FILE=/app/reports/correlation_report.json

# Non-root user for security
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["python", "main.py"]
