# =========================================================
# Stage 1: Build dependencies in a virtual environment
# =========================================================
FROM python:3.10-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ libgomp1 && \
    rm -rf /var/lib/apt/lists/*

# Create virtualenv and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =========================================================
# Stage 2: Hardened Runtime Container
# =========================================================
FROM python:3.10-slim AS runtime

# Install minimal runtime libraries (OpenMP for XGBoost/PyTorch and curl for health probes)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libgomp1 curl && \
    rm -rf /var/lib/apt/lists/*

# Create dedicated non-root service account
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -m appuser

WORKDIR /app

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application modules and model artifacts
COPY --chown=appuser:appgroup artifacts/ artifacts/
COPY --chown=appuser:appgroup cloud/ cloud/
COPY --chown=appuser:appgroup explainability/ explainability/
COPY --chown=appuser:appgroup models/ models/
COPY --chown=appuser:appgroup preprocessing/ preprocessing/
COPY --chown=appuser:appgroup telemetry/ telemetry/
COPY --chown=appuser:appgroup config.yaml .

# Security & Runtime environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    ARTIFACTS_DIR=/app/artifacts \
    PORT=8000

# Container healthcheck using liveness probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Drop privileges to non-root user
USER appuser:appgroup

EXPOSE 8000

CMD ["uvicorn", "cloud.app:app", "--host", "0.0.0.0", "--port", "8000"]
