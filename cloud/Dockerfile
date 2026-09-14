# Use official Python runtime as a parent image
FROM python:3.10-slim as builder

# Set work directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ libgomp1 && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Second stage
FROM python:3.10-slim

WORKDIR /app

# Install runtime dependencies for XGBoost/SHAP
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*

# Copy installed dependencies from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy project files
COPY artifacts/ artifacts/
COPY cloud/ cloud/
COPY explainability/ explainability/
COPY models/ models/
COPY preprocessing/ preprocessing/
COPY telemetry/ telemetry/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV ARTIFACTS_DIR=/app/artifacts

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "cloud.app:app", "--host", "0.0.0.0", "--port", "8000"]
