# PLC Discovery Tool - Docker Image
# Multi-stage build for optimized image size

FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------
# Builder stage: Install Python dependencies
# ---------------------------------------------------
FROM base as builder

COPY requirements.txt .
RUN pip install --user -r requirements.txt

# ---------------------------------------------------
# Production stage
# ---------------------------------------------------
FROM base as production

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY plc_discovery/ ./plc_discovery/
COPY plc_scanner.py .
COPY plc_config.example.yaml .
COPY type_mapping.example.json .

# Create output directory
RUN mkdir -p /app/output

# Default command
ENTRYPOINT ["python", "plc_scanner.py"]
CMD ["--help"]

# ---------------------------------------------------
# Development stage (includes dev dependencies)
# ---------------------------------------------------
FROM base as development

COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements.txt -r requirements-dev.txt

COPY . .

# Create output directory
RUN mkdir -p /app/output

CMD ["python", "-m", "pytest", "tests/", "-v"]

# ---------------------------------------------------
# Simulator stage
# ---------------------------------------------------
FROM base as simulator

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY simulators/ ./simulators/
COPY plc_discovery/ ./plc_discovery/

# Simulator ports (see simulators/run_all.py): SLMP, Modbus, EtherNet/IP, S7, FINS
EXPOSE 5001 1502 44818 1102 9600/tcp 9600/udp

CMD ["python", "simulators/run_all.py"]


