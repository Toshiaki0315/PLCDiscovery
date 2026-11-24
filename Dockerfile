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

# Installed under /install and copied to /usr/local below (not /root/.local):
# the packages stay usable when the container runs as another user
COPY requirements.txt requirements-optional.txt ./
RUN pip install --prefix=/install -r requirements.txt -r requirements-optional.txt

# ---------------------------------------------------
# Production stage
# ---------------------------------------------------
FROM base as production

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY plc_discovery/ ./plc_discovery/
COPY plc_scanner.py .
COPY plc_config.example.yaml .
COPY type_mapping.example.json .

# Output directory. The default output path ./plc_scan_results points to
# /app/output, the directory mounted in README / docker-compose (results
# were otherwise written inside the container and lost with --rm)
RUN mkdir -p /app/output && ln -s /app/output /app/plc_scan_results

# The container runs as root by default: the ARP scan of discovery needs raw
# sockets, and results are written to a bind-mounted host directory. Data
# collection needs neither; to run it as your own user (Linux):
#   docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/plc_scan_results:/app/output" plc-scanner ...

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
EXPOSE 5001 1502 44818 44819 44820 1102 9600/tcp 9600/udp

# Inside the container the simulators must listen on all interfaces;
# docker-compose publishes them on the host's loopback only
CMD ["python", "simulators/run_all.py", "--host", "0.0.0.0"]


