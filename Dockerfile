# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies including Docker CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    gnupg \
    lsb-release \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and add to docker group
RUN useradd -m appuser && chown -R appuser /app \
    && groupadd -f docker \
    && usermod -aG docker appuser
USER appuser

# Install container vulnerability scanners
# Both Docker Scout and Grype are installed - selection via CONTAINER_SCANNER env var
RUN mkdir -p /home/appuser/.local/bin && \
    curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s -- -b /home/appuser/.local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /home/appuser/.local/bin

# Install Python dependencies
COPY --chown=appuser:appuser requirements.txt /app/
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy project
COPY --chown=appuser:appuser . /app/

# Add local bin to path for appuser
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Expose port
EXPOSE 5000

# Run the application with increased timeout for long-running scans (Docker Scout, Checkov)
# Docker Scout can be slower than Grype, especially pulling images from registries
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--timeout", "600", "--workers", "2", "app:app"]
