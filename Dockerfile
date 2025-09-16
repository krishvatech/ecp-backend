FROM python:3.11-slim

# Prevent Python from writing pyc files
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System dependencies
RUN apt-get update && apt-get install -y build-essential libpq-dev curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Add a helpful label
LABEL org.opencontainers.image.title="ECP Backend" \
      org.opencontainers.image.description="Events & Community Platform backend pinned to Django 5.2.6 LTS" \
      org.opencontainers.image.source="https://example.com"

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . /app/

# Gunicorn with Uvicorn worker for ASGI (Channels)
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "ecp_backend.asgi:application", "--bind", "0.0.0.0:8000"]

# Create non-root user for better security
RUN useradd -ms /bin/bash appuser
USER appuser

# Expose application port
EXPOSE 8000