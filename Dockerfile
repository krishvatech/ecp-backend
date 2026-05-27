FROM python:3.11-slim

ARG BUILD_SHA=unknown
ARG BUILD_TAG=unknown
ARG IMAGE_URI=unknown

LABEL org.opencontainers.image.revision="${BUILD_SHA}" \
      org.opencontainers.image.version="${BUILD_TAG}" \
      org.opencontainers.image.ref.name="${IMAGE_URI}" \
      org.opencontainers.image.title="ecp-backend"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_BUILD_SHA="${BUILD_SHA}"
ENV APP_BUILD_TAG="${BUILD_TAG}"
ENV APP_IMAGE_URI="${IMAGE_URI}"

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    netcat-openbsd \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# MJML CLI fallback (used when the Python `mrml` compiler is unavailable)
RUN npm install -g mjml

COPY . /app/

RUN useradd -ms /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Healthcheck queries the Django health endpoint.  This is used by Docker and the
# GitHub workflow to verify readiness.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health/ || exit 1

# Keep Daphne's application close timeout above normal browser abort/reconnect
# windows so in-flight Django requests can finish cleanly under load.
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "--application-close-timeout", "30", "ecp_backend.asgi:application"]
