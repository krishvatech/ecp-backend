# Events & Community Platform Backend

This repository contains a headless Django backend for an Events & Community Platform.  It uses Django REST Framework (DRF) for API endpoints, Simple JWT for authentication, Channels for WebSocket support, Celery for asynchronous tasks, and PostgreSQL + Redis for storage and messaging.

## Quickstart with Docker

1. Copy the example environment file and adjust values as needed:

   ```bash
   cp .env.example .env
   ```

2. Build and start the services:

   ```bash
   docker compose up --build
   ```

3. Apply database migrations and (optionally) load initial fixture data:

   ```bash
   docker compose exec web python manage.py migrate
   docker compose exec web python manage.py loaddata data/fixtures/users.json
   docker compose exec web python manage.py loaddata data/fixtures/community.json
   docker compose exec web python manage.py loaddata data/fixtures/events.json
   ```

4. Access the API at `http://localhost:8000/api/` when `DEBUG=True`.  You can use the browsable API or cURL examples (see below).

5. Create a superuser (optional) to access the admin panel at `/admin/`:

   ```bash
   docker compose exec web python manage.py createsuperuser
   ```

## Running Locally without Docker

You can run the project directly on your host machine if you have Python 3.11, PostgreSQL, and Redis installed:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
export DJANGO_SETTINGS_MODULE=ecp_backend.settings.dev
python manage.py migrate
python manage.py runserver 0.0.0.0:8000

# Start Celery worker and beat in separate shells
celery -A ecp_backend.celery_app worker -l info
celery -A ecp_backend.celery_app beat -l info
```

## Tests

Run the Django tests using pytest:

```bash
pytest
```

## API Overview

- `POST /api/auth/register/` – Register a new user with nested profile
- `POST /api/auth/token/` – Obtain JWT access and refresh tokens
- `POST /api/auth/token/refresh/` – Refresh an access token
- `GET /api/users/me/` – Retrieve the authenticated user’s details
- `PUT /api/users/me/` – Update authenticated user’s email or profile
- `GET /api/community/` – List community the user belongs to
- `POST /api/community/` – Create a new community (user becomes owner)
- `GET/PATCH/DELETE /api/community/<id>/` – Retrieve, update, or delete an community
- `GET /api/events/` – List events in community the user belongs to
- `POST /api/events/` – Create an event within an community
- `GET/PATCH/DELETE /api/events/<id>/` – Manage an event

WebSocket endpoint (authenticated via JWT):

- `ws://<host>:8000/ws/events/<event_id>/` – Connect with `?token=<JWT_ACCESS_TOKEN>` query to broadcast or listen for messages within the event’s group.

## License

Distributed under the MIT License.  See `LICENSE` for more information.