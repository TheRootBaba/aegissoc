FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY web ./web
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000
CMD ["sh", "-c", "DATABASE_URL=\"$MIGRATION_DATABASE_URL\" alembic upgrade head && python -m scripts.configure_runtime_role && DATABASE_URL=\"$RUNTIME_DATABASE_URL\" exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
