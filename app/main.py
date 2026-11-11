from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request

from app.api.routes import events, health
from app.core.config import settings
from app.core.logging_config import configure_logging, request_id_var


configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle; schema changes are applied with Alembic."""
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    description="Local-first security event ingestion and investigation foundation.",
    lifespan=lifespan,
)


@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    """Attach a server-generated correlation ID to each request and response."""
    request_id = str(uuid4())
    token = request_id_var.set(request_id)
    request.state.request_id = request_id
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        request_id_var.reset(token)


app.include_router(health.router)
app.include_router(events.router)


@app.get("/")
def root():
    return {
        "name": "AegisSOC",
        "status": "running",
        "docs": "/docs",
        "phase": 1,
    }
