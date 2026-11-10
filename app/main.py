from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import events, health
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from app import models  # noqa: F401 - registers SQLAlchemy models


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Convenience for the Phase 1 local prototype. Phase 1.1 will replace
    # create_all with Alembic migrations before broader deployment.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Local-first security event ingestion and investigation foundation.",
    lifespan=lifespan,
)

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
