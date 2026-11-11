import logging
from pathlib import Path
from contextlib import asynccontextmanager
from time import perf_counter
from uuid import uuid4
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from app.api.routes import workspaces, alert_workflow, audit, auth, cases, connectors, detections, detection_schedules, events, health, operations, sources, detection_rules, threat_intel, asset_risk, sigma, response_actions
from app.core.config import settings
from app.core.logging_config import configure_logging, request_id_var
configure_logging(settings.log_level)
logger = logging.getLogger("aegissoc.http")
WEB_DIR = Path(__file__).resolve().parents[1] / "web"
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle; schema changes are applied with Alembic."""
    yield
app = FastAPI(title=settings.app_name, version="0.4.0", description="Authenticated security event ingestion and investigation platform.", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.auth_secret_key, same_site="lax", https_only=settings.app_env == "production")
@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request_id = str(uuid4())
    token = request_id_var.set(request_id)
    request.state.request_id = request_id
    started_at = perf_counter()
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path.startswith("/api/v1/auth"):
            response.headers["Cache-Control"] = "no-store"
        if settings.app_env == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        logger.info("http_request_completed", extra={"method": request.method, "path": request.url.path, "status_code": response.status_code, "duration_ms": round((perf_counter() - started_at) * 1000, 2)})
        return response
    finally:
        request_id_var.reset(token)
app.include_router(health.router)
app.include_router(workspaces.router)
app.include_router(sources.router)
app.include_router(auth.router)
app.include_router(events.router)
app.include_router(detections.router)
app.include_router(detection_schedules.router)
app.include_router(alert_workflow.router)
app.include_router(cases.router)
app.include_router(detection_rules.router)
app.include_router(threat_intel.router)
app.include_router(asset_risk.router)
app.include_router(sigma.router)
app.include_router(response_actions.router)
app.include_router(audit.router)
app.include_router(operations.router)
app.include_router(connectors.router)
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(WEB_DIR / "index.html")
@app.get("/")
def root():
    return {"name": "AegisSOC", "status": "running", "docs": "/docs", "phase": 1}
