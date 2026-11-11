"""Workspace-aware polling worker for recurring AegisSOC detection schedules."""

import logging
import time

from sqlalchemy import inspect

from app.db.session import SessionLocal, engine
from app.models import Workspace
from app.services.detection_scheduler import run_due_schedules_once
from app.services.workspace_workers import activate_workspace, active_workspace_ids

POLL_INTERVAL_SECONDS = 5


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logger = logging.getLogger("aegissoc.scheduler.worker")
    logger.info("Detection scheduler worker starting; waiting for schema migrations")
    while True:
        try:
            if inspect(engine).has_table("detection_schedules"):
                break
        except Exception:
            logger.exception("Database not ready; retrying schema check")
        time.sleep(POLL_INTERVAL_SECONDS)
    logger.info("Workspace-aware detection scheduler started")
    while True:
        try:
            with SessionLocal() as db:
                workspace_ids = active_workspace_ids(db)
                db.rollback()
                for workspace_id in workspace_ids:
                    activate_workspace(db, workspace_id)
                    completed = run_due_schedules_once(db)
                    if completed:
                        logger.info("workspace_schedule_executions workspace_id=%s completed=%s", workspace_id, completed)
                    db.rollback()
        except Exception as exc:
            logger.error("scheduler_iteration_failed error_type=%s", type(exc).__name__)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
