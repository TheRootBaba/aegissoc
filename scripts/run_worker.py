"""Workspace-aware integration polling worker with bounded shutdown."""

import logging
import os
import signal
import time

from app.db.session import SessionLocal
from app.services.connector_runtime import run_due_connectors_once
from app.services.workspace_workers import activate_workspace, active_workspace_ids

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("aegissoc.worker")
running = True


def stop_worker(signum, frame):
    global running
    running = False


def main():
    signal.signal(signal.SIGTERM, stop_worker)
    signal.signal(signal.SIGINT, stop_worker)
    interval = max(2, min(60, int(os.getenv("WORKER_POLL_SECONDS", "5"))))
    logger.info("workspace_aware_worker_started poll_interval_seconds=%s", interval)
    while running:
        db = SessionLocal()
        try:
            workspace_ids = active_workspace_ids(db)
            db.rollback()
            for workspace_id in workspace_ids:
                if not running:
                    break
                activate_workspace(db, workspace_id)
                try:
                    completed = run_due_connectors_once(db, batch_size=5)
                    if completed:
                        logger.info("connector_worker_cycle_completed workspace_id=%s connectors=%s",
                                    workspace_id, completed)
                except Exception as exc:
                    db.rollback()
                    logger.error("connector_worker_workspace_failed workspace_id=%s error_type=%s",
                                 workspace_id, type(exc).__name__)
        except Exception as exc:
            db.rollback()
            logger.error("worker_cycle_failed error_type=%s", type(exc).__name__)
        finally:
            db.close()
        for _ in range(interval * 10):
            if not running:
                break
            time.sleep(0.1)
    logger.info("worker_stopped")


if __name__ == "__main__":
    main()
