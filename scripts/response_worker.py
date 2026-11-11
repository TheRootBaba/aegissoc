"""Workspace-aware response action delivery worker."""

import logging
import time

from app.db.session import SessionLocal
from app.services.response_execution import run_due_response_actions_once
from app.services.workspace_workers import activate_workspace, active_workspace_ids

logger = logging.getLogger("aegissoc.response_worker")


def main() -> None:
    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logger.info("response_worker_started")
    while True:
        db = SessionLocal()
        try:
            workspace_ids = active_workspace_ids(db)
            db.rollback()
            for workspace_id in workspace_ids:
                activate_workspace(db, workspace_id)
                try:
                    completed = run_due_response_actions_once(db, batch_size=10)
                    if completed:
                        logger.info("response_actions_processed workspace_id=%s count=%s", workspace_id, completed)
                except Exception as exc:
                    db.rollback()
                    logger.error("response_workspace_failed workspace_id=%s error_type=%s",
                                 workspace_id, type(exc).__name__)
        except Exception as exc:
            db.rollback()
            logger.error("response_worker_cycle_failed error_type=%s", type(exc).__name__)
        finally:
            db.close()
        time.sleep(3)


if __name__ == "__main__":
    main()
