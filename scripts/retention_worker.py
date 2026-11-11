"""Periodic retention worker operating independently within each workspace."""

import logging
import time

from sqlalchemy import text

from app.db.session import SessionLocal
from app.services.retention import run_retention_cleanup
from app.services.workspace_workers import activate_workspace, active_workspace_ids

logger = logging.getLogger("aegissoc.retention_worker")


def main() -> None:
    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(name)s %(message)s")
    while True:
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1 FROM alembic_version LIMIT 1"))
            break
        except Exception:
            logger.info("retention_worker_waiting_for_schema")
            time.sleep(5)
        finally:
            db.close()

    while True:
        db = SessionLocal()
        try:
            workspace_ids = active_workspace_ids(db)
            db.rollback()
            for workspace_id in workspace_ids:
                activate_workspace(db, workspace_id)
                try:
                    result = run_retention_cleanup(db)
                    logger.info("retention_cleanup_completed workspace_id=%s status=%s records_affected=%s",
                                workspace_id, result["status"], result["records_affected"])
                except Exception as exc:
                    db.rollback()
                    logger.error("retention_cleanup_failed workspace_id=%s error_type=%s",
                                 workspace_id, type(exc).__name__)
        except Exception as exc:
            db.rollback()
            logger.error("retention_worker_iteration_failed error_type=%s", type(exc).__name__)
        finally:
            db.close()
        time.sleep(3600)


if __name__ == "__main__":
    main()
