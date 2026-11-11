"""Periodic retention worker; database migrations are owned by the API service."""

import logging
import time

from sqlalchemy import text

from app.db.session import SessionLocal
from app.services.retention import run_retention_cleanup

logger = logging.getLogger("aegissoc.retention_worker")


def main() -> None:
    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # Wait for the API's Alembic migration step before touching retention tables.
    while True:
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1 FROM retention_policies LIMIT 1"))
            break
        except Exception:
            logger.info("retention_worker_waiting_for_schema")
            time.sleep(5)
        finally:
            db.close()

    while True:
        db = SessionLocal()
        try:
            result = run_retention_cleanup(db)
            logger.info("retention_cleanup_completed status=%s records_affected=%s", result["status"], result["records_affected"])
        except Exception as exc:
            logger.error("retention_cleanup_failed error_type=%s", type(exc).__name__)
        finally:
            db.close()
        time.sleep(3600)


if __name__ == "__main__":
    main()
