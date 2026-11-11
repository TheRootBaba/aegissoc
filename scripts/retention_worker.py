"""Periodic retention worker; database migrations are owned by the API service."""

import logging
import time

from app.db.session import SessionLocal
from app.services.retention import run_retention_cleanup

logger = logging.getLogger("aegissoc.retention_worker")


def main() -> None:
    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(name)s %(message)s")
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
