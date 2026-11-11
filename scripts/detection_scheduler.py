"""Long-running polling worker for recurring AegisSOC detection schedules."""

import logging
import time

from sqlalchemy import inspect

from app.db.session import SessionLocal, engine
from app.services.detection_scheduler import run_due_schedules_once

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
    logger.info("Detection scheduler worker started; polling every %s seconds", POLL_INTERVAL_SECONDS)
    while True:
        try:
            with SessionLocal() as db:
                completed = run_due_schedules_once(db)
            if completed:
                logger.info("Scheduled detection executions completed: %s", completed)
        except Exception:
            logger.exception("Scheduler polling iteration failed; retrying")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
