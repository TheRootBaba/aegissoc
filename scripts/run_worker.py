import logging
import os
import signal
import time
from app.db.session import SessionLocal
from app.services.connector_runtime import run_due_connectors_once
from app.services.detection_scheduler import run_due_schedules_once

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
    logger.info("worker_started poll_interval_seconds=%s", interval)
    while running:
        db = SessionLocal()
        try:
            detections = run_due_schedules_once(db, batch_size=10)
            connectors = run_due_connectors_once(db, batch_size=5)
            if detections or connectors:
                logger.info("worker_cycle_completed detections=%s connectors=%s", detections, connectors)
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
