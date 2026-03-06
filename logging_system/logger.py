import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import os

from .log_formatter import JSONFormatter
from .message_builder import build_message


def get_logger():

    logger = logging.getLogger("EDR")

    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    os.makedirs("logs", exist_ok=True)

    today = datetime.now().strftime("%Y-%m-%d")
    log_filename = f"logs/{today}_edr_logs.json"

    handler = RotatingFileHandler(
        log_filename,
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )

    formatter = JSONFormatter()
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


logger = get_logger()


def log_event(event_data):

    message = build_message(event_data)

    log_record = {
        "message": message,
        "level": "INFO",
        "timestamp": datetime.now().isoformat() + "Z",
        "event_data": event_data
    }

    logger.info(message, extra={"event": log_record})