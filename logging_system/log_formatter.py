import logging
import json


class JSONFormatter(logging.Formatter):

    def format(self, record):

        if hasattr(record, "event"):
            log_record = record.event
        else:
            log_record = {
                "message": record.getMessage(),
                "level": record.levelname
            }

        return json.dumps(log_record)