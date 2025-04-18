DEFAULT_CRAWL_DEPTH = 3
DEFAULT_DELAY = 1
DEFAULT_PROXY = None
LOG_LEVEL = "INFO"

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": "secure.log",
            "mode": "a",
            "formatter": "detailed",
        },
    },
    "formatters": {
        "detailed": {
            "format": "%(asctime)s %(levelname)s %(message)s",
        },
    },
    "root": {
        "handlers": ["file"],
        "level": "INFO",
    },
}
