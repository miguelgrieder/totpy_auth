import logging
import os

LOG_NAME = "totpy_auth"
LOG_LEVEL = "DEBUG"
LOG_DIR_PATH = "logs"


def configure_logging() -> None:
    if LOG_LEVEL == "DEBUG":
        logformat = "\x1b[32m[%(asctime)s][%(levelno)s]: %(message)s\x1b[0m"
    else:
        logformat = "\x1b[32m[%(asctime)s][%(levelno)s]: %(message)s\x1b[0m"
    formatter = logging.Formatter(logformat)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel("NOTSET")

    log = logging.getLogger(LOG_NAME)
    log.handlers = []
    log.setLevel(LOG_LEVEL)
    log.addHandler(console_handler)
    log_file_path = os.path.join(LOG_DIR_PATH, f"{LOG_NAME}.log")
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setFormatter(formatter)
    file_handler.setLevel("NOTSET")
    log.addHandler(file_handler)
