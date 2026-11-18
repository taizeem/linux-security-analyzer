import logging
from pathlib import Path
import sys
from typing import Optional


LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(
    name: str = "security_analyzer",
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
) -> logging.Logger:
    """Configure and return a logger instance without duplicate handlers."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        if log_file is not None:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger