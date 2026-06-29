"""Centralized logging — console + rotating log files."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(
    log_dir: Path,
    level: str = "INFO",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    main_file = RotatingFileHandler(
        log_dir / "threatvault.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    main_file.setFormatter(fmt)
    root.addHandler(main_file)

    error_file = RotatingFileHandler(
        log_dir / "error.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    error_file.setLevel(logging.ERROR)
    error_file.setFormatter(fmt)
    root.addHandler(error_file)

    access_logger = logging.getLogger("threatvault.access")
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = False
    access_logger.handlers.clear()

    access_file = RotatingFileHandler(
        log_dir / "access.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    access_file.setFormatter(fmt)
    access_logger.addHandler(access_file)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True

    logging.getLogger(__name__).info(
        "Logging initialized -> %s (level=%s)", log_dir.resolve(), level
    )
# Project version: ThreatVault V1.1
