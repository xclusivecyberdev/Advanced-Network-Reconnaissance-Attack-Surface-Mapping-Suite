"""Logging configuration for the reconnaissance suite."""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional


def setup_logger(name: str, config: Optional[Any] = None) -> logging.Logger:
    """
    Setup logger with file and console handlers.

    Args:
        name: Logger name
        config: Configuration object

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    # Get configuration
    if config:
        log_level = config.get('logging.level', 'INFO')
        log_file = config.get('logging.file', 'logs/recon_suite.log')
        log_format = config.get('logging.format',
                                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        max_bytes = config.get('logging.max_bytes', 10485760)
        backup_count = config.get('logging.backup_count', 5)
    else:
        log_level = 'INFO'
        log_file = 'logs/recon_suite.log'
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        max_bytes = 10485760
        backup_count = 5

    # Set log level
    logger.setLevel(getattr(logging, log_level.upper()))

    # Create formatters
    formatter = logging.Formatter(log_format)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Failed to setup file logging: {e}")

    return logger


# Import Any for type hints
from typing import Any
