import logging
from typing import Optional

def setup_logger(name: str, level: str = 'INFO', to_console: bool = True, to_file: Optional[str] = None) -> logging.Logger:
    """
    Sets up a logger with the specified name, level, and output options.

    :param name: Name of the logger.
    :param level: Logging level (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
    :param to_console: If True, logs will be output to the console.
    :param to_file: If provided, logs will be output to the specified file.
    :return: Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s  %(name)s (%(filename)s:%(lineno)d)  %(message)s ',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    if to_console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    if to_file:
        file_handler = logging.FileHandler(to_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
