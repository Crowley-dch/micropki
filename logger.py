"""
Настройка логирования для MicroPKI
"""

import logging
import sys
from pathlib import Path
from datetime import datetime


def setup_logger(log_file=None, log_level=logging.INFO):

    logger = logging.getLogger('micropki')
    logger.setLevel(log_level)

    # Убираем старые обработчики, если есть
    logger.handlers.clear()

    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    if log_file:
        log_path = Path(log_file)

        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger


def get_logger():

    return logging.getLogger('micropki')


if __name__ == '__main__':
    logger = setup_logger()
    logger.info("Тестовое информационное сообщение")
    logger.warning("Тестовое предупреждение")
    logger.error("Тестовая ошибка")

    file_logger = setup_logger("test.log")
    file_logger.info("Это сообщение должно быть в файле")
    print("Лог записан в test.log")