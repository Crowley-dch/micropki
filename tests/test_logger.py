import pytest
import tempfile
from pathlib import Path
import logging

from micropki.logger import setup_logger, get_logger


class TestLogger:

    def test_setup_logger_console(self):
        logger = setup_logger(log_file=None)

        assert logger is not None
        assert logger.name == 'micropki'
        assert logger.level == logging.INFO
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)

    def test_setup_logger_file(self):
        import time

        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            log_file = f.name

        try:
            logger = setup_logger(log_file=log_file)

            assert logger is not None
            assert len(logger.handlers) == 1
            assert isinstance(logger.handlers[0], logging.FileHandler)

            logger.info("Test log message")

            for handler in logger.handlers:
                handler.close()
            logger.handlers.clear()

            time.sleep(0.1)

            log_path = Path(log_file)
            assert log_path.exists()
            content = log_path.read_text(encoding='utf-8')
            assert "Test log message" in content

        finally:
            # Очистка
            try:
                Path(log_file).unlink(missing_ok=True)
            except PermissionError:
                time.sleep(0.5)
                Path(log_file).unlink(missing_ok=True)

    def test_get_logger(self):
        logger1 = setup_logger()
        logger2 = get_logger()

        assert logger1 is logger2

    def test_log_format(self):
        import time

        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            log_file = f.name

        try:
            logger = setup_logger(log_file=log_file)
            logger.info("Test message")

            for handler in logger.handlers:
                handler.close()
            logger.handlers.clear()

            time.sleep(0.1)

            content = Path(log_file).read_text(encoding='utf-8')

            import re
            pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \[INFO\] Test message'
            assert re.search(pattern, content) is not None

        finally:
            try:
                Path(log_file).unlink(missing_ok=True)
            except PermissionError:
                time.sleep(0.5)
                Path(log_file).unlink(missing_ok=True)