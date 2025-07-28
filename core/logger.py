import os
import logging
from logging.handlers import RotatingFileHandler

class Logger:
    _logger = None

    @staticmethod
    def get_logger():
        if Logger._logger is None:
            Logger._configure_logger()
        return Logger._logger

    @staticmethod
    def _configure_logger():
        if not os.path.exists('logs/'):
            os.makedirs('logs/')

        Logger._logger = logging.getLogger()
        # Ajusta el nivel según la configuración de debug
        Logger._logger.setLevel(logging.INFO)

        # Handler para logs de nivel INFO y WARNING
        info_handler = RotatingFileHandler('./logs/info.log', maxBytes=10*1024*1024, backupCount=5)
        info_handler.setLevel(logging.INFO)
        class InfoAndWarningFilter(logging.Filter):
            def filter(self, record):
                return record.levelno in (logging.INFO, logging.WARNING)
        info_handler.addFilter(InfoAndWarningFilter())
        info_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        info_handler.setFormatter(info_formatter)
        Logger._logger.addHandler(info_handler)

        # Handler para logs de nivel ERROR y superiores
        error_handler = RotatingFileHandler('./logs/error.log', maxBytes=10*1024*1024, backupCount=5)
        error_handler.setLevel(logging.ERROR)
        error_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        error_handler.setFormatter(error_formatter)
        Logger._logger.addHandler(error_handler)

logger = Logger.get_logger()
