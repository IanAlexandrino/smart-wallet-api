"""
Configuração centralizada do sistema de logging.
Sistema prático e estruturado para logs organizados por módulos.
"""

import os
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Optional


class LoggerManager:
    """Gerenciador centralizado de loggers para diferentes módulos."""

    _loggers = {}
    _base_log_dir = None

    @classmethod
    def setup_logging(cls, app) -> None:
        """
        Configura o sistema de logging para a aplicação.

        Args:
            app: Instância do Flask
        """
        # Define o diretório base de logs
        cls._base_log_dir = Path(app.root_path).parent / "logs"
        cls._base_log_dir.mkdir(exist_ok=True)

        # Configura o nível de log baseado no ambiente
        log_level = logging.DEBUG if app.config.get('DEBUG') else logging.INFO

        # Configura o logger raiz da aplicação
        cls._setup_root_logger(app, log_level)

    @classmethod
    def _setup_root_logger(cls, app, log_level: int) -> None:
        """Configura o logger raiz da aplicação Flask."""
        app.logger.setLevel(log_level)

        # Remove handlers existentes
        for handler in app.logger.handlers[:]:
            app.logger.removeHandler(handler)

        # Adiciona apenas o handler do console para o logger raiz
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(cls._get_console_formatter())
        app.logger.addHandler(console_handler)

    @classmethod
    def get_logger(cls, module_name: str, category: str = "general") -> logging.Logger:
        """
        Obtém um logger específico para um módulo.

        Args:
            module_name: Nome do módulo (ex: 'user_service', 'auth_service')
            category: Categoria do módulo (ex: 'services', 'redis')

        Returns:
            Logger configurado para o módulo
        """
        # Se o base_log_dir não foi configurado ainda, use um diretório padrão
        if cls._base_log_dir is None:
            from pathlib import Path
            import os
            # Tenta determinar o diretório do projeto
            project_root = Path(__file__).parent.parent
            cls._base_log_dir = project_root / "logs"
            cls._base_log_dir.mkdir(exist_ok=True)

        logger_key = f"{category}.{module_name}"

        if logger_key not in cls._loggers:
            cls._loggers[logger_key] = cls._create_module_logger(
                module_name, category
            )

        return cls._loggers[logger_key]

    @classmethod
    def _create_module_logger(cls, module_name: str, category: str) -> logging.Logger:
        """
        Cria um logger específico para um módulo.

        Args:
            module_name: Nome do módulo
            category: Categoria do módulo

        Returns:
            Logger configurado
        """
        logger_name = f"smart_wallet.{category}.{module_name}"
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)

        # Evita propagação para o logger raiz
        logger.propagate = False

        # Cria diretório específico da categoria
        category_dir = cls._base_log_dir / category
        category_dir.mkdir(exist_ok=True)

        # Cria diretório específico do módulo
        module_dir = category_dir / module_name
        module_dir.mkdir(exist_ok=True)

        # Configura handlers para o logger (APENAS ARQUIVOS, SEM CONSOLE)
        cls._add_file_handler(logger, module_dir, f"{module_name}.log")
        cls._add_error_handler(logger, module_dir, f"{module_name}_errors.log")

        return logger

    @classmethod
    def _add_file_handler(cls, logger: logging.Logger, log_dir: Path, filename: str) -> None:
        """Adiciona handler para logs gerais com rotação."""
        file_path = log_dir / filename

        # Rotating file handler (10MB, 5 backups)
        file_handler = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(cls._get_file_formatter())
        logger.addHandler(file_handler)

    @classmethod
    def _add_error_handler(cls, logger: logging.Logger, log_dir: Path, filename: str) -> None:
        """Adiciona handler específico para erros."""
        file_path = log_dir / filename

        error_handler = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(cls._get_file_formatter())
        logger.addHandler(error_handler)

    @classmethod
    def _add_console_handler(cls, logger: logging.Logger) -> None:
        """Adiciona handler para console com formatação simples."""
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(cls._get_console_formatter())
        logger.addHandler(console_handler)

    @classmethod
    def _get_file_formatter(cls) -> logging.Formatter:
        """Retorna formatador para arquivos de log."""
        return logging.Formatter(
            fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    @classmethod
    def _get_console_formatter(cls) -> logging.Formatter:
        """Retorna formatador para console."""
        return logging.Formatter(
            fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%H:%M:%S'
        )


# Funções auxiliares para facilitar o uso
def get_service_logger(service_name: str) -> logging.Logger:
    """
    Obtém um logger para um serviço específico.

    Args:
        service_name: Nome do serviço (ex: 'user_service', 'auth_service')

    Returns:
        Logger configurado para o serviço
    """
    return LoggerManager.get_logger(service_name, "services")


def get_redis_logger(module_name: str) -> logging.Logger:
    """
    Obtém um logger para um módulo Redis específico.

    Args:
        module_name: Nome do módulo Redis (ex: 'config', 'health')

    Returns:
        Logger configurado para o módulo Redis
    """
    return LoggerManager.get_logger(module_name, "redis")


def setup_logging(app) -> None:
    """
    Configura o sistema de logging da aplicação.

    Args:
        app: Instância do Flask
    """
    LoggerManager.setup_logging(app)
