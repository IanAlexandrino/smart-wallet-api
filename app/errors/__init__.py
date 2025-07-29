"""
Módulo de tratamento de erros da aplicação
"""

from .handlers import register_http_handlers
from .database import register_database_handlers
from .auth import register_jwt_handlers


def register_error_handlers(app):
    """
    Registra todos os error handlers da aplicação
    """
    register_http_handlers(app)
    register_database_handlers(app)
    register_jwt_handlers(app)

    # Futuramente adicionar:
    # register_custom_handlers(app)
