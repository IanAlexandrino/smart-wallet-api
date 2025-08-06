"""
Decorators para validação de requisições.
"""

from functools import wraps
from flask import request
from werkzeug.exceptions import BadRequest


def validate_json_content_type(f):
    """
    Decorator que valida se o Content-Type da requisição é application/json
    e se o body contém JSON válido.

    Args:
        f: Função a ser decorada

    Returns:
        Função decorada que valida o Content-Type e JSON

    Raises:
        BadRequest: Se Content-Type não for application/json ou JSON inválido
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            raise BadRequest('Content-Type deve ser application/json')

        json_data = request.get_json()
        if not json_data:
            raise BadRequest('Body da requisição deve conter JSON válido')

        return f(*args, **kwargs)
    return decorated_function
