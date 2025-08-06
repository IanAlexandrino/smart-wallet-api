"""
Decoradores personalizados para autenticação e autorização.
"""

from functools import wraps
from flask_jwt_extended import jwt_required
from werkzeug.exceptions import Unauthorized, Forbidden

from app.services.auth_service import AuthService


def auth_required(optional: bool = False):
    """
    Decorator que requer autenticação JWT.

    Args:
        optional: Se True, não falha se token não estiver presente
    """
    def decorator(f):
        @wraps(f)
        @jwt_required(optional=optional)
        def decorated_function(*args, **kwargs):
            if not optional:
                # Valida se token e usuário são válidos
                if not AuthService.validate_token_claims():
                    raise Unauthorized("Token inválido ou usuário não encontrado")
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def role_required(*allowed_roles):
    """
    Decorator que requer um ou mais roles específicos.

    Args:
        *allowed_roles: Roles permitidos (UserRole enums)
    """
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user = AuthService.get_current_user()

            if not current_user:
                raise Unauthorized("Token inválido ou usuário não encontrado")

            # Admin sempre tem acesso
            if current_user.is_admin:
                return f(*args, **kwargs)

            # Verifica se usuário tem algum dos roles permitidos
            if current_user.role not in allowed_roles:
                raise Forbidden("Acesso negado. Role insuficiente")

            return f(*args, **kwargs)
        return decorated_function
    return decorator
