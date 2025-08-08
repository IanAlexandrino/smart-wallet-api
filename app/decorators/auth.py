"""
Decoradores personalizados para autenticação e autorização.
"""

from functools import wraps
from flask_jwt_extended import jwt_required
from werkzeug.exceptions import Unauthorized, Forbidden, BadRequest

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
        *allowed_roles: Roles permitidos (strings: 'admin', 'user')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = AuthService.get_current_user()

            # Admin sempre tem acesso
            if current_user.is_admin:
                return f(*args, **kwargs)

            # Verifica se usuário tem algum dos roles permitidos
            if current_user.role not in allowed_roles:
                raise Forbidden("Acesso negado. Role insuficiente")

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def own_resource_or_admin_required(user_id_param='user_id'):
    """
    Decorator que permite acesso apenas se:
    - O usuário é admin (pode acessar qualquer recurso), OU
    - O usuário regular está acessando apenas seu próprio recurso

    Args:
        user_id_param: Nome do parâmetro que contém o user_id na rota (padrão: 'user_id')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = AuthService.get_current_user()

            # Admin sempre tem acesso total
            if current_user.is_admin:
                return f(*args, **kwargs)

            # Para usuários regulares, verifica se está acessando próprio recurso
            target_user_id = kwargs.get(user_id_param)
            if target_user_id is None:
                raise BadRequest(f"Parâmetro '{user_id_param}' não encontrado na rota")

            if current_user.id != target_user_id:
                raise Forbidden("Acesso negado. Você só pode acessar seus próprios dados")

            return f(*args, **kwargs)
        return decorated_function
    return decorator
