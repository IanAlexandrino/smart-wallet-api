"""
Rotas de autenticação.
"""

from flask import Blueprint, request

from app.schemas.auth import (
    LoginSchema,
    RegisterSchema,
    RefreshTokenSchema,
    UserResponseSchema,
    TokenResponseSchema,
    RegisterResponseSchema,
    RefreshResponseSchema
)
from app.services.auth_service import AuthService
from app.services.jwt_service import JWTService
from app.decorators.auth import auth_required
from app.decorators.validation import validate_json_content_type
from app.responses import success_response


# Criar blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')

# Instanciar schemas
login_schema = LoginSchema()
register_schema = RegisterSchema()
refresh_schema = RefreshTokenSchema()
user_response_schema = UserResponseSchema()
token_response_schema = TokenResponseSchema()
register_response_schema = RegisterResponseSchema()
refresh_response_schema = RefreshResponseSchema()


@auth_bp.route('/register', methods=['POST'])
@validate_json_content_type
def register():
    """Registra um novo usuário no sistema."""
    # Valida dados de entrada
    user_data = register_schema.load(request.json)

    # Valida se senhas coincidem
    register_schema.validate_passwords_match(request.json)

    # Registra usuário
    user, tokens = AuthService.register_user(user_data)

    # Prepara resposta (inclui dados do usuário apenas no registro)
    response_data = register_response_schema.dump({
        **tokens,
        'user': user
    })

    return success_response(
        data=response_data,
        message="Usuário registrado com sucesso",
        status_code=201
    )


@auth_bp.route('/login', methods=['POST'])
@validate_json_content_type
def login():
    """Autentica um usuário com username/email e senha."""
    # Valida dados de entrada
    login_data = login_schema.load(request.json)

    # Autentica usuário
    user, tokens = AuthService.authenticate_user(
        identifier=login_data['identifier'],
        password=login_data['password']
    )

    # Prepara resposta (apenas tokens, sem dados do usuário)
    response_data = token_response_schema.dump(tokens)

    return success_response(
        data=response_data,
        message="Login realizado com sucesso"
    )


@auth_bp.route('/refresh', methods=['POST'])
@validate_json_content_type
def refresh_token():
    """Renova o access token usando refresh token."""
    # Valida dados de entrada
    refresh_data = refresh_schema.load(request.json)

    # Renova token
    new_tokens = JWTService.refresh_access_token(refresh_data['refresh_token'])

    # Prepara resposta
    response_data = refresh_response_schema.dump(new_tokens)

    return success_response(
        data=response_data,
        message="Token renovado com sucesso"
    )


@auth_bp.route('/logout', methods=['POST'])
@auth_required()
def logout():
    """Faz logout do usuário atual revogando todos os seus tokens."""
    AuthService.logout_user(revoke_all_devices=True)

    return success_response(
        message="Logout realizado com sucesso em todos os dispositivos"
    )
