"""
Error handlers para autenticação JWT
"""
from flask_jwt_extended.exceptions import (
    JWTExtendedException,
    NoAuthorizationError,
    InvalidHeaderError,
    JWTDecodeError,
    CSRFError,
    WrongTokenError
)
from ..responses import error_response
from ..extensions import jwt


def register_jwt_handlers(app):
    """Registra handlers para erros JWT"""

    @app.errorhandler(NoAuthorizationError)
    def handle_no_authorization(err):
        return error_response(
            message="Token de acesso obrigatório.",
            code="TOKEN_REQUIRED",
            status_code=401
        )

    @app.errorhandler(InvalidHeaderError)
    def handle_invalid_header(err):
        return error_response(
            message="Cabeçalho de autorização inválido.",
            code="INVALID_HEADER",
            status_code=401
        )

    @app.errorhandler(JWTDecodeError)
    def handle_decode_error(err):
        return error_response(
            message="Token inválido ou malformado.",
            code="INVALID_TOKEN",
            status_code=401
        )

    @app.errorhandler(WrongTokenError)
    def handle_wrong_token(err):
        return error_response(
            message="Tipo de token incorreto.",
            code="WRONG_TOKEN_TYPE",
            status_code=401
        )

    @app.errorhandler(CSRFError)
    def handle_csrf_error(err):
        return error_response(
            message="Erro de validação CSRF.",
            code="CSRF_ERROR",
            status_code=401
        )

    @app.errorhandler(JWTExtendedException)
    def handle_jwt_exception(err):
        return error_response(
            message="Erro de autenticação.",
            code="AUTH_ERROR",
            status_code=401
        )

    # HANDLERS CUSTOMIZADOS PARA TOKENS REVOGADOS
    @jwt.revoked_token_loader
    def handle_revoked_token(jwt_header, jwt_payload):
        """Handler para tokens que estão na blacklist."""
        return error_response(
            message="Sua sessão expirou ou foi encerrada. Faça login novamente para continuar.",
            code="TOKEN_REVOKED",
            status_code=401
        )

    @jwt.expired_token_loader
    def handle_expired_token(jwt_header, jwt_payload):
        """Handler para tokens expirados."""
        return error_response(
            message="Seu token de acesso expirou. Faça login novamente ou use o refresh token.",
            code="TOKEN_EXPIRED",
            status_code=401
        )

    @jwt.invalid_token_loader
    def handle_invalid_token(error_message):
        """Handler para tokens inválidos."""
        return error_response(
            message="Token de acesso inválido. Verifique se você está logado corretamente.",
            code="INVALID_TOKEN",
            status_code=401
        )

    @jwt.unauthorized_loader
    def handle_unauthorized_callback(error_message):
        """Handler para requisições sem token quando obrigatório."""
        return error_response(
            message="Acesso negado. É necessário estar logado para acessar este recurso.",
            code="LOGIN_REQUIRED",
            status_code=401
        )
