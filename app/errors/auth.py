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
