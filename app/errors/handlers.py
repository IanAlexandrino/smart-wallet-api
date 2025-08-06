"""
Error handlers para requisições HTTP e validação
"""
from marshmallow import ValidationError
from werkzeug.exceptions import (
    BadRequest,
    NotFound,
    HTTPException,
    Unauthorized,
    Forbidden,
    MethodNotAllowed,
    Conflict,
    ServiceUnavailable
)
from flask_jwt_extended.exceptions import JWTDecodeError
from jwt.exceptions import DecodeError  # Exceção do PyJWT
from ..responses import error_response


def register_http_handlers(app):
    """Registra handlers para erros HTTP básicos"""

    @app.errorhandler(ValidationError)
    def handle_validation_error(err):
        return error_response(
            message="Dados de entrada inválidos.",
            code="INVALID_DATA",
            status_code=400,
            errors=err.messages
        )

    @app.errorhandler(ValueError)
    def handle_value_error(err):
        return error_response(
            message=str(err),
            code="INVALID_OPERATION",
            status_code=400
        )

    @app.errorhandler(BadRequest)
    def handle_bad_request(err):
        return error_response(
            message=err.description or "Requisição inválida.",
            code="BAD_REQUEST",
            status_code=400
        )

    @app.errorhandler(Unauthorized)
    def handle_unauthorized(err):
        return error_response(
            message=err.description or "Acesso não autorizado.",
            code="UNAUTHORIZED",
            status_code=401
        )

    @app.errorhandler(JWTDecodeError)
    def handle_jwt_decode_error(err):
        """Handler específico para erros de decodificação JWT (Flask-JWT-Extended)"""
        error_msg = str(err).lower()

        # Mapeia tipos específicos de erro JWT para mensagens user-friendly
        if "not enough segments" in error_msg:
            message = "Refresh token inválido ou malformado. Faça login novamente."
        elif "invalid payload" in error_msg or "expecting value" in error_msg:
            message = "Refresh token corrompido. Faça login novamente."
        elif "signature" in error_msg:
            message = "Refresh token com assinatura inválida. Faça login novamente."
        elif "expired" in error_msg:
            message = "Refresh token expirado. Faça login novamente."
        else:
            message = "Refresh token inválido. Faça login novamente."

        return error_response(
            message=message,
            code="UNAUTHORIZED",
            status_code=401
        )

    @app.errorhandler(DecodeError)
    def handle_decode_error(err):
        """Handler específico para erros de decodificação JWT (PyJWT)"""
        error_msg = str(err).lower()

        # Mapeia tipos específicos de erro PyJWT para mensagens user-friendly
        if "not enough segments" in error_msg:
            message = "Refresh token inválido ou malformado. Faça login novamente."
        elif "invalid payload" in error_msg or "expecting value" in error_msg:
            message = "Refresh token corrompido. Faça login novamente."
        elif "signature" in error_msg:
            message = "Refresh token com assinatura inválida. Faça login novamente."
        elif "expired" in error_msg:
            message = "Refresh token expirado. Faça login novamente."
        else:
            message = "Refresh token inválido. Faça login novamente."

        return error_response(
            message=message,
            code="UNAUTHORIZED",
            status_code=401
        )

    @app.errorhandler(Forbidden)
    def handle_forbidden(err):
        return error_response(
            message=err.description or "Acesso proibido.",
            code="FORBIDDEN",
            status_code=403
        )

    @app.errorhandler(NotFound)
    def handle_not_found(err):
        return error_response(
            message=err.description or "Recurso não encontrado.",
            code="NOT_FOUND",
            status_code=404
        )

    @app.errorhandler(MethodNotAllowed)
    def handle_method_not_allowed(err):
        return error_response(
            message=f"Método não permitido. Métodos válidos: {', '.join(err.valid_methods)}.",
            code="METHOD_NOT_ALLOWED",
            status_code=405
        )

    @app.errorhandler(Conflict)
    def handle_conflict(err):
        return error_response(
            message=err.description or "Conflito de dados.",
            code="CONFLICT",
            status_code=409
        )

    @app.errorhandler(ServiceUnavailable)
    def handle_service_unavailable(err):
        return error_response(
            message=err.description or "Serviço temporariamente indisponível.",
            code="SERVICE_UNAVAILABLE",
            status_code=503
        )

    @app.errorhandler(FileNotFoundError)
    def handle_file_not_found_error(err):
        return error_response(
            message=str(err),
            code="FILE_NOT_FOUND",
            status_code=500
        )

    @app.errorhandler(Exception)
    def handle_unexpected_error(err):
        if isinstance(err, HTTPException):
            raise err
        app.logger.exception(err)
        return error_response(
            message="Erro interno. Tente novamente mais tarde.",
            code="INTERNAL_SERVER_ERROR",
            status_code=500
        )
