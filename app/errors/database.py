"""
Error handlers para banco de dados
"""
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from ..responses import error_response


def register_database_handlers(app):
    """Registra handlers para erros de banco de dados"""

    @app.errorhandler(NoResultFound)
    def handle_no_result(err):
        return error_response(
            message="Registro não encontrado.",
            code="NOT_FOUND",
            status_code=404
        )

    @app.errorhandler(IntegrityError)
    def handle_integrity_error(err):
        return error_response(
            message="Erro de integridade no banco de dados.",
            code="INTEGRITY_ERROR",
            status_code=409,
            errors=str(err.orig)
        )
