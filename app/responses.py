from flask import has_app_context, make_response, current_app
from typing import Dict, Any, Optional, Union, List
from collections import OrderedDict
import json
from decimal import Decimal
from .utils import now_br


class DecimalEncoder(json.JSONEncoder):
    """Encoder customizado para serializar objetos Decimal"""

    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)


class APIResponse:
    """Classe para padronizar respostas da API"""

    @staticmethod
    def _create_response(payload: dict, status_code: int) -> tuple:
        """
        Cria uma resposta HTTP, verificando se está dentro do contexto do Flask

        Args:
            payload: Dados da resposta
            status_code: Código de status HTTP

        Returns:
            tuple: (response, status_code)
        """
        if has_app_context():
            # Dentro do contexto do Flask - cria resposta customizada preservando ordem
            json_data = json.dumps(
                payload, ensure_ascii=False, separators=(',', ':'), cls=DecimalEncoder)
            response = make_response(json_data, status_code)
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
            return response
        else:
            # Fora do contexto do Flask - retorna dict simples para testes
            return payload, status_code

    @staticmethod
    def success(
        message: str = "Operação realizada com sucesso",
        data: Optional[Union[Dict, List, Any]] = None,
        status_code: int = 200,
        meta: Optional[Dict] = None
    ) -> tuple:
        """
        Resposta de sucesso padrão

        Args:
            message: Mensagem de sucesso
            data: Dados a serem retornados
            status_code: Código de status HTTP
            meta: Metadados adicionais (paginação, etc.)

        Returns:
            tuple: (response, status_code)
        """
        payload = OrderedDict([
            ("status", "success"),
            ("message", message)
        ])

        # Adiciona data logo após message se existir
        if data is not None:
            payload["data"] = data

        # Timestamp sempre após os dados principais
        payload["timestamp"] = now_br().isoformat()

        # Meta por último (paginação, etc.)
        if meta is not None:
            payload["meta"] = meta

        return APIResponse._create_response(payload, status_code)

    @staticmethod
    def created(
        message: str = "Recurso criado com sucesso",
        data: Optional[Union[Dict, List, Any]] = None,
        resource_id: Optional[Union[str, int]] = None
    ) -> tuple:
        """
        Resposta para recursos criados (POST)

        Args:
            message: Mensagem de sucesso
            data: Dados do recurso criado
            resource_id: ID do recurso criado

        Returns:
            tuple: (response, status_code)
        """
        payload = OrderedDict([
            ("status", "success"),
            ("message", message)
        ])

        # Adiciona data logo após message se existir
        if data is not None:
            payload["data"] = data

        # Timestamp sempre após os dados principais
        payload["timestamp"] = now_br().isoformat()

        # Resource ID por último
        if resource_id is not None:
            payload["resource_id"] = resource_id

        return APIResponse._create_response(payload, 201)

    @staticmethod
    def updated(
        message: str = "Recurso atualizado com sucesso",
        data: Optional[Union[Dict, List, Any]] = None
    ) -> tuple:
        """
        Resposta para recursos atualizados (PUT/PATCH)

        Args:
            message: Mensagem de sucesso
            data: Dados atualizados do recurso

        Returns:
            tuple: (response, status_code)
        """
        return APIResponse.success(message, data, 200)

    @staticmethod
    def deleted(
        message: str = "Recurso removido com sucesso",
        resource_id: Optional[Union[str, int]] = None
    ) -> tuple:
        """
        Resposta para recursos deletados (DELETE)

        Args:
            message: Mensagem de sucesso
            resource_id: ID do recurso removido

        Returns:
            tuple: (response, status_code)
        """
        payload = OrderedDict([
            ("status", "success"),
            ("message", message),
            ("timestamp", now_br().isoformat())
        ])

        # Resource ID por último
        if resource_id is not None:
            payload["resource_id"] = resource_id

        return APIResponse._create_response(payload, 200)

    @staticmethod
    def no_content(message: str = "Operação realizada com sucesso") -> tuple:
        """
        Resposta sem conteúdo (204)

        Args:
            message: Mensagem de sucesso

        Returns:
            tuple: (response, status_code)
        """
        return APIResponse._create_response(OrderedDict([
            ("status", "success"),
            ("message", message),
            ("timestamp", now_br().isoformat())
        ]), 204)

    @staticmethod
    def paginated(
        data: List,
        page: int,
        per_page: int,
        total: int,
        message: str = "Dados obtidos com sucesso"
    ) -> tuple:
        """
        Resposta paginada para listagens

        Args:
            data: Lista de dados
            page: Página atual
            per_page: Itens por página
            total: Total de itens
            message: Mensagem de sucesso

        Returns:
            tuple: (response, status_code)
        """
        total_pages = (total + per_page - 1) // per_page
        has_next = page < total_pages
        has_prev = page > 1

        meta = {
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": total_pages,
                "has_next": has_next,
                "has_prev": has_prev
            }
        }

        return APIResponse.success(message, data, 200, meta)

    @staticmethod
    def custom(
        status: str,
        message: str,
        status_code: int = 200,
        **kwargs
    ) -> tuple:
        """
        Resposta customizada para casos específicos

        Args:
            status: Status da resposta
            message: Mensagem
            status_code: Código de status HTTP
            **kwargs: Dados adicionais

        Returns:
            tuple: (response, status_code)
        """
        payload = OrderedDict([
            ("status", status),
            ("message", message)
        ])

        # Adiciona campos extras (pode incluir data) antes do timestamp
        payload.update(kwargs)

        # Timestamp sempre por último
        payload["timestamp"] = now_br().isoformat()

        return APIResponse._create_response(payload, status_code)

    @staticmethod
    def error(
        message: str,
        code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = 500,
        errors: Optional[Union[Dict, List, str]] = None,
        details: Optional[str] = None
    ) -> tuple:
        """
        Resposta de erro padrão

        Args:
            message: Mensagem de erro
            code: Código específico do erro
            status_code: Código de status HTTP
            errors: Detalhes específicos do erro (opcional)
            details: Detalhes adicionais do erro (opcional)

        Returns:
            tuple: (response, status_code)

        Note:
            Timestamp é automaticamente incluído no fuso horário brasileiro (UTC-3)
        """
        payload = OrderedDict([
            ("status", "error"),
            ("code", code),
            ("message", message)
        ])

        # Adiciona errors se existir
        if errors is not None:
            payload["errors"] = errors

        # Adiciona details se existir
        if details is not None:
            payload["details"] = details

        # Timestamp sempre por último
        payload["timestamp"] = now_br().isoformat()

        return APIResponse._create_response(payload, status_code)


# Aliases para facilitar o uso
def success_response(*args, **kwargs):
    """Alias para APIResponse.success()"""
    return APIResponse.success(*args, **kwargs)


def created_response(*args, **kwargs):
    """Alias para APIResponse.created()"""
    return APIResponse.created(*args, **kwargs)


def updated_response(*args, **kwargs):
    """Alias para APIResponse.updated()"""
    return APIResponse.updated(*args, **kwargs)


def deleted_response(*args, **kwargs):
    """Alias para APIResponse.deleted()"""
    return APIResponse.deleted(*args, **kwargs)


def no_content_response(*args, **kwargs):
    """Alias para APIResponse.no_content()"""
    return APIResponse.no_content(*args, **kwargs)


def paginated_response(*args, **kwargs):
    """Alias para APIResponse.paginated()"""
    return APIResponse.paginated(*args, **kwargs)


def error_response(*args, **kwargs):
    """Alias para APIResponse.error()"""
    return APIResponse.error(*args, **kwargs)


def custom_response(*args, **kwargs):
    """Alias para APIResponse.custom()"""
    return APIResponse.custom(*args, **kwargs)