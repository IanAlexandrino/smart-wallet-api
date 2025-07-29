from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from math import ceil
from werkzeug.exceptions import BadRequest


def now_br():
    """Retorna datetime atual no fuso horário do Brasil (UTC-3)"""
    brazil_tz = timezone(timedelta(hours=-3))
    return datetime.now(brazil_tz)


class PaginationHelper:
    """Utilitário para paginação com validações e formatação padronizada"""

    DEFAULT_PAGE = 1
    DEFAULT_PER_PAGE = 20
    MAX_PER_PAGE = 100
    MIN_PER_PAGE = 1

    @staticmethod
    def validate_pagination_params(page: Optional[int] = None, per_page: Optional[int] = None) -> Dict[str, int]:
        """
        Valida e normaliza parâmetros de paginação

        Args:
            page: Número da página (opcional)
            per_page: Itens por página (opcional)

        Returns:
            Dict com page e per_page validados

        Raises:
            BadRequest: Se os parâmetros forem inválidos
        """
        # Normaliza page
        if page is None:
            page = PaginationHelper.DEFAULT_PAGE
        elif page < 1:
            raise BadRequest("Página deve ser um número positivo")

        # Normaliza per_page
        if per_page is None:
            per_page = PaginationHelper.DEFAULT_PER_PAGE
        elif per_page < PaginationHelper.MIN_PER_PAGE:
            raise BadRequest(
                f"Itens por página deve ser no mínimo {PaginationHelper.MIN_PER_PAGE}")
        elif per_page > PaginationHelper.MAX_PER_PAGE:
            raise BadRequest(
                f"Itens por página deve ser no máximo {PaginationHelper.MAX_PER_PAGE}")

        return {
            'page': page,
            'per_page': per_page
        }

    @staticmethod
    def calculate_pagination_info(total_items: int, page: int, per_page: int) -> Dict[str, Any]:
        """
        Calcula informações de paginação

        Args:
            total_items: Total de itens
            page: Página atual
            per_page: Itens por página

        Returns:
            Dict com informações de paginação
        """
        total_pages = ceil(total_items / per_page) if total_items > 0 else 1
        has_prev = page > 1
        has_next = page < total_pages
        offset = (page - 1) * per_page

        return {
            'page': page,
            'per_page': per_page,
            'total_items': total_items,
            'total_pages': total_pages,
            'has_prev': has_prev,
            'has_next': has_next,
            'prev_page': page - 1 if has_prev else None,
            'next_page': page + 1 if has_next else None,
            'offset': offset
        }

    @staticmethod
    def format_paginated_response(items: List[Any], pagination_info: Dict[str, Any],
                                  additional_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Formata resposta paginada seguindo padrão da API

        Retorna formato plano/flat onde:
        - data: contém os itens diretamente
        - pagination: metadados de paginação no primeiro nível
        - outros metadados: no primeiro nível (filter, etc.)

        Args:
            items: Lista de itens da página atual
            pagination_info: Informações de paginação
            additional_data: Dados adicionais (opcional)

        Returns:
            Dict formatado para resposta da API no padrão flat
        """
        response = {
            'data': items,
            'pagination': {
                'page': pagination_info['page'],
                'per_page': pagination_info['per_page'],
                'total_items': pagination_info['total_items'],
                'total_pages': pagination_info['total_pages'],
                'has_prev': pagination_info['has_prev'],
                'has_next': pagination_info['has_next'],
                'prev_page': pagination_info['prev_page'],
                'next_page': pagination_info['next_page']
            }
        }

        # Adiciona dados adicionais se fornecidos
        if additional_data:
            response.update(additional_data)

        return response

    @staticmethod
    def parse_request_pagination_params(request) -> Dict[str, int]:
        """
        Extrai e valida parâmetros de paginação do request Flask

        Args:
            request: Objeto request do Flask

        Returns:
            Dict com page e per_page validados

        Raises:
            BadRequest: Se os parâmetros não puderem ser convertidos ou forem inválidos
        """
        try:
            page = int(request.args.get('page', PaginationHelper.DEFAULT_PAGE))
        except (ValueError, TypeError):
            raise BadRequest("Parâmetro 'page' deve ser um número inteiro")

        try:
            per_page = int(request.args.get(
                'per_page', PaginationHelper.DEFAULT_PER_PAGE))
        except (ValueError, TypeError):
            raise BadRequest("Parâmetro 'per_page' deve ser um número inteiro")

        return PaginationHelper.validate_pagination_params(page, per_page)