"""
Rotas para operações de usuários.
"""

from flask import Blueprint, request
from werkzeug.exceptions import NotFound, BadRequest

from app.schemas import (
    UserCreateSchema,
    UserUpdateSchema,
    ChangePasswordSchema,
    UserListQuerySchema,
    UserDetailResponseSchema
)
from app.services.user_service import UserService
from app.decorators.auth import auth_required, role_required, own_resource_or_admin_required
from app.decorators.validation import validate_json_content_type
from app.responses import success_response
from app.utils import PaginationHelper


# Criar blueprint
users_bp = Blueprint('users', __name__, url_prefix='/api/v1/users')

# Instanciar schemas
user_create_schema = UserCreateSchema()
user_update_schema = UserUpdateSchema()
change_password_schema = ChangePasswordSchema()
user_list_query_schema = UserListQuerySchema()
user_response_schema = UserDetailResponseSchema()


@users_bp.route('', methods=['POST'])
@auth_required()
@role_required('admin')
@validate_json_content_type
def create_user():
    """Cria um novo usuário (apenas admins)."""
    # Valida dados de entrada
    user_data = user_create_schema.load(request.json)

    # Cria usuário
    user = UserService.create_user(user_data)

    # Prepara resposta
    response_data = user_response_schema.dump(user)

    return success_response(
        data=response_data,
        message="Usuário criado com sucesso",
        status_code=201
    )


@users_bp.route('', methods=['GET'])
@auth_required()
@role_required('admin')
def list_users():
    """Lista usuários com filtros e paginação."""
    # Filtra apenas os parâmetros que não são de paginação para o schema
    query_args = {k: v for k, v in request.args.items() if k not in ['page', 'per_page']}

    # Valida parâmetros de query para filtros
    query_params = user_list_query_schema.load(query_args)

    # Extrai e valida parâmetros de paginação
    pagination_params = PaginationHelper.parse_request_pagination_params(request)

    # Obtém query configurada do service
    query = UserService.get_all_users(
        search=query_params.get('search'),
        role=query_params.get('role')
    )

    # Aplica paginação na query
    total_count = query.count()
    offset = (pagination_params['page'] - 1) * pagination_params['per_page']
    users = query.offset(offset).limit(pagination_params['per_page']).all()

    # Serializa usuários
    users_data = user_response_schema.dump(users, many=True)

    # Calcula informações de paginação
    pagination_info = PaginationHelper.calculate_pagination_info(
        total_items=total_count,
        page=pagination_params['page'],
        per_page=pagination_params['per_page']
    )

    # Prepara dados adicionais (filtros aplicados)
    additional_data = {}
    if query_params.get('search'):
        additional_data['search'] = query_params['search']
    if query_params.get('role'):
        additional_data['role'] = query_params['role']

    # Formata resposta usando o padrão do PaginationHelper
    response_data = PaginationHelper.format_paginated_response(
        items=users_data,
        pagination_info=pagination_info,
        additional_data=additional_data if additional_data else None
    )

    return success_response(
        data=response_data,
        message="Usuários listados com sucesso"
    )


@users_bp.route('/<int:user_id>', methods=['GET'])
@auth_required()
@own_resource_or_admin_required()
def get_user(user_id):
    """Busca usuário por ID."""
    # Busca usuário
    user = UserService.get_user_by_id(user_id)
    if not user:
        raise NotFound('Usuário não encontrado')

    # Prepara resposta
    response_data = user_response_schema.dump(user)

    return success_response(
        data=response_data,
        message="Usuário encontrado com sucesso"
    )


@users_bp.route('/<int:user_id>', methods=['PATCH'])
@auth_required()
@own_resource_or_admin_required()
@validate_json_content_type
def update_user(user_id):
    """Atualiza dados do usuário."""
    # Valida dados de entrada
    user_data = user_update_schema.load(request.json)

    # Verifica se há dados para atualizar
    if not user_data:
        raise BadRequest('Nenhum dado fornecido para atualização')

    # Atualiza usuário
    user = UserService.update_user(user_id, user_data)

    # Prepara resposta
    response_data = user_response_schema.dump(user)

    return success_response(
        data=response_data,
        message="Usuário atualizado com sucesso"
    )


@users_bp.route('/<int:user_id>/password', methods=['PUT'])
@auth_required()
@own_resource_or_admin_required()
@validate_json_content_type
def change_password(user_id):
    """Altera senha do usuário."""
    # Valida dados de entrada
    password_data = change_password_schema.load(request.json)

    # Altera senha
    UserService.change_password(
        user_id,
        password_data['current_password'],
        password_data['new_password']
    )

    return success_response(
        message="Senha alterada com sucesso"
    )


@users_bp.route('/<int:user_id>', methods=['DELETE'])
@auth_required()
@own_resource_or_admin_required()
def deactivate_user(user_id):
    """Desativa usuário (soft delete)."""
    # Desativa usuário
    UserService.deactivate_user(user_id)

    return success_response(
        message="Usuário desativado com sucesso"
    )


@users_bp.route('/<int:user_id>/restore', methods=['PATCH'])
@auth_required()
@role_required('admin')
def restore_user(user_id):
    """Reativa usuário - apenas admins."""
    # Reativa usuário
    user = UserService.restore_user(user_id)

    # Prepara resposta
    response_data = user_response_schema.dump(user)

    return success_response(
        data=response_data,
        message="Usuário reativado com sucesso"
    )
