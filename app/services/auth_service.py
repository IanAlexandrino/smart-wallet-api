"""
Serviço de autenticação completo.
Implementa operações de login, registro, logout e gerenciamento de tokens.
"""

from typing import Dict, Any, Optional, Tuple
from flask import current_app
from flask_jwt_extended import get_jwt
from werkzeug.exceptions import BadRequest, Unauthorized, Conflict, ServiceUnavailable

from app.models.user import User, UserRole
from app.services.user_service import UserService
from app.services.jwt_service import JWTService
from app.utils import now_br


class AuthService:
    """Serviço para operações de autenticação."""

    @staticmethod
    def register_user(user_data: Dict[str, Any]) -> Tuple[User, Dict[str, Any]]:
        """
        Registra um novo usuário no sistema.

        Args:
            user_data: Dados do usuário já validados

        Returns:
            Tuple contendo o usuário criado e os tokens

        Raises:
            Conflict: Se username ou email já existem
            BadRequest: Se dados inválidos
        """
        try:
            # Verifica se usuário já existe
            existing_user = UserService.get_user_by_email(user_data['email'])
            if existing_user:
                raise Conflict('Email já está em uso')

            existing_user = UserService.get_user_by_username(
                user_data['username'])
            if existing_user:
                raise Conflict('Username já está em uso')

            # Cria o usuário
            user = UserService.create_user(user_data)

            # Log para debug - verifica se role foi definido corretamente
            current_app.logger.debug(f"Usuário criado com role: {user.role} (tipo: {type(user.role)})")

            # Gera tokens para o usuário
            tokens = JWTService.create_tokens(
                user_id=user.id,
                additional_claims={
                    'username': user.username,
                    'role': user.role.value
                }
            )

            current_app.logger.info(f"Usuário {user.username} registrado com sucesso")

            return user, tokens

        except (Conflict, BadRequest):
            raise
        except Exception as e:
            current_app.logger.error(f"Erro no registro do usuário: {str(e)}")
            raise BadRequest("Erro interno no registro do usuário")

    @staticmethod
    def authenticate_user(identifier: str, password: str) -> Tuple[User, Dict[str, Any]]:
        """
        Autentica um usuário por username ou email.

        Args:
            identifier: Username ou email do usuário
            password: Senha do usuário

        Returns:
            Tuple contendo o usuário autenticado e os tokens

        Raises:
            Unauthorized: Se credenciais inválidas ou conta bloqueada
            BadRequest: Se muitas tentativas de login
        """
        try:
            # Busca usuário por email ou username
            user = None
            if '@' in identifier:
                user = UserService.get_user_by_email(identifier)
            else:
                user = UserService.get_user_by_username(identifier)

            # Verifica se usuário existe e senha está correta
            if not user or not user.check_password(password):
                raise Unauthorized('Credenciais inválidas')

            # Verifica se usuário está ativo
            if not user.is_active:
                raise Unauthorized('Conta desativada. Entre em contato com o suporte.')

            # Log para debug - verifica se role está correto
            current_app.logger.debug(f"Login para usuário com role: {user.role} (tipo: {type(user.role)})")

            # Claims para o token
            additional_claims = {
                'username': user.username,
                'role': user.role.value
            }

            # Gera tokens
            tokens = JWTService.create_tokens(
                user_id=user.id,
                additional_claims=additional_claims
            )

            current_app.logger.info(f"Login bem-sucedido para usuário {user.username}")

            return user, tokens

        except (Unauthorized, BadRequest):
            raise
        except Exception as e:
            current_app.logger.error(f"Erro na autenticação: {str(e)}")
            raise BadRequest("Erro interno na autenticação")

    @staticmethod
    def logout_user(revoke_all_devices: bool = False) -> None:
        """
        Faz logout do usuário atual.

        Args:
            revoke_all_devices: Se deve revogar tokens de todos os dispositivos

        Raises:
            Unauthorized: Se token atual inválido
            ServiceUnavailable: Se falha na revogação de tokens
        """
        try:
            # Obtém informações do token atual
            current_token = get_jwt()
            user_id = JWTService.get_current_user_id()

            if not user_id or not current_token:
                raise Unauthorized("Token inválido")

            jti = current_token.get('jti')
            token_type = current_token.get('type', 'access')

            # Verifica se o token atual já foi revogado
            if JWTService.is_token_blacklisted(jti):
                current_app.logger.warning(f"Tentativa de logout com token já revogado: {jti}")
                raise Unauthorized("Este token já foi invalidado. Faça login novamente para obter um novo token.")

            # Verifica se todos os tokens do usuário já foram revogados
            token_iat = current_token.get('iat', 0)
            if JWTService.is_user_tokens_revoked(user_id, token_iat):
                current_app.logger.warning(f"Tentativa de logout com token de usuário já revogado: usuário {user_id}")
                raise Unauthorized("Sua sessão foi encerrada em todos os dispositivos. Faça login novamente.")

            if revoke_all_devices:
                # Revoga todos os tokens do usuário
                success = JWTService.revoke_all_user_tokens(user_id)
                if success:
                    current_app.logger.info(f"Logout de todos os dispositivos para usuário {user_id}")
                else:
                    raise ServiceUnavailable("Falha ao revogar tokens de todos os dispositivos")
            else:
                # Revoga apenas o token atual
                success = JWTService.revoke_token(jti, token_type)
                if success:
                    current_app.logger.info(f"Logout do dispositivo atual para usuário {user_id}")
                else:
                    raise ServiceUnavailable("Falha ao revogar token atual")

        except Unauthorized:
            raise
        except ServiceUnavailable:
            raise
        except Exception as e:
            current_app.logger.error(f"Erro no logout: {str(e)}")
            raise ServiceUnavailable("Erro interno no serviço de logout")

    @staticmethod
    def get_current_user() -> Optional[User]:
        """
        Obtém o usuário atual baseado no token JWT.

        Returns:
            Usuário atual ou None se não encontrado
        """
        try:
            user_id = JWTService.get_current_user_id()
            if not user_id:
                return None

            return UserService.get_user_by_id(user_id)

        except Exception as e:
            current_app.logger.error(f"Erro ao obter usuário atual: {str(e)}")
            return None

    @staticmethod
    def get_user_permissions(user: User) -> Dict[str, Any]:
        """
        Obtém permissões do usuário.

        Args:
            user: Usuário

        Returns:
            Dict com permissões do usuário
        """
        permissions = {
            'can_create_users': user.is_admin,
            'can_edit_users': user.is_admin,
            'can_delete_users': user.is_admin,
            'can_view_all_users': user.is_admin,
            'can_manage_settings': user.is_admin,
            'is_admin': user.is_admin,
            'is_regular_user': user.is_regular_user,
            'role': user.role.value
        }

        return permissions

    @staticmethod
    def validate_token_claims(required_role: Optional[UserRole] = None) -> bool:
        """
        Valida claims do token atual.

        Args:
            required_role: Role mínimo requerido

        Returns:
            True se token válido e usuário tem permissão
        """
        try:
            current_token = get_jwt()
            user_id = JWTService.get_current_user_id()

            if not user_id or not current_token:
                return False

            # Verifica se usuário ainda existe e está ativo
            user = UserService.get_user_by_id(user_id)
            if not user or not user.is_active:
                return False

            # Verifica role se especificado
            if required_role:
                if user.role != required_role and not user.is_admin:
                    return False

            return True

        except Exception as e:
            current_app.logger.error(f"Erro ao validar token: {str(e)}")
            return False
