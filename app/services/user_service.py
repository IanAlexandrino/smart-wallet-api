from typing import Optional, Dict, Any
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_
from werkzeug.exceptions import NotFound, Conflict, BadRequest

from app.extensions import db
from app.models import User
from app.logging_config import get_service_logger

# Logger específico para este serviço
logger = get_service_logger('user_service')


class UserService:
    """Service para operações relacionadas ao usuário"""

    @staticmethod
    def create_user(data: Dict[str, Any]) -> User:
        """
        Cria um novo usuário

        Args:
            data: Dicionário com dados do usuário (já validados)

        Returns:
            User: Usuário criado

        Raises:
            Conflict: Se username ou email já existem
            BadRequest: Se dados inválidos
        """
        try:
            # Verifica se username ou email já existem
            username = data['username'].lower().strip()
            email = data['email'].lower().strip()

            existing_user_by_username = UserService.get_user_by_username(
                username)
            if existing_user_by_username:
                logger.warning(f"Tentativa de criar usuário com username já existente: {username}")
                raise Conflict('Username já está em uso')

            existing_user_by_email = UserService.get_user_by_email(email)
            if existing_user_by_email:
                logger.warning(f"Tentativa de criar usuário com email já existente: {email}")
                raise Conflict('Email já está em uso')

            # Cria o usuário
            user = User(
                username=data['username'].lower().strip(),
                email=data['email'].lower().strip(),
                first_name=data['first_name'].strip().title(),
                last_name=data['last_name'].strip().title(),
                phone=data.get('phone'),
                birth_date=data.get('birth_date')
            )

            # Define a role baseada no request ou 'user' como padrão
            role = data.get('role', 'user')
            user.set_role(role)

            # Define a senha
            user.set_password(data['password'])

            # Log para debug - verifica se role está correto
            logger.debug(f'Usuário criado com role: {user.role} (tipo: {type(user.role)})')

            # Salva no banco
            db.session.add(user)
            db.session.commit()

            logger.info(f"Usuário criado com sucesso: {user.username} (ID: {user.id})")
            return user

        except (Conflict, BadRequest):
            raise
        except IntegrityError:
            db.session.rollback()
            logger.error(f"Erro de integridade ao criar usuário: {data.get('username', 'unknown')}")
            raise BadRequest('Erro de integridade dos dados')
        except ValueError as e:
            logger.error(f"Erro de validação ao criar usuário: {str(e)}")
            raise BadRequest(str(e))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro inesperado ao criar usuário: {str(e)}")
            raise

    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[User]:
        """
        Busca usuário por ID

        Args:
            user_id: ID do usuário

        Returns:
            User ou None se não encontrado
        """
        logger.debug(f"Buscando usuário por ID: {user_id}")
        return db.session.query(User).filter_by(id=user_id, is_active=True).first()

    @staticmethod
    def get_user_by_email(email: str) -> Optional[User]:
        """
        Busca usuário por email

        Args:
            email: Email do usuário

        Returns:
            User ou None se não encontrado
        """
        return db.session.query(User).filter_by(email=email.lower().strip(), is_active=True).first()

    @staticmethod
    def get_user_by_username(username: str) -> Optional[User]:
        """
        Busca usuário por username

        Args:
            username: Username do usuário

        Returns:
            User ou None se não encontrado
        """
        return db.session.query(User).filter_by(username=username.lower().strip(), is_active=True).first()

    @staticmethod
    def update_user(user_id: int, data: Dict[str, Any]) -> User:
        """
        Atualiza dados do usuário

        Args:
            user_id: ID do usuário
            data: Dados para atualizar

        Returns:
            User: Usuário atualizado

        Raises:
            NotFound: Se usuário não encontrado
            BadRequest: Se dados inválidos
        """
        try:
            user = UserService.get_user_by_id(user_id)
            if not user:
                logger.warning(f"Tentativa de atualizar usuário inexistente: {user_id}")
                raise NotFound('Usuário não encontrado')

            # Atualiza campos fornecidos
            for field, value in data.items():
                if hasattr(user, field):
                    setattr(user, field, value)

            db.session.commit()
            logger.info(f"Usuário atualizado com sucesso: {user.username} (ID: {user.id})")
            return user

        except (NotFound, BadRequest):
            raise
        except IntegrityError:
            db.session.rollback()
            logger.error(f"Erro de integridade ao atualizar usuário {user_id}")
            raise BadRequest('Erro de integridade dos dados')
        except ValueError as e:
            logger.error(f"Erro de validação ao atualizar usuário {user_id}: {str(e)}")
            raise BadRequest(str(e))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro inesperado ao atualizar usuário {user_id}: {str(e)}")
            raise

    @staticmethod
    def change_password(user_id: int, current_password: str, new_password: str) -> None:
        """
        Altera senha do usuário

        Args:
            user_id: ID do usuário
            current_password: Senha atual
            new_password: Nova senha

        Raises:
            NotFound: Se usuário não encontrado
            BadRequest: Se senha atual incorreta ou dados inválidos
        """
        try:
            user = UserService.get_user_by_id(user_id)
            if not user:
                logger.warning(f"Tentativa de alterar senha de usuário inexistente: {user_id}")
                raise NotFound('Usuário não encontrado')

            # Verifica senha atual
            if not user.check_password(current_password):
                logger.warning(f"Tentativa de alterar senha com senha atual incorreta para usuário {user_id}")
                raise BadRequest('Senha atual incorreta')

            # Define nova senha
            user.set_password(new_password)
            db.session.commit()

            logger.info(f"Senha alterada com sucesso para usuário {user_id}")

        except (NotFound, BadRequest):
            raise
        except ValueError as e:
            logger.error(f"Erro de validação ao alterar senha do usuário {user_id}: {str(e)}")
            raise BadRequest(str(e))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro inesperado ao alterar senha do usuário {user_id}: {str(e)}")
            raise

    @staticmethod
    def deactivate_user(user_id: int) -> None:
        """
        Desativa usuário (soft delete)

        Args:
            user_id: ID do usuário

        Raises:
            NotFound: Se usuário não encontrado
        """
        try:
            user = UserService.get_user_by_id(user_id)
            if not user:
                logger.warning(f"Tentativa de desativar usuário inexistente: {user_id}")
                raise NotFound('Usuário não encontrado')

            user.delete(soft_delete=True)
            db.session.commit()

            logger.info(f"Usuário desativado com sucesso: {user.username} (ID: {user_id})")

        except NotFound:
            raise
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro inesperado ao desativar usuário {user_id}: {str(e)}")
            raise

    @staticmethod
    def restore_user(user_id: int) -> User:
        """
        Reativa usuário

        Args:
            user_id: ID do usuário

        Returns:
            User: Usuário reativado

        Raises:
            NotFound: Se usuário não encontrado
        """
        try:
            user = db.session.query(User).get(user_id)  # Busca mesmo inativos
            if not user:
                logger.warning(f"Tentativa de restaurar usuário inexistente: {user_id}")
                raise NotFound('Usuário não encontrado')

            user.restore()
            db.session.commit()

            logger.info(f"Usuário restaurado com sucesso: {user.username} (ID: {user_id})")
            return user

        except NotFound:
            raise  # Re-raise HTTP exceptions
        except Exception as e:
            db.session.rollback()
            logger.error(f"Erro inesperado ao restaurar usuário {user_id}: {str(e)}")
            raise  # Propaga o erro original

    @staticmethod
    def get_users_query(search: str = None):
        """
        Retorna query base para busca de usuários

        Args:
            search: Termo de busca (nome, email, username)

        Returns:
            Query: Query SQLAlchemy para usuários ativos com filtros aplicados
        """
        query = db.session.query(User).filter_by(is_active=True)

        # Aplicar busca se fornecida
        if search:
            search_term = f'%{search}%'
            query = query.filter(
                or_(
                    User.first_name.ilike(search_term),
                    User.last_name.ilike(search_term),
                    User.email.ilike(search_term),
                    User.username.ilike(search_term)
                )
            )

        return query

    @staticmethod
    def get_all_users(search: str = None, role: str = None):
        """
        Retorna query para busca de usuários ativos com filtros opcionais

        Args:
            search: Termo de busca (nome, email, username)
            role: Filtro por role ('admin' ou 'user')

        Returns:
            Query: Query SQLAlchemy configurada com filtros e ordenação
        """
        logger.debug(f"Preparando query para usuários com filtros - search: {search}, role: {role}")

        # Inicia com query base
        query = UserService.get_users_query(search=search)

        # Aplica filtro por role se fornecido
        if role:
            query = query.filter_by(role=role)

        # Ordena por nome (A-Z)
        query = query.order_by(User.first_name.asc(), User.last_name.asc())

        return query
