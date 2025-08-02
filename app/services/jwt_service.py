"""
Serviço JWT completo com Redis blacklist.
Implementa access tokens, refresh tokens e gerenciamento de blacklist.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Any
from flask import current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_jwt,
    get_jwt_identity,
)
from ..extensions import redis_store
from ..models.user import User
from ..utils import now_br


class JWTService:
    """Serviço para gerenciamento completo de JWTs."""

    # Prefixo para blacklist no Redis
    BLACKLIST_PREFIX = "jwt_blacklist:"

    @staticmethod
    def _redis_operation_safe(operation, *args, fallback_result=None, **kwargs):
        """
        Executa operação Redis com tratamento de erro básico.

        Args:
            operation: Função Redis a ser executada
            *args: Argumentos da função
            fallback_result: Resultado retornado se a operação falhar
            **kwargs: Argumentos nomeados da função

        Returns:
            Resultado da operação ou fallback_result
        """
        try:
            return operation(*args, **kwargs)
        except Exception as e:
            current_app.logger.error(f"Erro na operação Redis: {str(e)}")
            return fallback_result

    @staticmethod
    def create_tokens(user_id: int, additional_claims: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Cria access token e refresh token para um usuário.

        Args:
            user_id: ID do usuário
            additional_claims: Claims adicionais para incluir no token

        Returns:
            Dict contendo access_token, refresh_token e metadados
        """
        # Claims padrão
        claims = {
            "user_id": user_id,    # ID do usuário para fácil acesso
            "type": "access"       # Tipo do token para validação
        }

        # Adiciona claims extras se fornecidos
        if additional_claims:
            claims.update(additional_claims)

        # Cria os tokens
        access_token = create_access_token(
            identity=str(user_id),  # Converte para string
            additional_claims=claims
        )

        refresh_claims = {
            "user_id": user_id,    # ID do usuário para fácil acesso
            "type": "refresh"      # Tipo do token para validação
        }

        refresh_token = create_refresh_token(
            identity=str(user_id),  # Converte para string
            additional_claims=refresh_claims
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()),
            "refresh_expires_in": int(current_app.config['JWT_REFRESH_TOKEN_EXPIRES'].total_seconds())
        }

    @staticmethod
    def refresh_access_token(refresh_token: str) -> Dict[str, Any]:
        """
        Cria um novo access token usando refresh token.

        Args:
            refresh_token: Refresh token válido

        Returns:
            Dict contendo novo access_token e metadados

        Raises:
            ValueError: Se refresh token for inválido ou rate limit atingido
        """
        try:
            # Decodifica o refresh token
            decoded_token = decode_token(refresh_token)
            user_id = int(decoded_token['sub'])  # Converte de volta para int
            jti = decoded_token['jti']

            # Verifica rate limiting
            can_refresh, rate_limit_error = JWTService.can_refresh_token(
                user_id)
            if not can_refresh:
                raise ValueError(rate_limit_error)

            # Verifica se o refresh token está na blacklist
            if JWTService.is_token_blacklisted(jti):
                raise ValueError("Refresh token foi revogado")

            # Verifica se todos os tokens do usuário foram revogados
            token_iat = decoded_token.get('iat', 0)
            if JWTService.is_user_tokens_revoked(user_id, token_iat):
                raise ValueError(
                    "Refresh token foi revogado (revogação em massa)")

            # Incrementa contador de refresh
            JWTService.increment_refresh_count(user_id)

            # Cria novo access token
            claims = {
                "user_id": user_id,
                "type": "access",
                "refreshed_from": jti  # Indica que foi criado via refresh
            }

            new_access_token = create_access_token(
                identity=str(user_id),  # Converte para string
                additional_claims=claims
            )

            return {
                "access_token": new_access_token,
                "token_type": "Bearer",
                "expires_in": int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
            }

        except Exception as e:
            raise ValueError(f"Erro ao renovar token: {str(e)}")

    @staticmethod
    def revoke_token(jti: str, token_type: str = "access") -> bool:
        """
        Adiciona um token à blacklist.

        Args:
            jti: JWT ID do token
            token_type: Tipo do token (access ou refresh)

        Returns:
            True se o token foi adicionado à blacklist com sucesso
        """
        try:
            # Calcula tempo de expiração baseado no tipo do token
            if token_type == "refresh":
                expires_delta = current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
            else:
                expires_delta = current_app.config['JWT_ACCESS_TOKEN_EXPIRES']

            # Dados para armazenar na blacklist
            blacklist_data = json.dumps({
                "revoked_at": now_br("isoformat"),
                "type": token_type
            })

            # Adiciona à blacklist com expiração automática
            blacklist_key = f"{JWTService.BLACKLIST_PREFIX}{jti}"
            result = JWTService._redis_operation_safe(
                redis_store.setex,
                blacklist_key,
                int(expires_delta.total_seconds()),
                blacklist_data,
                fallback_result=False
            )

            if result is not False:
                current_app.logger.info(
                    f"Token {jti} ({token_type}) adicionado à blacklist")
                return True
            else:
                current_app.logger.warning(
                    f"Falha ao adicionar token {jti} à blacklist (Redis indisponível)")
                return False

        except Exception as e:
            current_app.logger.error(f"Erro ao revogar token {jti}: {str(e)}")
            return False

    @staticmethod
    def is_token_blacklisted(jti: str) -> bool:
        """
        Verifica se um token está na blacklist.

        Args:
            jti: JWT ID do token

        Returns:
            True se o token estiver na blacklist, False caso contrário

        Note:
            Se o Redis estiver indisponível, assume que o token NÃO está na blacklist
            para evitar bloquear usuários com tokens válidos.
        """
        try:
            blacklist_key = f"{JWTService.BLACKLIST_PREFIX}{jti}"

            # Verifica se existe na blacklist
            result = JWTService._redis_operation_safe(
                redis_store.exists,
                blacklist_key,
                fallback_result=False  # Se falhar, assume que NÃO está na blacklist
            )

            if result:
                current_app.logger.info(f"Token {jti} encontrado na blacklist")
            else:
                current_app.logger.debug(
                    f"Token {jti} não está na blacklist (ou Redis indisponível)")

            return bool(result)

        except Exception as e:
            current_app.logger.error(
                f"Erro ao verificar blacklist para token {jti}: {str(e)}")
            # Em caso de erro, assume que o token NÃO está na blacklist
            # Isso evita bloquear usuários com tokens válidos quando o Redis está com problemas
            return False

    @staticmethod
    def get_current_user_id() -> Optional[int]:
        """
        Obtém o ID do usuário atual do token JWT em contexto.
        Deve ser usado dentro de uma rota protegida por @jwt_required.

        Returns:
            ID do usuário ou None se não conseguir obter
        """
        try:
            user_id = get_jwt_identity()
            return int(user_id) if user_id else None
        except Exception as e:
            current_app.logger.error(f"Erro ao obter ID do usuário: {str(e)}")
            return None

    @staticmethod
    def get_current_token_claims() -> Optional[Dict]:
        """
        Obtém os claims do token atual.
        Deve ser usado dentro de uma rota protegida por @jwt_required.

        Returns:
            Dict com claims do token ou None se não conseguir obter
        """
        try:
            return get_jwt()
        except Exception as e:
            current_app.logger.error(
                f"Erro ao obter claims do token: {str(e)}")
            return None

    @staticmethod
    def get_token_info(token: str) -> Optional[Dict]:
        """
        Obtém informações de um token.

        Args:
            token: Token JWT

        Returns:
            Dict com informações do token ou None se inválido
        """
        try:
            decoded = decode_token(token)

            return {
                "jti": decoded.get("jti"),
                "user_id": decoded.get("sub"),
                "type": decoded.get("type", "access"),
                "issued_at": datetime.fromtimestamp(decoded.get("iat", 0)),
                "expires_at": datetime.fromtimestamp(decoded.get("exp", 0)),
                "is_blacklisted": JWTService.is_token_blacklisted(decoded.get("jti"))
            }

        except Exception as e:
            current_app.logger.error(
                f"Erro ao obter informações do token: {str(e)}")
            return None

    @staticmethod
    def revoke_all_user_tokens(user_id: int) -> bool:
        """
        Revoga todos os tokens de um usuário específico.
        Útil para logout forçado de todos os dispositivos.

        Args:
            user_id: ID do usuário

        Returns:
            True se a operação foi bem-sucedida
        """
        try:
            # Cria chave para blacklist global do usuário
            user_blacklist_key = f"user_blacklist:{user_id}"

            # Armazena timestamp de revogação
            revocation_data = json.dumps({
                "revoked_at": now_br("isoformat"),
                "reason": "all_tokens_revoked"
            })

            # Define expiração para o maior tempo possível entre access e refresh
            max_expire = max(
                current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
                current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
            )

            result = JWTService._redis_operation_safe(
                redis_store.setex,
                user_blacklist_key,
                int(max_expire.total_seconds()),
                revocation_data,
                fallback_result=False
            )

            if result is not False:
                current_app.logger.info(
                    f"Todos os tokens do usuário {user_id} foram revogados")
                return True
            else:
                current_app.logger.warning(
                    f"Falha ao revogar tokens do usuário {user_id}")
                return False

        except Exception as e:
            current_app.logger.error(
                f"Erro ao revogar tokens do usuário {user_id}: {str(e)}")
            return False

    @staticmethod
    def is_user_tokens_revoked(user_id: int, token_iat: int) -> bool:
        """
        Verifica se todos os tokens do usuário foram revogados após determinado timestamp.

        Args:
            user_id: ID do usuário
            token_iat: Timestamp de criação do token

        Returns:
            True se os tokens do usuário foram revogados após a criação do token
        """
        try:
            user_blacklist_key = f"user_blacklist:{user_id}"

            result = JWTService._redis_operation_safe(
                redis_store.get,
                user_blacklist_key,
                fallback_result=None
            )

            if not result:
                return False

            revocation_data = json.loads(result)
            revoked_at = datetime.fromisoformat(revocation_data["revoked_at"])
            token_created_at = datetime.fromtimestamp(token_iat)

            # Se o token foi criado antes da revogação, está inválido
            return token_created_at < revoked_at

        except Exception as e:
            current_app.logger.error(
                f"Erro ao verificar revogação do usuário {user_id}: {str(e)}")
            return False

    @staticmethod
    def cleanup_expired_tokens() -> int:
        """
        Remove tokens expirados da blacklist (limpeza manual).
        O Redis já faz isso automaticamente com TTL, mas pode ser útil para estatísticas.

        Returns:
            Número de tokens removidos
        """
        try:
            pattern = f"{JWTService.BLACKLIST_PREFIX}*"
            keys = redis_store.keys(pattern)

            removed = 0
            for key in keys:
                # Verifica se a chave ainda existe (pode ter expirado entre keys() e get())
                if not redis_store.exists(key):
                    removed += 1

            return removed

        except Exception as e:
            current_app.logger.error(f"Erro na limpeza de tokens: {str(e)}")
            return 0

    @staticmethod
    def get_blacklist_stats() -> Dict[str, Any]:
        """
        Obtém estatísticas da blacklist.

        Returns:
            Dict com estatísticas dos tokens na blacklist
        """
        try:
            pattern = f"{JWTService.BLACKLIST_PREFIX}*"
            keys = redis_store.keys(pattern)

            stats = {
                "total_blacklisted": len(keys),
                "access_tokens": 0,
                "refresh_tokens": 0,
                "user_revocations": 0,
                "oldest_token": None,
                "newest_token": None
            }

            timestamps = []

            for key in keys:
                try:
                    data = redis_store.get(key)
                    if data:
                        token_data = json.loads(data)
                        token_type = token_data.get("type", "unknown")

                        if token_type == "access":
                            stats["access_tokens"] += 1
                        elif token_type == "refresh":
                            stats["refresh_tokens"] += 1
                        elif "user_blacklist:" in key.decode() if isinstance(key, bytes) else key:
                            stats["user_revocations"] += 1

                        # Coleta timestamps para estatísticas de tempo
                        revoked_at = token_data.get("revoked_at")
                        if revoked_at:
                            timestamps.append(revoked_at)

                except Exception:
                    continue

            # Estatísticas de tempo
            if timestamps:
                timestamps.sort()
                stats["oldest_token"] = timestamps[0]
                stats["newest_token"] = timestamps[-1]

            return stats

        except Exception as e:
            current_app.logger.error(f"Erro ao obter estatísticas: {str(e)}")
            return {
                "error": str(e),
                "total_blacklisted": 0,
                "access_tokens": 0,
                "refresh_tokens": 0,
                "user_revocations": 0
            }


# Callback para verificar se token está na blacklist
def check_if_token_revoked(jwt_header, jwt_payload):
    """Callback do Flask-JWT-Extended para verificar tokens revogados."""
    jti = jwt_payload['jti']
    user_id = int(jwt_payload['sub'])
    token_iat = jwt_payload.get('iat', 0)

    # Verifica blacklist individual do token
    if JWTService.is_token_blacklisted(jti):
        return True

    # Verifica se todos os tokens do usuário foram revogados
    return JWTService.is_user_tokens_revoked(user_id, token_iat)
