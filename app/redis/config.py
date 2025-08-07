"""
Configurações Redis SSL para Square Cloud.
Contém funções específicas para configurar conexões Redis com SSL.
"""

import os
import ssl
import redis
from urllib.parse import urlparse
from app.logging_config import get_redis_logger

# Logger específico para este módulo Redis
logger = get_redis_logger('config')


def configure_redis_ssl(app):
    """
    Configura Redis com SSL para Square Cloud.

    Args:
        app: Instância da aplicação Flask

    Returns:
        redis.Redis: Cliente Redis configurado ou None se falhar
    """
    logger.debug("Iniciando configuração Redis SSL")
    redis_url = app.config.get('REDIS_URL')
    if not redis_url:
        logger.warning("REDIS_URL não configurada")
        return None

    try:
        # Parse da URL do Redis
        parsed_url = urlparse(redis_url)
        logger.debug(f"URL Redis parseada: {parsed_url.hostname}:{parsed_url.port}")

        # Configuração SSL
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = app.config.get('REDIS_SSL_CHECK_HOSTNAME', False)
        # Para certificados auto-assinados da Square Cloud
        ssl_context.verify_mode = ssl.CERT_NONE

        # Tenta carregar certificado se existir
        cert_file = app.config.get('REDIS_SSL_CERTFILE')
        if cert_file and os.path.exists(cert_file):
            ssl_context.load_cert_chain(cert_file)
            logger.info(f"Certificado SSL carregado: {cert_file}")

        # Cria conexão Redis com SSL
        redis_client = redis.Redis(
            host=parsed_url.hostname,
            port=parsed_url.port or 6380,  # Porta padrão SSL Redis
            password=parsed_url.password,
            ssl=True,
            # Não verifica certificado (para Square Cloud)
            ssl_cert_reqs=ssl.CERT_NONE,
            ssl_check_hostname=False,
            socket_connect_timeout=10,
            socket_timeout=10,
            retry_on_timeout=True,
            health_check_interval=30
        )

        # Testa a conexão
        redis_client.ping()
        logger.info("Conexão Redis SSL estabelecida com sucesso")

        # Substitui a instância padrão do FlaskRedis
        from app.extensions import redis_store
        redis_store._redis_client = redis_client

        return redis_client

    except Exception as e:
        logger.error(f"Erro ao configurar Redis SSL: {str(e)}")
        return None


def get_redis_ssl_config(app):
    """
    Retorna as configurações SSL do Redis.

    Args:
        app: Instância da aplicação Flask

    Returns:
        dict: Configurações SSL
    """
    return {
        'ssl_cert_reqs': app.config.get('REDIS_SSL_CERT_REQS', 'required'),
        'ssl_check_hostname': app.config.get('REDIS_SSL_CHECK_HOSTNAME', False),
        'ssl_certfile': app.config.get('REDIS_SSL_CERTFILE'),
        'ssl_keyfile': app.config.get('REDIS_SSL_KEYFILE'),
        'ssl_ca_certs': app.config.get('REDIS_SSL_CA_CERTS')
    }
