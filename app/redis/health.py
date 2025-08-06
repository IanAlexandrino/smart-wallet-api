"""
Health check e monitoramento Redis.
Funções para verificar status e saúde da conexão Redis.
"""

from flask import current_app


def get_redis_connection_info():
    """
    Obtém informações sobre a conexão Redis atual.

    Returns:
        dict: Informações da conexão Redis
    """
    try:
        from app.extensions import redis_store

        # Tenta fazer ping
        ping_result = redis_store.ping()

        # Obtém informações da conexão
        connection_kwargs = getattr(
            redis_store._redis_client.connection_pool,
            'connection_kwargs',
            {}
        )

        return {
            "connected": ping_result,
            "ssl_enabled": connection_kwargs.get('ssl', False),
            "host": connection_kwargs.get('host', 'unknown'),
            "port": connection_kwargs.get('port', 'unknown'),
            "ssl_check_hostname": connection_kwargs.get('ssl_check_hostname', False),
            "ssl_cert_reqs": connection_kwargs.get('ssl_cert_reqs', 'none')
        }

    except Exception as e:
        current_app.logger.error(f"Erro ao obter informações Redis: {str(e)}")
        return {
            "connected": False,
            "error": str(e)
        }


def test_redis_operations():
    """
    Testa operações básicas do Redis.

    Returns:
        dict: Resultado dos testes
    """
    try:
        from app.extensions import redis_store

        # Teste de ping
        ping_result = redis_store.ping()

        # Teste de SET/GET
        test_key = "health_check_test"
        test_value = "redis_ok"

        redis_store.set(test_key, test_value, ex=10)
        retrieved_value = redis_store.get(test_key)
        redis_store.delete(test_key)

        # Teste de TTL
        ttl_key = "ttl_test"
        redis_store.set(ttl_key, "ttl_value", ex=5)
        ttl_value = redis_store.ttl(ttl_key)
        redis_store.delete(ttl_key)

        return {
            "ping": ping_result,
            "set_get": retrieved_value.decode() if retrieved_value else None,
            "ttl_test": ttl_value > 0,
            "status": "healthy"
        }

    except Exception as e:
        current_app.logger.error(f"Erro no teste Redis: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }


def check_redis_ssl_status():
    """
    Verifica especificamente o status SSL da conexão Redis.

    Returns:
        dict: Status SSL detalhado
    """
    try:
        from app.extensions import redis_store

        # Verifica se o cliente Redis existe
        if not hasattr(redis_store, '_redis_client'):
            return {
                "ssl_configured": False,
                "error": "Cliente Redis não configurado"
            }

        # Obtém informações da conexão
        connection_pool = redis_store._redis_client.connection_pool
        connection_kwargs = getattr(connection_pool, 'connection_kwargs', {})

        ssl_info = {
            "ssl_configured": connection_kwargs.get('ssl', False),
            "ssl_cert_reqs": connection_kwargs.get('ssl_cert_reqs', 'none'),
            "ssl_check_hostname": connection_kwargs.get('ssl_check_hostname', False),
            "health_check_interval": connection_kwargs.get('health_check_interval', 0)
        }

        # Testa a conexão SSL
        if ssl_info["ssl_configured"]:
            ping_result = redis_store.ping()
            ssl_info["ssl_connection_test"] = ping_result

        return ssl_info

    except Exception as e:
        current_app.logger.error(f"Erro ao verificar SSL Redis: {str(e)}")
        return {
            "ssl_configured": False,
            "error": str(e)
        }
