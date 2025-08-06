"""
Módulo Redis - Configurações e conexões Redis SSL.
Centraliza toda a lógica relacionada ao Redis.
"""

from .config import configure_redis_ssl
from .health import get_redis_connection_info, test_redis_operations

__all__ = [
    'configure_redis_ssl',
    'get_redis_connection_info',
    'test_redis_operations'
]
