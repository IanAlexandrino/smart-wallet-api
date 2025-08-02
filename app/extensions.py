from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager
from flask_redis import FlaskRedis


class FlaskRedisSSL(FlaskRedis):
    """FlaskRedis customizado com configuração SSL automática."""

    def init_app(self, app, **kwargs):
        """Inicializa Redis com SSL automático para Square Cloud."""
        # Chama a inicialização padrão primeiro
        super().init_app(app, **kwargs)

        # Configura SSL se necessário - flexível por configuração
        redis_url = app.config.get('REDIS_URL', '')
        ssl_required = app.config.get('REDIS_SSL_REQUIRED', False)

        # Auto-detecta Square Cloud ou usa configuração manual
        auto_ssl = 'squareweb.app' in redis_url

        if redis_url and (ssl_required or auto_ssl):
            try:
                from .redis import configure_redis_ssl
                configure_redis_ssl(app)
                if auto_ssl:
                    app.logger.info("SSL auto-configurado para Square Cloud")
                else:
                    app.logger.info("SSL configurado via REDIS_SSL_REQUIRED")
            except Exception as e:
                app.logger.warning(f"Configuração SSL Redis falhou: {str(e)}")


db = SQLAlchemy()
cors = CORS()
ma = Marshmallow()
jwt = JWTManager()
redis_store = FlaskRedisSSL()  # Usando nossa classe customizada
