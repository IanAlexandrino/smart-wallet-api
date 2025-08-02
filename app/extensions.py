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

        # Configura SSL se necessário
        if app.config.get('REDIS_URL') and 'squareweb.app' in app.config.get('REDIS_URL', ''):
            try:
                from .redis import configure_redis_ssl
                configure_redis_ssl(app)
            except Exception as e:
                app.logger.warning(f"Configuração SSL Redis falhou: {str(e)}")


db = SQLAlchemy()
cors = CORS()
ma = Marshmallow()
jwt = JWTManager()
redis_store = FlaskRedisSSL()  # Usando nossa classe customizada
