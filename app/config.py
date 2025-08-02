import secrets
import os
from datetime import timedelta
from dotenv import load_dotenv

# Carregar variáveis do .env
load_dotenv()

# Detecta o ambiente: 'development', 'production' ou 'homologation'
env = os.getenv('FLASK_ENV', 'development').lower()


class BaseConfig:
    # Database
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_HEADER_TYPE = 'Bearer'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

    # Redis
    REDIS_URL = os.getenv('REDIS_URL')

    # Redis SSL Configuration (para Square Cloud)
    REDIS_SSL_CERT_REQS = 'required'
    REDIS_SSL_CA_CERTS = None  # Usa certificados do sistema
    
    # Caminho do arquivo de certificado SSL configurável via variável de ambiente, com fallback
    _default_certfile = os.path.join(os.path.dirname(__file__), 'redis', 'ssl', 'certificate.pem')
    _certfile_env = os.getenv('REDIS_SSL_CERTFILE', _default_certfile)
    if _certfile_env and not os.path.isfile(_certfile_env):
        import warnings
        warnings.warn(f"REDIS_SSL_CERTFILE '{_certfile_env}' não existe. As operações SSL podem falhar.")
        REDIS_SSL_CERTFILE = None
    else:
        REDIS_SSL_CERTFILE = _certfile_env
    
    # Caminho do arquivo de chave SSL configurável por meio de variável de ambiente, com fallback  
    _default_keyfile = os.path.join(os.path.dirname(__file__), 'redis', 'ssl', 'certificate.pem')
    _keyfile_env = os.getenv('REDIS_SSL_KEYFILE', _default_keyfile)
    if _keyfile_env and not os.path.isfile(_keyfile_env):
        import warnings
        warnings.warn(f"REDIS_SSL_KEYFILE '{_keyfile_env}' não existe. As operações SSL podem falhar.")
        REDIS_SSL_KEYFILE = None
    else:
        REDIS_SSL_KEYFILE = _keyfile_env
        
    REDIS_SSL_CHECK_HOSTNAME = False  # Square Cloud usa certificado wildcard

    # Swagger/OpenAPI
    SHOW_SWAGGER = False


class DevelopmentConfig(BaseConfig):
    # Secret key gerada automaticamente
    SECRET_KEY = secrets.token_hex(32)
    # Nível de debuging
    DEBUG = True
    # Habilita visualização da swagger.ui em desenvolvimento
    SHOW_SWAGGER = True


class HomologationConfig(BaseConfig):
    # Secret key para homologação
    SECRET_KEY = os.getenv('SECRET_KEY_HML')
    # Nível de debuging
    DEBUG = False
    # Banco de homologação configurado no .env (MySQL)
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.getenv('DB_USER_HML')}:{os.getenv('DB_PASS_HML')}"
        f"@{os.getenv('DB_HOST_HML')}:{os.getenv('DB_PORT_HML')}/{os.getenv('DB_NAME_HML')}"
    )
    # Habilita visualização da swagger.ui em homologação
    SHOW_SWAGGER = True


class ProductionConfig(BaseConfig):
    # Secret key para produção
    SECRET_KEY = os.getenv('SECRET_KEY_PRD')
    # Nível de debuging
    DEBUG = False
    # Banco de produção configurado no .env (MySQL)
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.getenv('DB_USER_PRD')}:{os.getenv('DB_PASS_PRD')}"
        f"@{os.getenv('DB_HOST_PRD')}:{os.getenv('DB_PORT_PRD')}/{os.getenv('DB_NAME_PRD')}"
    )
    # Mantém visualização da swagger.ui desativada em produção
    SHOW_SWAGGER = False


def get_config():
    return {
        'production': ProductionConfig,
        'homologation': HomologationConfig,
        'development': DevelopmentConfig
    }.get(env, DevelopmentConfig)
