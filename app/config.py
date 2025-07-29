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
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_HEADER_TYPE = 'Bearer'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

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
