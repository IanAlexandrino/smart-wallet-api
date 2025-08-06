from flask import Flask
from .routes import register_blueprints
from .config import get_config
from .extensions import db, cors, ma, jwt, redis_store
from .errors import register_error_handlers
from .models import User
from .services.jwt_service import check_if_token_revoked
from .swagger import configure_swagger_ui
import os


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config())

    # Só cria DB SQLite em debug
    if app.config.get('DEBUG'):
        os.makedirs(app.instance_path, exist_ok=True)
        db_file = os.path.join(app.instance_path, 'database.db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_file}"

    # Inicializa as extensões
    db.init_app(app)
    cors.init_app(app)
    jwt.init_app(app)
    ma.init_app(app)
    redis_store.init_app(app)

    # Configura JWT callbacks para blacklist
    jwt.token_in_blocklist_loader(check_if_token_revoked)

    # Registra os blueprints
    register_blueprints(app)

    # Registra os handlers de erro
    register_error_handlers(app)

    # Configura Swagger UI
    configure_swagger_ui(app)

    return app
