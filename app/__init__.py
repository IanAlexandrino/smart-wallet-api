from flask import Flask
from .routes import register_blueprints
from .config import get_config
from .extensions import db, cors, ma, jwt
from .errors import register_error_handlers
from .models import User
# from flask_swagger_ui import get_swaggerui_blueprint
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

    # Registra os blueprints
    register_blueprints(app)

    # Registra os handlers de erro
    register_error_handlers(app)

    # OpenAPI/SWAGGER
    # if app.config.get('SHOW_SWAGGER'):
    #     SWAGGER_URL = '/dsl-agendamentos/v1/docs'
    #     API_URL = '/static/swagger.yaml'
    #     swagger_bp = get_swaggerui_blueprint(
    #         SWAGGER_URL,
    #         API_URL,
    #         config={'app_name': "DSL Agendamentos API"}
    #     )
    #     app.register_blueprint(swagger_bp, url_prefix=SWAGGER_URL)

    return app
