# Importa todos os blueprints
from .auth import auth_bp
from .users import users_bp

# Lista de todos os blueprints para registro automático
BLUEPRINTS = [
    auth_bp,
    users_bp,
]


def register_blueprints(app):
    """Registra todos os blueprints da aplicação"""
    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)
