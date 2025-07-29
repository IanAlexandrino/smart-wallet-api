# Lista de todos os blueprints para registro automático
BLUEPRINTS = [

]


def register_blueprints(app):
    """Registra todos os blueprints da aplicação"""
    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)