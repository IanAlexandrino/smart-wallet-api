"""
Configuração do Swagger UI para documentação da API.
"""
from flask_swagger_ui import get_swaggerui_blueprint


def configure_swagger_ui(app):
    """Configura a documentação Swagger UI."""
    # URLs para documentação
    SWAGGER_URL = '/api/v1/docs'  # URL da interface Swagger UI
    API_URL = '/static/swagger.yaml'  # URL do arquivo de especificação

    # Configuração do Swagger UI
    swagger_bp = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'app_name': "Smart Wallet API",
            'defaultModelsExpandDepth': 3,
            'defaultModelExpandDepth': 3,
            'docExpansion': 'list',
            'validatorUrl': None,
            'persistAuthorization': True,
            'displayRequestDuration': True,
            'tryItOutEnabled': True,
            'filter': True,
            'layout': 'StandaloneLayout',
            'deepLinking': True,
            'showExtensions': True,
            'showCommonExtensions': True,
            'supportedSubmitMethods': [
                'get',
                'post',
                'put',
                'delete',
                'patch'
            ],
            'oauth2RedirectUrl': None,
            'showMutatedRequest': True,
            'syntaxHighlight.theme': 'agate',
        }
    )

    # Registra o blueprint do Swagger
    app.register_blueprint(swagger_bp, url_prefix=SWAGGER_URL)
