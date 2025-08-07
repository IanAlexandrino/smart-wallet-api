"""
Schemas de validação para autenticação.
"""

from marshmallow import fields, validate, validates, ValidationError, post_load
from app.extensions import ma
import re


class LoginSchema(ma.Schema):
    """Schema para validação de login"""

    # Pode ser username ou email
    identifier = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=120),
        error_messages={
            'required': 'Identificador (username ou email) é obrigatório',
            'invalid': 'Identificador deve ser uma string válida'
        }
    )

    password = fields.Str(
        required=True,
        validate=validate.Length(min=6, max=128),
        error_messages={
            'required': 'Senha é obrigatória',
            'invalid': 'Senha deve ser uma string válida'
        }
    )

    @validates('identifier')
    def validate_identifier(self, value, **kwargs):
        """Valida se o identificador é um email válido ou username válido"""
        if not value or not value.strip():
            raise ValidationError('Identificador não pode estar vazio')

        # Se contém @, valida como email
        if '@' in value:
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, value):
                raise ValidationError('Email inválido')
        else:
            # Valida como username (apenas letras, números e underscore)
            username_regex = r'^[a-zA-Z0-9_]+$'
            if not re.match(username_regex, value):
                raise ValidationError('Username deve conter apenas letras, números e underscore')

    @post_load
    def normalize_data(self, data, **kwargs):
        """Normaliza dados após validação"""
        data['identifier'] = data['identifier'].lower().strip()
        return data


class RegisterSchema(ma.Schema):
    """Schema para validação de registro de usuário"""

    username = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=80),
        error_messages={
            'required': 'Username é obrigatório',
            'invalid': 'Username deve ser uma string válida'
        }
    )

    email = fields.Email(
        required=True,
        validate=validate.Length(max=120),
        error_messages={
            'required': 'Email é obrigatório',
            'invalid': 'Email deve ter um formato válido'
        }
    )

    password = fields.Str(
        required=True,
        validate=validate.Length(min=6, max=128),
        error_messages={
            'required': 'Senha é obrigatória',
            'invalid': 'Senha deve ser uma string válida'
        }
    )

    confirm_password = fields.Str(
        required=True,
        error_messages={
            'required': 'Confirmação de senha é obrigatória',
            'invalid': 'Confirmação de senha deve ser uma string válida'
        }
    )

    first_name = fields.Str(
        required=True,
        validate=validate.Length(min=2, max=50),
        error_messages={
            'required': 'Nome é obrigatório',
            'invalid': 'Nome deve ser uma string válida'
        }
    )

    last_name = fields.Str(
        required=True,
        validate=validate.Length(min=2, max=50),
        error_messages={
            'required': 'Sobrenome é obrigatório',
            'invalid': 'Sobrenome deve ser uma string válida'
        }
    )

    phone = fields.Str(
        allow_none=True,
        validate=validate.Length(max=20),
        error_messages={
            'invalid': 'Telefone deve ser uma string válida'
        }
    )

    birth_date = fields.Date(
        allow_none=True,
        error_messages={
            'invalid': 'Data de nascimento deve ter formato válido (YYYY-MM-DD)'
        }
    )

    @validates('username')
    def validate_username(self, value, **kwargs):
        """Valida username"""
        if not value or not value.strip():
            raise ValidationError('Username não pode estar vazio')

        # Username deve conter apenas letras, números e underscore
        username_regex = r'^[a-zA-Z0-9_]+$'
        if not re.match(username_regex, value):
            raise ValidationError('Username deve conter apenas letras, números e underscore')

    @validates('password')
    def validate_password(self, value, **kwargs):
        """Valida força da senha"""
        if not value:
            raise ValidationError('Senha não pode estar vazia')

        # Pelo menos uma letra
        if not re.search(r'[a-zA-Z]', value):
            raise ValidationError('Senha deve conter pelo menos uma letra')

        # Pelo menos um número
        if not re.search(r'[0-9]', value):
            raise ValidationError('Senha deve conter pelo menos um número')

    @validates('first_name')
    def validate_first_name(self, value, **kwargs):
        """Valida nome"""
        if not value or not value.strip():
            raise ValidationError('Nome não pode estar vazio')

        # Apenas letras e espaços
        if not re.match(r'^[a-zA-ZÀ-ÿ\s]+$', value.strip()):
            raise ValidationError('Nome deve conter apenas letras')

    @validates('last_name')
    def validate_last_name(self, value, **kwargs):
        """Valida sobrenome"""
        if not value or not value.strip():
            raise ValidationError('Sobrenome não pode estar vazio')

        # Apenas letras e espaços
        if not re.match(r'^[a-zA-ZÀ-ÿ\s]+$', value.strip()):
            raise ValidationError('Sobrenome deve conter apenas letras')

    @validates('phone')
    def validate_phone(self, value, **kwargs):
        """Valida telefone"""
        if value and value.strip():
            # Remove espaços e caracteres especiais para validação
            phone_clean = re.sub(r'[^\d]', '', value)
            if len(phone_clean) < 10 or len(phone_clean) > 15:
                raise ValidationError('Telefone deve ter entre 10 e 15 dígitos')

    def validate_passwords_match(self, data, **kwargs):
        """Valida se as senhas coincidem"""
        if data.get('password') != data.get('confirm_password'):
            raise ValidationError({
                'confirm_password': ['Senhas não coincidem']
            })

    @post_load
    def normalize_data(self, data, **kwargs):
        """Normaliza dados após validação"""
        # Remove confirm_password dos dados finais
        data.pop('confirm_password', None)

        # Normaliza campos de texto
        data['username'] = data['username'].lower().strip()
        data['email'] = data['email'].lower().strip()
        data['first_name'] = data['first_name'].strip().title()
        data['last_name'] = data['last_name'].strip().title()

        if data.get('phone'):
            data['phone'] = data['phone'].strip()

        return data


class RefreshTokenSchema(ma.Schema):
    """Schema para validação de refresh token"""

    refresh_token = fields.Str(
        required=True,
        error_messages={
            'required': 'Refresh token é obrigatório',
            'invalid': 'Refresh token deve ser uma string válida'
        }
    )

    @validates('refresh_token')
    def validate_refresh_token(self, value, **kwargs):
        """Valida refresh token"""
        if not value or not value.strip():
            raise ValidationError('Refresh token não pode estar vazio')


class UserResponseSchema(ma.Schema):
    """Schema para resposta com dados do usuário (sem senha)"""

    id = fields.Int()
    username = fields.Str()
    email = fields.Str()
    first_name = fields.Str()
    last_name = fields.Str()
    full_name = fields.Str()
    phone = fields.Str(allow_none=True)
    birth_date = fields.Date(allow_none=True)
    role = fields.Method("get_role")
    is_active = fields.Bool()

    def get_role(self, obj):
        """Retorna role como string"""
        return obj.role if obj.role else None


class TokenResponseSchema(ma.Schema):
    """Schema para resposta de tokens (sem dados do usuário)"""

    access_token = fields.Str()
    refresh_token = fields.Str()
    token_type = fields.Str()
    expires_in = fields.Int()
    refresh_expires_in = fields.Int()


class LoginResponseSchema(TokenResponseSchema):
    """Schema para resposta de login (herda de TokenResponseSchema)"""
    pass


class RegisterResponseSchema(ma.Schema):
    """Schema para resposta de registro (inclui dados do usuário uma única vez)"""

    access_token = fields.Str()
    refresh_token = fields.Str()
    token_type = fields.Str()
    expires_in = fields.Int()
    refresh_expires_in = fields.Int()
    user = fields.Nested(UserResponseSchema)


class RefreshResponseSchema(ma.Schema):
    """Schema para resposta de refresh token"""

    access_token = fields.Str()
    token_type = fields.Str()
    expires_in = fields.Int()
