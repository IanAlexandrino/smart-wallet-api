"""
Schemas de validação para operações de usuários.
"""

from marshmallow import fields, validate, validates, ValidationError, post_load
from app.extensions import ma
import re
from datetime import date


class UserCreateSchema(ma.Schema):
    """Schema para criação de usuário (sem confirmação de senha)"""

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

    role = fields.Str(
        allow_none=True,
        validate=validate.OneOf(['admin', 'user']),
        load_default='user',
        error_messages={
            'invalid': 'Role deve ser "admin" ou "user"'
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
        if value:
            # Remove espaços e caracteres especiais para validação
            clean_phone = re.sub(r'[^\d]', '', value)
            if len(clean_phone) < 10 or len(clean_phone) > 15:
                raise ValidationError('Telefone deve ter entre 10 e 15 dígitos')

    @validates('birth_date')
    def validate_birth_date(self, value, **kwargs):
        """Valida data de nascimento"""
        if value:
            today = date.today()
            if value >= today:
                raise ValidationError('Data de nascimento deve ser anterior à data atual')

            # Verifica se a pessoa tem pelo menos 13 anos
            age = today.year - value.year - \
                ((today.month, today.day) < (value.month, value.day))
            if age < 13:
                raise ValidationError('Usuário deve ter pelo menos 13 anos')

    @post_load
    def normalize_data(self, data, **kwargs):
        """Normaliza dados após validação"""
        data['username'] = data['username'].lower().strip()
        data['email'] = data['email'].lower().strip()
        data['first_name'] = data['first_name'].strip().title()
        data['last_name'] = data['last_name'].strip().title()

        if data.get('phone'):
            data['phone'] = data['phone'].strip()

        if not data.get('role'):
            data['role'] = 'user'

        return data


class UserUpdateSchema(ma.Schema):
    """Schema para atualização de usuário (todos os campos opcionais)"""

    first_name = fields.Str(
        allow_none=True,
        validate=validate.Length(min=2, max=50),
        error_messages={
            'invalid': 'Nome deve ser uma string válida'
        }
    )

    last_name = fields.Str(
        allow_none=True,
        validate=validate.Length(min=2, max=50),
        error_messages={
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

    @validates('first_name')
    def validate_first_name(self, value, **kwargs):
        """Valida nome"""
        if value is not None:
            if not value.strip():
                raise ValidationError('Nome não pode estar vazio')

            # Apenas letras e espaços
            if not re.match(r'^[a-zA-ZÀ-ÿ\s]+$', value.strip()):
                raise ValidationError('Nome deve conter apenas letras')

    @validates('last_name')
    def validate_last_name(self, value, **kwargs):
        """Valida sobrenome"""
        if value is not None:
            if not value.strip():
                raise ValidationError('Sobrenome não pode estar vazio')

            # Apenas letras e espaços
            if not re.match(r'^[a-zA-ZÀ-ÿ\s]+$', value.strip()):
                raise ValidationError('Sobrenome deve conter apenas letras')

    @validates('phone')
    def validate_phone(self, value, **kwargs):
        """Valida telefone"""
        if value is not None and value.strip():
            # Remove espaços e caracteres especiais para validação
            clean_phone = re.sub(r'[^\d]', '', value)
            if len(clean_phone) < 10 or len(clean_phone) > 15:
                raise ValidationError('Telefone deve ter entre 10 e 15 dígitos')

    @validates('birth_date')
    def validate_birth_date(self, value, **kwargs):
        """Valida data de nascimento"""
        if value is not None:
            today = date.today()
            if value >= today:
                raise ValidationError('Data de nascimento deve ser anterior à data atual')

            # Verifica se a pessoa tem pelo menos 13 anos
            age = today.year - value.year - \
                ((today.month, today.day) < (value.month, value.day))
            if age < 13:
                raise ValidationError('Usuário deve ter pelo menos 13 anos')

    @post_load
    def normalize_data(self, data, **kwargs):
        """Normaliza dados após validação"""
        if data.get('first_name'):
            data['first_name'] = data['first_name'].strip().title()

        if data.get('last_name'):
            data['last_name'] = data['last_name'].strip().title()

        if data.get('phone'):
            data['phone'] = data['phone'].strip()

        return data


class ChangePasswordSchema(ma.Schema):
    """Schema para alteração de senha"""

    current_password = fields.Str(
        required=True,
        error_messages={
            'required': 'Senha atual é obrigatória',
            'invalid': 'Senha atual deve ser uma string válida'
        }
    )

    new_password = fields.Str(
        required=True,
        validate=validate.Length(min=6, max=128),
        error_messages={
            'required': 'Nova senha é obrigatória',
            'invalid': 'Nova senha deve ser uma string válida'
        }
    )

    confirm_password = fields.Str(
        required=True,
        error_messages={
            'required': 'Confirmação de senha é obrigatória',
            'invalid': 'Confirmação de senha deve ser uma string válida'
        }
    )

    @validates('new_password')
    def validate_new_password(self, value, **kwargs):
        """Valida força da nova senha"""
        if not value:
            raise ValidationError('Nova senha não pode estar vazia')

        # Pelo menos uma letra
        if not re.search(r'[a-zA-Z]', value):
            raise ValidationError('Nova senha deve conter pelo menos uma letra')

        # Pelo menos um número
        if not re.search(r'[0-9]', value):
            raise ValidationError('Nova senha deve conter pelo menos um número')

    @validates('confirm_password')
    def validate_confirm_password(self, value, **kwargs):
        """Valida confirmação de senha - validação real feita em post_load"""
        pass

    @post_load
    def validate_passwords_match(self, data, **kwargs):
        """Valida se new_password e confirm_password coincidem"""
        if data.get('new_password') != data.get('confirm_password'):
            raise ValidationError({'confirm_password': ['Confirmação de senha não confere']})
        return data


class UserListQuerySchema(ma.Schema):
    """Schema para parâmetros de busca na listagem de usuários"""

    search = fields.Str(
        allow_none=True,
        validate=validate.Length(max=100),
        error_messages={
            'invalid': 'Termo de busca deve ser uma string válida'
        }
    )

    role = fields.Str(
        allow_none=True,
        validate=validate.OneOf(['admin', 'user']),
        error_messages={
            'invalid': 'Role deve ser "admin" ou "user"'
        }
    )

    @post_load
    def normalize_data(self, data, **kwargs):
        """Normaliza dados após validação"""
        if data.get('search'):
            data['search'] = data['search'].strip()

        return data


class UserResponseSchema(ma.Schema):
    """Schema para resposta de dados do usuário (sem senha)"""

    id = fields.Int()
    username = fields.Str()
    email = fields.Str()
    first_name = fields.Str()
    last_name = fields.Str()
    phone = fields.Str()
    birth_date = fields.Date()
    role = fields.Str()
    full_name = fields.Method('get_full_name')
    is_active = fields.Bool()

    def get_full_name(self, obj):
        """Retorna nome completo"""
        return f"{obj.first_name} {obj.last_name}"
