from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db
from .base import BaseModel


class User(BaseModel):
    """Modelo para usuários do sistema"""
    __tablename__ = 'users'

    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    birth_date = db.Column(db.Date, nullable=True)
    role = db.Column(
        db.Enum(
            'admin',
            'user'
        ),
        nullable=False,
        default='user'
    )

    def set_password(self, password):
        """Define a senha do usuário com hash"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica se a senha fornecida é válida"""
        return check_password_hash(self.password_hash, password)

    def set_role(self, role):
        """Define o role do usuário garantindo compatibilidade entre bancos"""
        if isinstance(role, str):
            # Valida se a string é um valor válido
            valid_roles = ['admin', 'user']
            if role.lower() in valid_roles:
                self.role = role.lower()
            else:
                self.role = 'user'  # Default
        else:
            # Default para 'user' se tipo inválido
            self.role = 'user'

    @property
    def full_name(self):
        """Retorna o nome completo do usuário"""
        return f"{self.first_name} {self.last_name}"

    @property
    def is_admin(self):
        """Verifica se o usuário é administrador"""
        return self.role == 'admin'

    @property
    def is_regular_user(self):
        """Verifica se o usuário é um usuário regular"""
        return self.role == 'user'

    def __repr__(self):
        return f'<User {self.username} ({self.email}) - {self.role}>'
