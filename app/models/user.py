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
    phone = db.Column(db.String(20), unique=True, nullable=True)
    birth_date = db.Column(db.Date, nullable=True)

    def set_password(self, password):
        """Define a senha do usuário com hash"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica se a senha fornecida é válida"""
        return check_password_hash(self.password_hash, password)

    @property
    def full_name(self):
        """Retorna o nome completo do usuário"""
        return f"{self.first_name} {self.last_name}"

    def __repr__(self):
        return f'<User {self.username} ({self.email})>'
