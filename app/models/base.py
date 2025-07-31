from app.extensions import db
from app.utils import now_br


class BaseModel(db.Model):
    """Classe abstrata base para todos os modelos"""
    __abstract__ = True

    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True
    )
    created_at = db.Column(
        db.DateTime,
        default=now_br,
        nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=now_br,
        onupdate=now_br,
        nullable=False
    )
    deleted_at = db.Column(
        db.DateTime,
        nullable=True
    )
    is_active = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )

    def delete(self, soft_delete=True):
        """Deleta o objeto, com opção de soft delete"""
        if soft_delete:
            self.deleted_at = now_br()
            self.is_active = False
        else:
            db.session.delete(self)

    def restore(self):
        """Restaura um objeto com soft delete"""
        self.deleted_at = None
        self.is_active = True
        return self

    @property
    def is_deleted(self):
        """Verifica se o objeto foi deletado (soft delete)"""
        return self.deleted_at is not None

    def __repr__(self):
        return f'<{self.__class__.__name__} {self.id}>'
