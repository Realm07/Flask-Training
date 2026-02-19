import uuid
from sqlalchemy.dialects.postgresql import UUID
from .extensions import db

class Tenant(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.string(100), nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=db.func.now())