
from .extensions import db, login_manager
from flask_login import UserMixin
import uuid
from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256))
    master_password_hash = db.Column(db.String(256))  # For encrypting the vault
    vault_salt = db.Column(db.String(24))  # Salt for encrypting passwords
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    # Relationships
    passwords = db.relationship('PasswordVault', backref='user', lazy=True, cascade='all, delete-orphan')
    categories = db.relationship('Category', backref='user', lazy=True, cascade='all, delete-orphan')
    
    # Vault unlock status (not stored in DB, used in session)
    vault_unlocked = False

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_master_password(self, master_password):
        self.master_password_hash = generate_password_hash(master_password)
    
    def check_master_password(self, master_password):
        return check_password_hash(self.master_password_hash, master_password)


class Category(db.Model):
    __tablename__ = 'categories'
    
    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    
    name = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(7), default='#6c757d')  # Hex color for UI
    user_id = db.Column(
        db.String(36),
        db.ForeignKey('users.id'),
        nullable=False
    )
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    # Relationships
    passwords = db.relationship('PasswordVault', backref='category', lazy=True)


class PasswordVault(db.Model):
    __tablename__ = 'password_vault'
    
    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    
    service_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    # Encrypted password stored as base64 (after encryption)
    encrypted_password = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(500))
    notes = db.Column(db.Text)
    is_favorite = db.Column(db.Boolean, default=False)
    
    user_id = db.Column(
        db.String(36),
        db.ForeignKey('users.id'),
        nullable=False
    )
    
    category_id = db.Column(
        db.String(36),
        db.ForeignKey('categories.id')
    )
    
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)