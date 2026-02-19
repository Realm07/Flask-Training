import sys
sys.path.insert(0, '.')
from app import create_app
from app.extensions import db
from app.models import User, PasswordVault

app = create_app()
with app.app_context():
    user = User.query.filter_by(email='sheesmohammad66@gmail.com').first()
    if user:
        print('User vault_salt:', user.vault_salt)
        passwords = PasswordVault.query.filter_by(user_id=user.id).all()
        print(f'Found {len(passwords)} passwords')
        for p in passwords:
            print(f'Password ID: {p.id}')
            print(f'Encrypted: {p.encrypted_password}')
            print(f'Service: {p.service_name}')
    else:
        print('User not found')
