import sys
sys.path.insert(0, '.')
from app.utils.encryption import encrypt_password, decrypt_password, generate_salt

print('Testing encryption...')
salt = 'ZlFsP5O4i08pMUIPfctGdA=='
master_password = 'test123'
password = 'mypassword'
encrypted = encrypt_password(password, master_password, salt)
print('Encrypted:', encrypted)
decrypted = decrypt_password(encrypted, master_password, salt)
print('Decrypted:', decrypted)
print('Match:', password == decrypted)
