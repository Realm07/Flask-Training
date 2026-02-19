import os
import json
import csv
import io
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from .extensions import db
from .models import User, Category, PasswordVault
from .utils.encryption import encrypt_password, decrypt_password, generate_salt
from .utils.password_generator import generate_password, calculate_password_strength

bp = Blueprint('main', __name__)


# ==================== Authentication Routes ====================

@bp.route('/')
def index():
    if current_user.is_authenticated:
        # Check if vault is unlocked
        if session.get('vault_unlocked'):
            return redirect(url_for('main.dashboard'))
        return redirect(url_for('main.unlock_vault'))
    return redirect(url_for('main.login'))


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        master_password = request.form.get('master_password', '')
        confirm_master = request.form.get('confirm_master_password', '')
        
        errors = []
        
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        
        if not password or len(password) < 6:
            errors.append('Account password must be at least 6 characters.')
        
        if not master_password or len(master_password) < 4:
            errors.append('Master password must be at least 4 characters.')
        
        if master_password != confirm_master:
            errors.append('Master passwords do not match.')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            errors.append('An account with this email already exists.')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('auth/register.html')
        
        # Create new user
        user = User(email=email)
        user.set_password(password)
        user.set_master_password(master_password)
        user.vault_salt = generate_salt()  # Store salt for encryption
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('auth/register.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if session.get('vault_unlocked'):
            return redirect(url_for('main.dashboard'))
        return redirect(url_for('main.unlock_vault'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            flash('Invalid email or password.', 'danger')
            return render_template('auth/login.html')
        
        login_user(user)
        flash('Logged in successfully!', 'success')
        
        # Check if user has set a master password
        if user.master_password_hash:
            return redirect(url_for('main.unlock_vault'))
        
        session['vault_unlocked'] = True
        return redirect(url_for('main.dashboard'))
    
    return render_template('auth/login.html')


@bp.route('/unlock-vault', methods=['GET', 'POST'])
@login_required
def unlock_vault():
    # If vault is already unlocked, redirect to dashboard
    if session.get('vault_unlocked'):
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        master_password = request.form.get('master_password', '')
        
        if not current_user.check_master_password(master_password):
            flash('Invalid master password.', 'danger')
            return render_template('auth/unlock.html')
        
        session['vault_unlocked'] = True
        session['master_password'] = master_password  # Store in session for encryption/decryption
        flash('Vault unlocked!', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('auth/unlock.html')


@bp.route('/logout')
@login_required
def logout():
    session.pop('vault_unlocked', None)
    session.pop('master_password', None)
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('main.login'))


@bp.route('/lock-vault')
@login_required
def lock_vault():
    session.pop('vault_unlocked', None)
    session.pop('master_password', None)
    flash('Vault locked.', 'info')
    return redirect(url_for('main.unlock_vault'))


#Dashboard & Vault Routes

@bp.route('/dashboard')
@login_required
def dashboard():
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    # Get filter parameters
    filter_type = request.args.get('filter', 'all')
    category_id = request.args.get('category', '')
    search_query = request.args.get('search', '')
    
    # Base query - only current user's passwords
    query = PasswordVault.query.filter_by(user_id=current_user.id)
    
    # Apply filters
    if filter_type == 'favorites':
        query = query.filter_by(is_favorite=True)
    elif filter_type == 'recent':
        query = query.order_by(PasswordVault.updated_at.desc()).limit(10)
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    if search_query:
        search = f'%{search_query}%'
        query = query.filter(
            (PasswordVault.service_name.ilike(search)) |
            (PasswordVault.username.ilike(search)) |
            (PasswordVault.url.ilike(search)) |
            (PasswordVault.notes.ilike(search))
        )
    
    # Order by favorites first, then by name
    passwords = query.order_by(
        PasswordVault.is_favorite.desc(),
        PasswordVault.service_name.asc()
    ).all()
    
    # Decrypt passwords for display (only if needed)
    # We'll show masked passwords by default
    
    categories = Category.query.filter_by(user_id=current_user.id).all()
    
    return render_template('vault/dashboard.html',
                           passwords=passwords,
                           categories=categories,
                           filter_type=filter_type,
                           selected_category=category_id,
                           search_query=search_query)


# ==================== Password Management Routes ====================

@bp.route('/password/add', methods=['GET', 'POST'])
@login_required
def add_password():
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    categories = Category.query.filter_by(user_id=current_user.id).all()
    
    if request.method == 'POST':
        service_name = request.form.get('service_name', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        url = request.form.get('url', '').strip()
        notes = request.form.get('notes', '').strip()
        category_id = request.form.get('category_id', '')
        is_favorite = request.form.get('is_favorite') == 'on'
        
        if not service_name or not username or not password:
            flash('Service name, username, and password are required.', 'danger')
            return render_template('vault/password_add.html', categories=categories)
        
        # Encrypt the password
        master_password = session.get('master_password')
        encrypted_password = encrypt_password(password, master_password, current_user.vault_salt)
        
        new_password = PasswordVault(
            service_name=service_name,
            username=username,
            encrypted_password=encrypted_password,
            url=url,
            notes=notes,
            category_id=category_id if category_id else None,
            is_favorite=is_favorite,
            user_id=current_user.id
        )
        
        db.session.add(new_password)
        db.session.commit()
        
        flash('Password added successfully!', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('vault/password_add.html', categories=categories)


@bp.route('/password/<password_id>')
@login_required
def view_password(password_id):
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    password_entry = PasswordVault.query.filter_by(id=password_id, user_id=current_user.id).first()
    
    if not password_entry:
        flash('Password not found.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Decrypt the password
    master_password = session.get('master_password')
    

    
    decrypted_password = decrypt_password(
        password_entry.encrypted_password, 
        master_password, 
        current_user.vault_salt
    )
    
    categories = Category.query.filter_by(user_id=current_user.id).all()
    
    return render_template('vault/password_view.html',
                           password=password_entry,
                           decrypted_password=decrypted_password,
                           categories=categories)


@bp.route('/password/<password_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_password(password_id):
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    password_entry = PasswordVault.query.filter_by(id=password_id, user_id=current_user.id).first()
    
    if not password_entry:
        flash('Password not found.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    categories = Category.query.filter_by(user_id=current_user.id).all()
    
    if request.method == 'POST':
        password_entry.service_name = request.form.get('service_name', '').strip()
        password_entry.username = request.form.get('username', '').strip()
        new_password = request.form.get('password', '')
        password_entry.url = request.form.get('url', '').strip()
        password_entry.notes = request.form.get('notes', '').strip()
        password_entry.category_id = request.form.get('category_id') or None
        password_entry.is_favorite = request.form.get('is_favorite') == 'on'
        
        # Only re-encrypt if a new password was provided
        if new_password:
            master_password = session.get('master_password')
            salt = current_user.vault_salt.encode() if current_user.vault_salt else None
            encrypted_password = encrypt_password(new_password, master_password, current_user.vault_salt)
            password_entry.encrypted_password = encrypted_password
        
        db.session.commit()
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('main.dashboard'))
    
    # Decrypt for display in form
    master_password = session.get('master_password')
    decrypted_password = decrypt_password(
        password_entry.encrypted_password, 
        master_password, 
        current_user.vault_salt
    )
    
    return render_template('vault/password_edit.html',
                           password=password_entry,
                           decrypted_password=decrypted_password,
                           categories=categories)


@bp.route('/password/<password_id>/delete', methods=['POST'])
@login_required
def delete_password(password_id):
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    password_entry = PasswordVault.query.filter_by(id=password_id, user_id=current_user.id).first()
    
    if not password_entry:
        flash('Password not found.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    db.session.delete(password_entry)
    db.session.commit()
    
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))


@bp.route('/password/<password_id>/toggle-favorite', methods=['POST'])
@login_required
def toggle_favorite(password_id):
    if not session.get('vault_unlocked'):
        return jsonify({'success': False, 'message': 'Vault is locked'}), 401
    
    password_entry = PasswordVault.query.filter_by(id=password_id, user_id=current_user.id).first()
    
    if not password_entry:
        return jsonify({'success': False, 'message': 'Password not found'}), 404
    
    password_entry.is_favorite = not password_entry.is_favorite
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'is_favorite': password_entry.is_favorite
    })


# ==================== Category Management Routes ====================

@bp.route('/categories')
@login_required
def list_categories():
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    categories = Category.query.filter_by(user_id=current_user.id).all()
    return render_template('vault/categories.html', categories=categories)


@bp.route('/categories/add', methods=['GET', 'POST'])
@login_required
def add_category():
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        color = request.form.get('color', '#6c757d')
        
        if not name:
            flash('Category name is required.', 'danger')
            return render_template('vault/category_add.html')
        
        # Check for duplicate name
        existing = Category.query.filter_by(user_id=current_user.id, name=name).first()
        if existing:
            flash('A category with this name already exists.', 'danger')
            return render_template('vault/category_add.html')
        
        category = Category(name=name, color=color, user_id=current_user.id)
        db.session.add(category)
        db.session.commit()
        
        flash('Category added successfully!', 'success')
        return redirect(url_for('main.list_categories'))
    
    return render_template('vault/category_add.html')


@bp.route('/categories/<category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    category = Category.query.filter_by(id=category_id, user_id=current_user.id).first()
    
    if not category:
        flash('Category not found.', 'danger')
        return redirect(url_for('main.list_categories'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        color = request.form.get('color', '#6c757d')
        
        if not name:
            flash('Category name is required.', 'danger')
            return render_template('vault/category_edit.html', category=category)
        
        # Check for duplicate name (excluding current category)
        existing = Category.query.filter(
            Category.user_id == current_user.id,
            Category.name == name,
            Category.id != category_id
        ).first()
        
        if existing:
            flash('A category with this name already exists.', 'danger')
            return render_template('vault/category_edit.html', category=category)
        
        category.name = name
        category.color = color
        db.session.commit()
        
        flash('Category updated successfully!', 'success')
        return redirect(url_for('main.list_categories'))
    
    return render_template('vault/category_edit.html', category=category)


@bp.route('/categories/<category_id>/delete', methods=['POST'])
@login_required
def delete_category(category_id):
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    category = Category.query.filter_by(id=category_id, user_id=current_user.id).first()
    
    if not category:
        flash('Category not found.', 'danger')
        return redirect(url_for('main.list_categories'))
    
    # Move passwords to uncategorized (set category_id to None)
    for password in category.passwords:
        password.category_id = None
    
    db.session.delete(category)
    db.session.commit()
    
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('main.list_categories'))


# ==================== Password Generator API ====================

@bp.route('/api/generate-password')
@login_required
def api_generate_password():
    if not session.get('vault_unlocked'):
        return jsonify({'error': 'Vault is locked'}), 401
    
    length = request.args.get('length', 16, type=int)
    use_uppercase = request.args.get('uppercase', 'true').lower() == 'true'
    use_lowercase = request.args.get('lowercase', 'true').lower() == 'true'
    use_digits = request.args.get('digits', 'true').lower() == 'true'
    use_special = request.args.get('special', 'true').lower() == 'true'
    exclude_ambiguous = request.args.get('exclude_ambiguous', 'false').lower() == 'true'
    
    password = generate_password(
        length=length,
        use_uppercase=use_uppercase,
        use_lowercase=use_lowercase,
        use_digits=use_digits,
        use_special=use_special,
        exclude_ambiguous=exclude_ambiguous
    )
    
    strength = calculate_password_strength(password)
    
    return jsonify({
        'password': password,
        'strength': strength
    })


@bp.route('/api/check-password-strength')
@login_required
def api_check_password_strength():
    password = request.args.get('password', '')
    strength = calculate_password_strength(password)
    return jsonify(strength)


# ==================== Export/Import Routes ====================

@bp.route('/export')
@login_required
def export_passwords():
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    format_type = request.args.get('format', 'json')
    
    passwords = PasswordVault.query.filter_by(user_id=current_user.id).all()
    categories = Category.query.filter_by(user_id=current_user.id).all()
    
    # Decrypt all passwords for export
    master_password = session.get('master_password')
    
    exported_data = []
    for pwd in passwords:
        decrypted = decrypt_password(pwd.encrypted_password, master_password, current_user.vault_salt)
        category = None
        if pwd.category_id:
            cat = next((c for c in categories if c.id == pwd.category_id), None)
            category = cat.name if cat else None
        
        exported_data.append({
            'service_name': pwd.service_name,
            'username': pwd.username,
            'password': decrypted,
            'url': pwd.url,
            'notes': pwd.notes,
            'category': category,
            'is_favorite': pwd.is_favorite,
            'created_at': pwd.created_at.isoformat() if pwd.created_at else None,
            'updated_at': pwd.updated_at.isoformat() if pwd.updated_at else None
        })
    
    if format_type == 'csv':
        # Create CSV
        output = io.StringIO()
        if exported_data:
            writer = csv.DictWriter(output, fieldnames=exported_data[0].keys())
            writer.writeheader()
            writer.writerows(exported_data)
        
        return output.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename=passwords_export.csv'
        }
    
    # Default to JSON
    return jsonify({
        'exported_at': db.func.now().scalar,
        'password_count': len(exported_data),
        'passwords': exported_data
    })


@bp.route('/import', methods=['GET', 'POST'])
@login_required
def import_passwords():
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(url_for('main.import_passwords'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('main.import_passwords'))
        
        try:
            # Determine format from filename
            if file.filename.endswith('.csv'):
                # Parse CSV
                content = file.read().decode('utf-8')
                reader = csv.DictReader(io.StringIO(content))
                data = list(reader)
            else:
                # Parse JSON
                data = json.load(file)
            
            if not isinstance(data, list):
                # Check if it's our export format
                if 'passwords' in data:
                    data = data['passwords']
                else:
                    data = [data]
            
            master_password = session.get('master_password')
            
            # Create category name to ID mapping
            categories = {c.name: c.id for c in Category.query.filter_by(user_id=current_user.id).all()}
            
            imported_count = 0
            errors = []
            
            for item in data:
                try:
                    service_name = item.get('service_name') or item.get('service') or item.get('name', '')
                    username = item.get('username') or item.get('user') or item.get('email', '')
                    password = item.get('password') or item.get('pass', '')
                    
                    if not service_name or not username or not password:
                        errors.append(f"Skipped entry: missing required fields")
                        continue
                    
                    # Encrypt password
                    encrypted_password = encrypt_password(password, master_password, current_user.vault_salt)
                    
                    # Get category ID
                    category_name = item.get('category')
                    category_id = categories.get(category_name) if category_name else None
                    
                    new_password = PasswordVault(
                        service_name=service_name,
                        username=username,
                        encrypted_password=encrypted_password,
                        url=item.get('url', ''),
                        notes=item.get('notes', ''),
                        category_id=category_id,
                        is_favorite=item.get('is_favorite', False),
                        user_id=current_user.id
                    )
                    
                    db.session.add(new_password)
                    imported_count += 1
                    
                except Exception as e:
                    errors.append(f"Error importing entry: {str(e)}")
            
            db.session.commit()
            
            flash(f'Successfully imported {imported_count} passwords!', 'success')
            if errors:
                for error in errors[:5]:  # Show first 5 errors
                    flash(error, 'warning')
            
            return redirect(url_for('main.dashboard'))
            
        except Exception as e:
            flash(f'Error importing file: {str(e)}', 'danger')
            return redirect(url_for('main.import_passwords'))
    
    return render_template('vault/import.html')


# ==================== Settings Routes ====================

@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if not session.get('vault_unlocked'):
        return redirect(url_for('main.unlock_vault'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_master_password':
            current_master = request.form.get('current_master_password', '')
            new_master = request.form.get('new_master_password', '')
            confirm_master = request.form.get('confirm_master_password', '')
            
            if not current_user.check_master_password(current_master):
                flash('Current master password is incorrect.', 'danger')
                return render_template('vault/settings.html')
            
            if new_master != confirm_master:
                flash('New master passwords do not match.', 'danger')
                return render_template('vault/settings.html')
            
            if len(new_master) < 4:
                flash('New master password must be at least 4 characters.', 'danger')
                return render_template('vault/settings.html')
            
            # Re-encrypt all passwords with new master password
            new_salt = generate_salt()
            
            passwords = PasswordVault.query.filter_by(user_id=current_user.id).all()
            
            for pwd in passwords:
                # Decrypt with old
                decrypted = decrypt_password(pwd.encrypted_password, current_master, current_user.vault_salt)
                # Re-encrypt with new
                pwd.encrypted_password = encrypt_password(decrypted, new_master, new_salt)
            
            current_user.set_master_password(new_master)
            current_user.vault_salt = new_salt
            session['master_password'] = new_master
            
            db.session.commit()
            flash('Master password changed successfully!', 'success')
        
        elif action == 'change_account_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not current_user.check_password(current_password):
                flash('Current account password is incorrect.', 'danger')
                return render_template('vault/settings.html')
            
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return render_template('vault/settings.html')
            
            if len(new_password) < 6:
                flash('New password must be at least 6 characters.', 'danger')
                return render_template('vault/settings.html')
            
            current_user.set_password(new_password)
            db.session.commit()
            flash('Account password changed successfully!', 'success')
    
    return render_template('vault/settings.html')
