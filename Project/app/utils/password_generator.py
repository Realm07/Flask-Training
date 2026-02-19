import random
import string


def generate_password(length: int = 16, 
                     use_uppercase: bool = True, 
                     use_lowercase: bool = True, 
                     use_digits: bool = True, 
                     use_special: bool = True,
                     exclude_ambiguous: bool = False) -> str:
    characters = ''
    
    if use_uppercase:
        if exclude_ambiguous:
            characters += string.ascii_uppercase.replace('O', '').replace('I', '')
        else:
            characters += string.ascii_uppercase
    
    if use_lowercase:
        if exclude_ambiguous:
            characters += string.ascii_lowercase.replace('l', '').replace('o', '')
        else:
            characters += string.ascii_lowercase
    
    if use_digits:
        if exclude_ambiguous:
            characters += string.digits.replace('0', '').replace('1', '')
        else:
            characters += string.digits
    
    if use_special:
        characters += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    if not characters:
        characters = string.ascii_letters + string.digits
    
    password = []
    
    if use_uppercase:
        if exclude_ambiguous:
            password.append(random.choice(string.ascii_uppercase.replace('O', '').replace('I', '')))
        else:
            password.append(random.choice(string.ascii_uppercase))
    
    if use_lowercase:
        if exclude_ambiguous:
            password.append(random.choice(string.ascii_lowercase.replace('l', '').replace('o', '')))
        else:
            password.append(random.choice(string.ascii_lowercase))
    
    if use_digits:
        if exclude_ambiguous:
            password.append(random.choice(string.digits.replace('0', '').replace('1', '')))
        else:
            password.append(random.choice(string.digits))
    
    if use_special:
        password.append(random.choice('!@#$%^&*()_+-=[]{}|;:,.<>?'))
    
    remaining_length = length - len(password)
    password.extend(random.choice(characters) for _ in range(remaining_length))
    
    random.shuffle(password)
    
    return ''.join(password)


def calculate_password_strength(password: str) -> dict:
    score = 0
    feedback = []
    
    if not password:
        return {'score': 0, 'strength': 'Very Weak', 'feedback': ['Password is empty']}
    
    if len(password) >= 8:
        score += 10
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    if len(password) >= 20:
        score += 10
    
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
    
    if has_lower:
        score += 10
    if has_upper:
        score += 10
    if has_digit:
        score += 10
    if has_special:
        score += 15
    
    if len(set(password)) < len(password) * 0.5:
        score -= 10
        feedback.append('Contains repeated characters')
    
    sequential = False
    for i in range(len(password) - 2):
        if ord(password[i+1]) - ord(password[i]) == 1 and ord(password[i+2]) - ord(password[i+1]) == 1:
            sequential = True
            break
    
    if sequential:
        score -= 10
        feedback.append('Contains sequential characters')
    
    common_patterns = ['123', 'abc', 'password', 'qwerty', 'admin']
    for pattern in common_patterns:
        if pattern in password.lower():
            score -= 15
            feedback.append(f'Contains common pattern: {pattern}')
    
    score = max(0, min(100, score))
    
    if score >= 80:
        strength = 'Very Strong'
    elif score >= 60:
        strength = 'Strong'
    elif score >= 40:
        strength = 'Medium'
    elif score >= 20:
        strength = 'Weak'
    else:
        strength = 'Very Weak'
    
    if not feedback:
        if strength in ['Very Strong', 'Strong']:
            feedback.append('Great password!')
        else:
            feedback.append('Consider using a longer password with more character types')
    
    return {'score': score, 'strength': strength, 'feedback': feedback}
