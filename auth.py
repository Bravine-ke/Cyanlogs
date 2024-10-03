# app/auth.py
from flask import session, flash, redirect, url_for
from functools import wraps
from flask_dance.contrib.google import google

# Mock user database for demonstration
users = []
admin_user = {'username': 'admin', 'password': 'admin123'}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('You need to log in first.')
            return redirect(url_for('login_user'))  # Ensure 'login_user' route is defined in your app
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Admin login required.')
            return redirect(url_for('login_admin'))  # Ensure 'login_admin' route is defined in your app
        return f(*args, **kwargs)
    return decorated_function

def register_user(username, email):
    users.append({'username': username, 'email': email})

def validate_login(username, password):
    # Ensure users have passwords stored if you're using them
    return next((user for user in users if user['username'] == username and user.get('password') == password), None)

def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

def google_authorized():
    if not google.authorized:
        return "Authorization failed", 403

    resp = google.get('/userinfo')
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user_info = resp.json()
    username = user_info['name']
    email = user_info['email']

    # Register the user if not already in the users list
    if not any(user['username'] == username for user in users):
        register_user(username, email)  # Automatically register if not found
        flash('Registration successful using Google!')

    session['logged_in'] = True
    session['username'] = username
    flash(f'Welcome {username}! You are logged in with Google.')

    return redirect(url_for('user_dashboard'))


def logout_user():
    session.pop('logged_in', None)
    session.pop('admin_logged_in', None)
    flash('You have been logged out.')
