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
    # Check if the user is authorized by Google
    if not google.authorized:
        flash("Google authorization failed. Please try again.")
        return redirect(url_for('login_user'))  # Ensure 'login_user' route is defined
    
    # Get user info from Google
    try:
        resp = google.get('/userinfo')
        if not resp.ok:
            logging.error(f"Failed to fetch user info: {resp.text}")
            flash("Failed to retrieve user information from Google.")
            return redirect(url_for('login_user'))
        
        user_info = resp.json()
        username = user_info.get('name')
        email = user_info.get('email')
        
        if not username or not email:
            flash("Google user info is incomplete. Please ensure your Google account is properly configured.")
            return redirect(url_for('login_user'))
        
        # Register user if not already registered
        if not any(user['username'] == username for user in users):
            register_user(username, email)
            flash('Registration successful using Google!')
        
        # Store user information in session
        session['logged_in'] = True
        session['username'] = username
        flash(f"Welcome {username}! You are now logged in with Google.")
    
    except Exception as e:
        logging.error(f"Error during Google authorization: {e}")
        flash("An error occurred during Google login. Please try again.")
        return redirect(url_for('login_user'))

    # Redirect to user dashboard after successful login
    return redirect(url_for('user_dashboard'))
def logout_user():
    session.pop('logged_in', None)
    session.pop('admin_logged_in', None)
    flash('You have been logged out.')
