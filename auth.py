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
        action = request.args.get('action', 'login')  # Default to 'login'
        if action == 'register':
            # Redirect user to Google for registration
            return redirect(url_for('google.login', next='/google/login?action=register'))
        else:
            # Redirect user to Google for login
            return redirect(url_for('google.login', next='/google/login?action=login'))

def google_authorized():
    if not google.authorized:
        flash("Google authorization failed. Please try again.")
        return redirect(url_for('login_user'))

    try:
        # Get user info from Google
        resp = google.get('/userinfo')
        if not resp.ok:
            flash("Failed to retrieve user information from Google.")
            return redirect(url_for('login_user'))

        user_info = resp.json()
        username = user_info.get('name')
        email = user_info.get('email')

        if not username or not email:
            flash("Google user info is incomplete.")
            return redirect(url_for('login_user'))

        # Determine if this is for login or registration
        action = request.args.get('action', 'login')  # Default to login

        if action == 'register':
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('This email is already registered. Please log in.')
                return redirect(url_for('login_user'))

            # Register new user
            user = User(username=username, email=email)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful!')

        elif action == 'login':
            # Check if user exists
            user = User.query.filter_by(email=email).first()
            if not user:
                flash('No account found. Please register first.')
                return redirect(url_for('login_user'))

            flash(f"Welcome back, {user.username}!")

        # Log in the user
        session['logged_in'] = True
        session['username'] = username

    except Exception as e:
        flash("An error occurred during Google login.")
        return redirect(url_for('login_user'))

    # Redirect to the user dashboard after successful login/registration
    return redirect(url_for('user_dashboard'))

def logout_user():
    session.pop('logged_in', None)
    session.pop('admin_logged_in', None)
    flash('You have been logged out.')
