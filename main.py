# app/main.py
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_dance.contrib.google import google, make_google_blueprint

from auth import (
    admin_required,
    admin_user,
    google_authorized,
    google_login,
    login_required,
    logout_user,
    validate_login,
)
from forms import RegistrationForm  # Adjust this import based on your forms.py setup
from models import User, db  # Adjust this import based on your models.py setup
import os


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable track modifications to avoid warnings
# Access Google OAuth credentials from environment variables
app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET') 
db.init_app(app)

# Initialize Google blueprint
google_bp = make_google_blueprint(scope="https://www.googleapis.com/auth/userinfo.email")
app.register_blueprint(google_bp, url_prefix="/google")

with app.app_context():
    db.create_all()

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# User login
@app.route('/login', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = validate_login(username, password)  # Call the validation function from auth.py
        if user:
            session['logged_in'] = True
            session['username'] = username
            flash('Welcome back!')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials.')
            return redirect(url_for('login_user'))
    return render_template('login.html')

# Admin login
@app.route('/admin/login', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == admin_user['username'] and password == admin_user['password']:
            session['admin_logged_in'] = True
            flash('Admin login successful!')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.')
            return redirect(url_for('login_admin'))
    return render_template('admin-login.html')

# User dashboard
@app.route('/dashboard')
@login_required
def user_dashboard():
    return render_template('user-dashboard.html', username=session['username'])

# Admin dashboard
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin-dashboard.html')

# Google login
@app.route('/google/login')
def google_login_route():
    # Redirect to Google's login page
    if not google.authorized:
        return redirect(url_for('google.login'))
    else:
        return "This should not happen, user is already logged in!"


@app.route('/google/authorized')  # Correct endpoint name
def google_authorized_route():
    # Handle the authorization callback from Google
    if not google.authorized:
        return "Authorization failed", 403

    resp = google.get('/userinfo')
    if not resp.ok:
        return f"Failed to fetch user info: {resp.text}", 500

    user_info = resp.json()
    username = user_info['name']
    email = user_info['email']

    # Check if user exists, register if not
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=username, email=email)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful using Google!')

    session['logged_in'] = True
    session['username'] = username
    flash(f'Welcome {username}! You are logged in with Google.')
    return redirect(url_for('user_dashboard'))

# Logout
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login_user'))

if __name__ == '__main__':
    app.run(debug=True)
