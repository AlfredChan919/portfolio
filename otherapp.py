from flask import Flask, render_template, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Required for session encryption

# Configure Flask-Session to store data on the server
app.config["SESSION_TYPE"] = "filesystem"  # Stores sessions on the server
app.config["SESSION_PERMANENT"] = False
Session(app)  # Initialize Flask-Session

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect users here if not logged in

# Dummy User Model
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Fake user database
users = {1: User(1)}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

@app.route('/')
def home():
    return f"Welcome, {'User ' + str(current_user.id) if current_user.is_authenticated else 'Guest'}!"

@app.route('/login')
def login():
    user = users[1]  # Assume we have a single user
    login_user(user)  # Flask-Login handles authentication
    session["preferences"] = {"theme": "dark"}  # Store additional session data
    return redirect(url_for("dashboard"))

@app.route('/dashboard')
@login_required
def dashboard():
    theme = session.get("preferences", {}).get("theme", "default")  # Retrieve session data
    return f"Hello, User {current_user.id}! Your theme is {theme}."

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()  # Clear the session data
    return redirect(url_for("home"))

if __name__ == '__main__':
    app.run(debug=True)
