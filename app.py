# creation of website
from flask import Flask, render_template, url_for, flash

# modules for flask sessions
from flask import redirect, request, session
from flask_session import Session

# modules for flask login
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from os import path

# import generic User class
from models import User, db, PortfolioItem

import os

from authlib.integrations.flask_client import OAuth
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename

DB_NAME = "database.db"

app = Flask(__name__)

# session has default time limit, which will expire
app.config["SESSION_PERMANENT"] = False

# store in hard drive under /flask_sessions folder in config directory
app.config["SESSION_TYPE"] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'

app.config["SECRET_KEY"] = os.urandom(24)  # Generates a random secret key

Session(app)

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='1072343201721-jqj86rr4gabrtopspf7im329i415i30e.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
    },
)


@login_manager.user_loader
def load_user(id):
    # telling flask how to look for a user similar to user query get filter
    return User.query.get(int(id))


@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorized', _external=True)
    print(f"Redirect URI: {redirect_uri}")  # Debugging: Log the redirect URI
    return google.authorize_redirect(redirect_uri, prompt='select_account')


@app.route('/login/google/authorized')
def google_authorized():
    try:
        token = google.authorize_access_token()
        print(f"Token: {token}")  # Debugging: Log the token

        # Use the correct URL to fetch user info
        user_info = google.get('https://openidconnect.googleapis.com/v1/userinfo').json()
        print(f"User Info: {user_info}")  # Debugging: Log user info

        if not user_info or 'email' not in user_info:
            flash('Failed to retrieve user information from Google.', 'error')
            return redirect(url_for('login'))

        # Check if the user exists in the database
        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            # Create a new user if not found
            user = User(email=user_info['email'], first_name=user_info.get('given_name', 'Google User'))
            db.session.add(user)
            db.session.commit()

        # Log the user in
        login_user(user, remember=True)
        session['oauth_user'] = True
        session['email'] = user_info['email']
        flash('Logged in successfully with Google!', 'success')
        return redirect(url_for('home'))

    except Exception as e:
        print(f"Error during Google OAuth: {e}")  # Debugging: Log the error
        flash('An error occurred during Google login.', 'error')
        return redirect(url_for('login'))


# Form for editing portfolio
class PortfolioForm(FlaskForm):
    title = StringField('Project Title', validators=[DataRequired()])
    description = TextAreaField('Project Description', validators=[DataRequired()])
    image = FileField('Project Image')
    submit = SubmitField('Save')


@app.route('/edit-portfolio', methods=['GET', 'POST'])
@login_required
def edit_portfolio():
    form = PortfolioForm()
    if form.validate_on_submit():
        image = form.image.data
        image_filename = None
        if image:
            image_filename = secure_filename(image.filename)
            image.save(os.path.join('static/images', image_filename))

        portfolio_item = PortfolioItem(
            title=form.title.data,
            description=form.description.data,
            image_filename=image_filename,
            user_id=current_user.id
        )
        db.session.add(portfolio_item)
        db.session.commit()
        flash('Portfolio item added successfully!', 'success')
        return redirect(url_for('edit_portfolio'))

    portfolio_items = PortfolioItem.query.filter_by(user_id=current_user.id).all()
    return render_template('edit_portfolio.html', form=form, portfolio_items=portfolio_items, user=current_user)


@app.route('/delete-portfolio/<int:item_id>', methods=['POST'])
@login_required
def delete_portfolio(item_id):
    portfolio_item = PortfolioItem.query.get_or_404(item_id)
    if portfolio_item.user_id != current_user.id:
        flash('You do not have permission to delete this item.', 'error')
        return redirect(url_for('edit_portfolio'))

    db.session.delete(portfolio_item)
    db.session.commit()
    flash('Portfolio item deleted successfully!', 'success')
    return redirect(url_for('edit_portfolio'))


@app.route("/")
@login_required
def home():
    first_name = session.get("first_name", "Guest")
    portfolio_items = PortfolioItem.query.all()
    return render_template("index.html", user=current_user, portfolio_items=portfolio_items)


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                session["first_name"] = user.first_name
                # remember = true means everytime you open the website it will remember you/or until user clears browsing history
                return redirect(url_for('home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template('login.html', user=current_user)


@app.route("/logout")
@login_required
def logout():
    session.pop('oauth_user', None)  # Remove the OAuth flag on logout
    session.pop('email', None)  # Remove email from session
    logout_user()
    return redirect(url_for('login'))


# signup
@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')

        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least than 7 characters', category='error')
        else:
            # add user to the database
            new_user = User(email=email, first_name=first_name,
                            password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            session['first_name'] = first_name
            flash('Account created!', category='success')
            login_user(new_user, remember=True)

            return redirect(url_for('home'))

    return render_template('sign_up.html', user=current_user)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True, port=8888)