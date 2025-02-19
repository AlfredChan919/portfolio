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
from models import User,db

import os


DB_NAME="database.db"

# users=[]
# users.append(User(id=1, username='alfred', password='password'))
# users.append(User(id=2, username='pirsq', password='password'))

# print(users)

app = Flask(__name__)

# session has default time limit, which will expire
app.config["SESSION_PERMANENT"] = False

# store in hard drive under /flask_sessions foolder in config directory
app.config["SESSION_TYPE"] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'

app.config["SECRET_KEY"] = os.urandom(24)  # Generates a random secret key

Session(app)

db.init_app(app)

login_manager=LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    # telling flask how to look for a user similar to user query get filter
    return User.query.get(int(id))




@app.route("/")
@login_required
def home():
    first_name = session.get("first_name", "Guest")
    return render_template("index.html", user=current_user)

@app.route("/login", methods=["POST","GET"])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user=User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
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
    # # if form is submitted
    # if request.method == "POST":
    #     # record user name
    #     session["name"] = request.form.get("name")
    #     # redirect to main page
    #     return redirect("/")
    # return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#signup
@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method== 'POST':
        email = request.form.get('email')
        first_name=request.form.get('firstName')
        password1=request.form.get('password1')
        password2=request.form.get('password2')

        user=User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')

        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) <2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) <7:
            flash('Password must be at least than 7 characters', category='error')
        else:
            #add user to the database
            new_user=User(email=email, first_name=first_name, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            session['first_name']=first_name
            flash('Account created!', category='success')
            login_user(new_user, remember=True)
            
            return redirect(url_for('home'))

    return render_template('sign_up.html', user=current_user)






if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8888)