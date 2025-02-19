from flask_login import UserMixin
# import module for sqlalchemy
from flask_sqlalchemy import SQLAlchemy

db=SQLAlchemy()


# class User(UserMixin):
#     def __init__(self, id, username, password):
#         self.id = id
#         self.username = username
#         self.password = password

#     def __repr__(self):
#         return f'<User: {self.username}'
    
# database models
# db model for our users and for our notes(for this app)

# from sqlalchemy.sql import func

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))