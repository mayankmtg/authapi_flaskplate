#   Primary Author: Mayank Mohindra <mayankmohindra06@gmail.com>
#
#   Purpose: db.sqlite3 initiate 

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
import uuid

from utils import load_yaml

config = load_yaml('config.yaml')

app = Flask(__name__)
app.config['SECRET_KEY'] = config.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = config.get('DATABASE_URI')
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

db.create_all()

username = config.get('ADMIN_USERNAME')
password = config.get('ADMIN_PASSWORD')

hashed_password = generate_password_hash(password, method='sha256')
new_user = User(public_id=str(uuid.uuid4()), username=username, password=hashed_password, admin=True)
db.session.add(new_user)
db.session.commit()