from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mayank'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite3"

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

db.create_all()

username = 'admin'
password = 'admin'

hashed_password = generate_password_hash(password, method='sha256')
new_user = User(public_id=str(uuid.uuid4()), username=username, password=hashed_password, admin=True)
db.session.add(new_user)
db.session.commit()