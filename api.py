#   Primary Author: Mayank Mohindra <mayankmohindra06@gmail.com>
#
#   Purpose: Flask authentication library

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from urls import Urls
from utils import message_dict, return_dict
import datetime
import jwt



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

# 
# Create any models here
# 

def login_error():
    """
    Authentication error response
    """
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

def authentication_check(usertype):
    """
    Function decorator for authentication the user if that is the admin
    
    Args:
        usertype(str): either 'admin' or 'nonadmin'
    """
    def wrap(func):
        def inner(*args, **kwargs):
            try:
                token = request.headers['x-access-token']
                data = jwt.decode(token, app.config['SECRET_KEY'])
                current_user = User.query.filter_by(public_id=data['public_id']).first()
                if(usertype == 'admin' and not current_user.admin):
                    raise Exception("error \t - \t not enough permissions for this operation")
                return func(current_user, *args, **kwargs)
            except Exception:
                return jsonify(message_dict("invalid/missing token or permission denied")), 401
        inner.__name__ = func.__name__
        return inner
    return wrap


@app.route(Urls.USER.value, methods = ['POST'])
@authentication_check('admin')
def create_user(current_user):
    """
    Adding new user to the system (SQLAlchemy database)
    
    Args:
        current_user: passed from the authentication_check decorator. Contains the extracted logged in user
    
    Returns:
        JSON response
    """
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(message_dict('New user created!'))

@app.route(Urls.USER.value, methods = ['GET'])
@authentication_check('admin')
def get_users(current_user):
    """
    Getting all user registered in the system (SQLAlchemy database)
    
    Args:
        current_user: passed from the authentication_check decorator. Contains the extracted logged in user (using authentication header)
    
    Returns:
        JSON response
    """
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify(return_dict('users', output))
    
@app.route(Urls.USERIND.value, methods = ['GET'])
@authentication_check('admin')
def get_user(current_user, public_id):
    """
    Getting a particular user from the system
    
    Args:
        current_user: passed from the authentication_check decorator. Contains the extracted logged in user
        public_id: URL passed parameter (public component of the user_id)

    Returns:
        JSON response
    """
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify(message_dict("No user found!"))
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify(return_dict('user', user_data))

@app.route(Urls.USERIND.value, methods = ['PUT'])
@authentication_check('admin')
def promote_user(current_user, public_id):
    """
    Extending the admin status to any of the passed users in the URL
    
    Args:
        current_user: passed from the authentication_check decorator. Contains the extracted logged in user
        public_id: public id for the user whose status needs to be promoted
    
    Returns:
        JSON response
    """
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify(message_dict("No user found!"))
    
    user.admin = True
    db.session.commit()
    return jsonify(message_dict("Promotion Successful"))

@app.route(Urls.USERIND.value, methods= ["DELETE"])
@authentication_check('admin')
def delete_user(current_user, public_id):
    """
    Deleting an existent user
    
    Args:
        current_user: passed from the authentication_check decorator. Contains the extracted logged in user
        public_id: Public id for the user whose instance needs to be deleted
    
    Returns:
        JSON response
    """
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify(message_dict('No user found!'))
    db.session.delete(user)
    db.session.commit()
    return jsonify(message_dict('Deletion Successful'))


@app.route('/login')
def login():
    """
    Logging in to get the authentication token (validity 30 mins) for the session
    """
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return login_error()
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return login_error()
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify(return_dict('token', token.decode('UTF-8')))
    return login_error()


if __name__ == '__main__':
    app.run(debug=True)



