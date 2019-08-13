## --------------------------------------- START OF LICENSE NOTICE ------------------------------------------------------
# Copyright (c) 2019 Software Robotics Corporation Limited ("Soroco"). All rights reserved.
#
# NO WARRANTY. THE PRODUCT IS PROVIDED BY SOROCO "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL SOROCO BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE PRODUCT, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
# ---------------------------------------- END OF LICENSE NOTICE -------------------------------------------------------
#
#   Primary Author: Mayank Mohindra <mayank.mohindra@soroco.com>
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

def loginError():
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

def authentication_check(usertype):
    """
    Function decorator for authentication the user if that is the admin
    
    Args:
        usertype(str): either 'admin' or 'non-admin'
    
    Returns:
        None
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
def createUser(current_user):
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(message_dict('New user created!'))

@app.route(Urls.USER.value, methods = ['GET'])
@authentication_check('admin')
def getUsers(current_user):
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
def getUser(current_user, public_id):
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
def promoteUser(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify(message_dict("No user found!"))
    
    user.admin = True
    db.session.commit()
    return jsonify(message_dict("Promotion Successful"))

@app.route(Urls.USERIND.value, methods= ["DELETE"])
@authentication_check('admin')
def deleteUser(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify(message_dict('No user found!'))
    db.session.delete(user)
    db.session.commit()
    return jsonify(message_dict('Deletion Successful'))


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return loginError()
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return loginError()
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify(return_dict('token', token.decode('UTF-8')))
    return loginError()


if __name__ == '__main__':
    app.run(debug=True)



