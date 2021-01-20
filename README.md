# authapi_flaskplate

Flask authentication boilerplate

## Installation

```
$ pip install -r requirements.txt
$ python create_admin.py
```

## Deployment

## Endpoints

### /user
- GET: Get all registered users in the system
- POST: Create a new user

### /user/<public_id>
- GET: Getting a particular user from the system
- PUT: Extending the admin status to any of the passed users in the URL
- DELETE: Deleting an existent user

### /login

Send HTTP basic authentication request
