from flask import Flask, request, jsonify, redirect, url_for
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
from authlib.integrations.flask_client import OAuth
from backend.config import DevConfig
import random
import jwt as jwt_lib
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

import urllib.request
# from urllib.parse import Request, urlopen

from dotenv import load_dotenv
from os import getenv

# SuperAuth Tokens imports
from supertokens_python import get_all_cors_headers
from flask import Flask, abort
from flask_cors import CORS 
from supertokens_python.framework.flask import Middleware

app = Flask(__name__)
app.config.from_object(DevConfig)
Middleware(app)
oauth = OAuth(app)
JWTManager(app)

github = oauth.register(
    name='github',
    client_id=getenv("CLIENT_ID"),
    client_secret=getenv("CLIENT_SECRET"),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)   

# Replace these values with your OAuth 2.0 client credentials
CLIENT_ID = getenv("CLIENT_ID")
CLIENT_SECRET = getenv("CLIENT_SECRET")
TOKEN_URL = getenv("URL_ACCESS_TOKEN")
CODE = getenv("CODE")

# CODE='UeVtIHhCR1xTONUrz1Yrh4LhlZCBgl',
# CLIENT_ID = "d7bbb30f001852c17c12"
# CLIENT_SECRET = "10f82c2c6b3033da41dd68f2380c01fc66bbd06f"
TOKEN_URL = "https://github.com/login/oauth/access_token"


def generate_access_token(user_id):
    access_token = create_access_token(identity = user_id)
    return access_token

# Flask route for user authentication
@app.route('/login', methods=['POST'])
def login():
    # Assuming the client sends the username and password in JSON format
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Authenticate user (you may want to implement your own authentication logic here)
    if username == 'user' and password == 'password':
        # Request OAuth token
        client = BackendApplicationClient(client_id=CLIENT_ID)
        oauth = OAuth2Session(client=client)
        # token = oauth.fetch_token(
        #     token_url=TOKEN_URL, 
        #     client_id=CLIENT_ID, 
        #     # code=CODE,
        #     client_secret=CLIENT_SECRET,
        # )
        
        # redirect_url = url_for("authorize", _external=True, token=token)
        # return github.authorize_redirect(redirect_url)

        # # Create JWT token
        token=generate_access_token(random.randint(10000, 99999))
        jwt_token = jwt_lib.encode({'username': username}, DevConfig.JWT_SECRET_KEY, algorithm='HS256')
        
        print( jwt_token.encode('utf-8').decode("utf-8")) 

        return jsonify({'access_token': token, 'jwt_token': jwt_token.encode('utf-8').decode("utf-8")})
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


# Flask route for protected resource
@app.route('/protected', methods=['GET'])
# @jwt_required()
def protected():
    # Get JWT token from request header
    token = request.headers.get('Authorization')
    print(token)
    # token = token.split(".")[-1]
    # print(token)    
    print(jwt_lib.decode(token, DevConfig.JWT_SECRET_KEY, algorithms=['HS256']))

    if not token:
        return jsonify({'error': 'Authorization header is missing'}), 401

    try:
        # Decode JWT token
        decoded_token = jwt_lib.decode(token, DevConfig.JWT_SECRET_KEY, algorithms=['HS256'])
        username = decoded_token['username']
        print(f"username: {username}")

        return jsonify({'message': f'Hello, {username}! This is a protected resource.'})
    except jwt_lib.ExpiredSignatureError:
        return jsonify({'error': 'JWT token has expired'}), 401
    except jwt_lib.InvalidTokenError:
        return jsonify({'error': 'Invalid JWT token'}), 401

# Flask route for downloading an image (protected)
@app.route('/image_download', methods=['GET'])
def image_download():
    # Get JWT token from request header
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'error': 'Authorization header is missing'}), 401

    try:
        # Decode JWT token
        decoded_token = jwt_lib.decode(token, DevConfig.JWT_SECRET_KEY, algorithms=['HS256'])
        username = decoded_token['username']
        print(f"username: {username}")

        # Here you can implement logic to serve the image file
        # For example, you can use send_file from Flask to send the image file
        return jsonify({'message': f'Hello, {username}! You are downloading an image.'})
    except jwt_lib.ExpiredSignatureError:
        return jsonify({'error': 'JWT token has expired'}), 401
    except jwt_lib.InvalidTokenError:
        return jsonify({'error': 'Invalid JWT token'}), 401

# Flask route for downloading a zip file (protected)
@app.route('/zip_file_download', methods=['GET'])
def zip_file_download():
    # Get JWT token from request header
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'error': 'Authorization header is missing'}), 401

    try:
        # Decode JWT token
        decoded_token = jwt_lib.decode(token, DevConfig.JWT_SECRET_KEY, algorithms=['HS256'])
        username = decoded_token['username']

        # Here you can implement logic to serve the zip file
        # For example, you can use send_file from Flask to send the zip file
        return jsonify({'message': f'Hello, {username}! You are downloading a zip file.'})
    except jwt_lib.ExpiredSignatureError:
        return jsonify({'error': 'JWT token has expired'}), 401
    except jwt_lib.InvalidTokenError:
        return jsonify({'error': 'Invalid JWT token'}), 401


CORS(
    app=app,
    origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
    ],
    supports_credentials=True,
    allow_headers="*",
)

@app.route("/authorize")
def authorize():
    token = github.authorize_access_token()
    resp = github.get('user', token=token)
    profile = resp.json()
    # do something with the token and profile

    print(profile, token)
    print(jsonify({"access_token":token, "jwt_token":"just a dummy"}))
    return jsonify({"access_token":token, "jwt_token":"just a dummy"})

# This is required since if this is not there, then OPTIONS requests for
# the APIs exposed by the supertokens' Middleware will return a 404
@app.route('/', defaults={'u_path': ''})  
@app.route('/<path:u_path>')  
def catch_all(u_path: str):
    abort(404)



if __name__ == '__main__':
    load_dotenv()
    app.run(debug=True)