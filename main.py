from flask import Flask, jsonify, request
from flask_jwt_simple import (
    JWTManager, jwt_required, create_jwt, get_jwt_identity
)
import json
import requests
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


# Setup the Flask-JWT-Simple extension
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)


# Provide a method to create access tokens. The create_jwt()
# function is used to actually generate the token
@app.route('/login', methods=['GET'])
def login():
    token = request.args.get('token')

    if token:
        url = "https://www.googleapis.com/oauth2/v1/userinfo?access_token=" + token
        response = requests.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            username = data['email']
            ret = {'jwt': create_jwt(identity=username)}
            print('*'*30, username, jsonify(ret))
            return jsonify(ret), 200    
        else:
            return jsonify({"msg": "Not valid token"}), 400
    else:
        return jsonify({"msg": "Missing token"}), 400

# Protect a view with jwt_required, which requires a valid jwt
# to be present in the headers.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    return jsonify({'hello_from': get_jwt_identity()}), 200

if __name__ == '__main__':
    app.run(debug = True, port = 8889)