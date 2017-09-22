from flask import Flask, jsonify, request
from flask_jwt_simple import (
    JWTManager, jwt_required, create_jwt, get_jwt_identity, get_jwt
)
import json
import requests
from flask_cors import CORS 
from flask_restful import Resource, Api

app = Flask(__name__)

CORS(app)
api = Api(app)
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)


def has_role(role):
    def decorator(f):
        @jwt_required
        def helper(self):          
            roles = get_jwt_identity().get('roles', [])
            if role not in roles:
                return 'Not role ' + role, 400
            return f(self)
        return helper
    return decorator


class User(Resource):
    def get(self):
        token = request.args.get('token')
        print(token)
        if(token):
            url = "https://www.googleapis.com/oauth2/v1/userinfo?access_token=" + token
            response = requests.get(url)
            if response.status_code == 200:
                data = json.loads(response.text)
                email = data['email']    
                return {'jwt': create_jwt(identity={'email': email, 'roles': ['admin']})}, 200
            else:
                return 'Not valid token', 400
        else:
            return 'Missing token', 400

class Protected(Resource):
    @has_role('admin')    
    def get(self):
        return {'hello_from': get_jwt_identity()}, 200

api.add_resource(User, '/login')
api.add_resource(Protected, '/protected')


if __name__ == '__main__':
    app.run(debug=True, port=8889)
