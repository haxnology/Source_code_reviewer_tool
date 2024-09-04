from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import os
from datetime import datetime, timedelta
from functools import wraps
from scanner import StaticCodeAnalyzer  # Ensure scanner.py exists and is correctly implemented

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_default_secret_key')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            token = token.split(" ")[1]  # Extract the token part
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.user = data['username']  # Set the current user to the request context
            request.role = data['role']  # Set the current user role to the request context
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Replace this with your actual authentication logic
    if username == 'admin' and password == 'password':
        token = jwt.encode({
            'username': username,
            'role': 'admin',  # Assign a role to the user
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'access_token': token})

    return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    # Implement registration logic here
    # For now, we'll just simulate a successful registration
    return jsonify({'message': 'User registered successfully!'}), 200

@app.route('/scan', methods=['POST'])
@token_required
def scan():
    data = request.get_json()
    code = data.get('code')

    if request.role != 'admin':
        return jsonify({'message': 'You do not have the required role to perform this action.'}), 403

    analyzer = StaticCodeAnalyzer()
    results = analyzer.analyze_code(code)
    return jsonify(results)

if __name__ == '__main__':
    app.run(port=5000)
