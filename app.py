from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)
CORS(app) # Frontend connectivity ke liye
app.config['SECRET_KEY'] = 'Flare_Security_Admin_2026'

# --- JWT Protection Middleware ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or "Bearer " not in token:
            return jsonify({'message': 'Token missing!'}), 401
        try:
            token = token.split(" ")[1]
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Session expired!'}), 401
        return f(*args, **kwargs)
    return decorated

# --- FIX: Serve index.html at Home Path ---
@app.route('/')
def home():
    # Yeh line 404 error fix karegi
    return send_from_directory('', 'index.html')

# --- Login Endpoint ---
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if data and data.get('password') == 'admin123':
        token = jwt.encode({
            'user': 'Admin',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return jsonify({'message': 'Login Failed'}), 401

# --- Email Logs API ---
@app.route('/api/logs', methods=['GET'])
@token_required
def get_logs():
    # Mock data for TECH FLARE
    return jsonify([
        {"sender": "spoof@hacker.io", "subject": "Bank Alert", "type": "Phishing"},
        {"sender": "hr@techflare.com", "subject": "Policy Update", "type": "Safe"},
        {"sender": "support@google.com", "subject": "Sign-in attempt", "type": "Suspicious"}
    ])

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
