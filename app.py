from flask import Flask, jsonify, request
from flask_cors import CORS
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'FlareSecurity_Secret_Key_2026' # Change this for production

# Token Verification Middleware
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or "Bearer " not in token:
            return jsonify({'message': 'Authorization header missing!'}), 401
        try:
            token = token.split(" ")[1]
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token expired or invalid!'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    if auth and auth.get('password') == 'admin123': # Basic admin check
        token = jwt.encode({
            'user': 'Admin',
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) # 30 min expiry as requested
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid Credentials'}), 401

@app.route('/api/logs', methods=['GET'])
@token_required
def get_logs():
    # Mock logs for TECH FLARE
    return jsonify([
        {"id": 1, "sender": "spoof@hacker.com", "subject": "Urgent Update", "type": "Phishing"},
        {"id": 2, "sender": "ceo@techflare.com", "subject": "Quarterly Report", "type": "Safe"}
    ])

if __name__ == '__main__':
    app.run(debug=True)