# Safe Flask app - proper security practices - TEST FIXTURE
from flask import Flask, request, jsonify
import os
import subprocess
import requests
import json
import ast
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')

# No debug=True - use FLASK_DEBUG env var

# subprocess with shell=False instead of os.system
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    if not host.replace('.', '').replace('-', '').isalnum():
        return 'Invalid host', 400
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True)
    return result.stdout

# requests WITH timeout
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url, timeout=10)
    return response.text

# JSON instead of marshal
@app.route('/load-data')
def load_data():
    data = json.loads(request.data)
    return jsonify(data)

# Parameterized query
@app.route('/user/<int:user_id>')
def get_user(user_id):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return jsonify(cursor.fetchone())

# JWT WITH verification
@app.route('/profile')
def profile():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    return jsonify(payload)

# ast.literal_eval instead of eval
@app.route('/calc')
def calc():
    expr = request.args.get('expr', '0')
    result = ast.literal_eval(expr)
    return str(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
