# Vulnerable Flask app - TEST FIXTURE for ai-rsk detection
from flask import Flask, request, jsonify
import os
import requests
import marshal
import shelve
import jwt

app = Flask(__name__)

# Flask debug mode in production
app.run(debug=True, host='0.0.0.0', port=5000)

# os.system with potential user input
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    os.system(f'ping -c 1 {host}')
    return 'OK'

# requests without timeout
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text

# marshal deserialization
@app.route('/load-data')
def load_data():
    raw = request.data
    data = marshal.loads(raw)
    return jsonify(data)

# shelve with untrusted data
@app.route('/shelf')
def read_shelf():
    db = shelve.open('user_data')
    return str(db.get('key', 'none'))

# SQL injection via f-string
@app.route('/user/<user_id>')
def get_user(user_id):
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return jsonify(cursor.fetchone())

# JWT decode without verification
@app.route('/profile')
def profile():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = jwt.decode(token, options={"verify_signature": False})
    return jsonify(payload)

# eval with user input
@app.route('/calc')
def calc():
    expr = request.args.get('expression')
    result = eval(request.args.get('expr'))
    return str(result)
