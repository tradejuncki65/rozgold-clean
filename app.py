from flask import Flask, render_template, request
from datetime import datetime, timedelta
import uuid
import json
import os

app = Flask(__name__)

USERS_FILE = 'users.json'

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({}, f)

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/whitepaper')
def whitepaper():
    return render_template('whitepaper.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    users = load_users()
    if request.method == 'POST':
        wallet = request.form.get('wallet')
        referral = request.form.get('referral')
        user_id = str(uuid.uuid4())
        start_date = datetime.now()
        end_date = start_date + timedelta(days=240)

        users[user_id] = {
            'wallet': wallet,
            'referral': referral,
            'tokens': 50 if referral else 0,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'referral_code': user_id[:8],
            'referred_users': 0
        }

        save_users(users)
        return render_template('dashboard.html', user=users[user_id])

    return render_template('wallet_form.html')

@app.route('/referral/<ref_code>')
def referral_join(ref_code):
    return render_template('wallet_form.html', ref_code=ref_code)

import os
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
