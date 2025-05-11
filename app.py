from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from urllib.parse import urlparse, urljoin
import os

from config import Config
from models import db, User

# -------------------- INIT --------------------
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
mail = Mail(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# -------------------- FILE UPLOAD CONFIG --------------------
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# -------------------- UTILS --------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirmation-salt')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        return serializer.loads(token, salt='email-confirmation-salt', max_age=expiration)
    except:
        return False

def send_email(to, subject, template, **kwargs):
    msg = Message(subject, recipients=[to],
                  html=render_template(template, **kwargs),
                  sender=app.config['MAIL_USERNAME'])
    mail.send(msg)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

# -------------------- ROUTES --------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(email=email).first():
            flash("Email already exists.")
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        token = generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        send_email(email, 'Confirm Your Email', 'email/confirm.html', confirm_url=confirm_url, user=new_user)

        flash('A confirmation email has been sent.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash('Invalid or expired confirmation link.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed.')
    else:
        user.confirmed = True
        db.session.commit()
        send_email(user.email, 'Welcome to Roz Gold', 'email/welcome.html', user=user)
        flash('Account verified. Welcome!')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Login failed.")
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        current_user.wallet_address = request.form['wallet']
        current_user.plan = request.form['plan']
        investment_amount = 1000
        roi_map = {'Free': 0.2, 'Premium': 0.4, 'VIP': 0.6}
        roi = roi_map.get(current_user.plan, 0.2)
        current_user.returns = investment_amount * roi
        db.session.commit()
        flash("Account updated.")
        return redirect(url_for('dashboard'))
    return render_template('account.html', user=current_user)

@app.route('/kyc', methods=['GET', 'POST'])
@login_required
def kyc():
    if request.method == 'POST':
        id_doc = request.files['id_doc']
        selfie = request.files['selfie']

        if id_doc and allowed_file(id_doc.filename) and selfie and allowed_file(selfie.filename):
            id_filename = secure_filename(f"{current_user.id}_id_{id_doc.filename}")
            selfie_filename = secure_filename(f"{current_user.id}_selfie_{selfie.filename}")
            id_path = os.path.join(app.config['UPLOAD_FOLDER'], id_filename)
            selfie_path = os.path.join(app.config['UPLOAD_FOLDER'], selfie_filename)
            id_doc.save(id_path)
            selfie.save(selfie_path)

            current_user.kyc_status = 'Pending'
            db.session.commit()
            flash('KYC submitted. Awaiting review.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type.')
    return render_template('kyc.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# -------------------- LOCAL DEBUG --------------------
if __name__ == '__main__':
    app.run(debug=True)






