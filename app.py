from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from config import Config
from models import db, User, InvestmentPlan, Investment

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        msg = Message('Confirm Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Welcome to Roz Gold!\n\nPlease confirm your email: {link}'
        mail.send(msg)

        flash("Registration successful. Check your email to confirm.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.confirmed = True
            db.session.commit()
            flash("Email confirmed. Please login.")
            return redirect(url_for('login'))
    except SignatureExpired:
        flash("Confirmation link expired.")
        return redirect(url_for('register'))
    flash("Invalid confirmation link.")
    return redirect(url_for('register'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.confirmed:
                flash("Please confirm your email.")
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Invalid login.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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
        db.session.commit()
        flash("Account updated.")
        return redirect(url_for('dashboard'))
    return render_template('account.html', user=current_user)

@app.route('/kyc', methods=['GET', 'POST'])
@login_required
def kyc():
    if request.method == 'POST':
        current_user.kyc_status = 'Pending'
        db.session.commit()
        flash("KYC submitted.")
        return redirect(url_for('dashboard'))
    return render_template('kyc.html', user=current_user)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin/dashboard.html', users=users)

@app.route('/admin/verify/<int:user_id>/<status>')
@login_required
def verify_kyc(user_id, status):
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    user.kyc_status = status
    db.session.commit()
    flash(f"KYC {status} for {user.username}")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/investment-plans')
@login_required
def investment_plans():
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    plans = InvestmentPlan.query.all()
    return render_template('admin/investment_plans.html', plans=plans)

@app.route('/admin/add-plan', methods=['GET', 'POST'])
@login_required
def add_plan():
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        new_plan = InvestmentPlan(
            name=request.form['name'],
            description=request.form['description'],
            roi=float(request.form['roi']),
            duration_days=int(request.form['duration']),
            min_amount=float(request.form['min_amount']),
            max_amount=float(request.form['max_amount'])
        )
        db.session.add(new_plan)
        db.session.commit()
        flash("Plan added.")
        return redirect(url_for('investment_plans'))
    return render_template('admin/add_plan.html')

@app.route('/invest', methods=['GET', 'POST'])
@login_required
def invest():
    plans = InvestmentPlan.query.all()
    if request.method == 'POST':
        selected_plan = InvestmentPlan.query.get(int(request.form['plan_id']))
        amount = float(request.form['amount'])

        if amount < selected_plan.min_amount or amount > selected_plan.max_amount:
            flash("Amount out of allowed range.")
            return redirect(url_for('invest'))

        roi = selected_plan.roi
        new_inv = Investment(
            user_id=current_user.id,
            plan=selected_plan.name,
            amount=amount,
            roi=roi
        )
        db.session.add(new_inv)
        db.session.commit()
        flash(f"Invested ${amount} in {selected_plan.name} plan.")
        return redirect(url_for('my_investments'))

    return render_template('invest.html', plans=plans)

@app.route('/my-investments')
@login_required
def my_investments():
    investments = Investment.query.filter_by(user_id=current_user.id).all()
    return render_template('my_investments.html', investments=investments)

@app.route('/create-tables')
def create_tables():
    db.create_all()
    return "Tables created!"

if __name__ == '__main__':
    app.run(debug=True)










