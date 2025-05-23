from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(200))
    wallet_address = db.Column(db.String(255))
    plan = db.Column(db.String(100))
    returns = db.Column(db.Float)
    kyc_status = db.Column(db.String(50), default='Not Submitted')
    kyc_document = db.Column(db.String(255))
    full_name = db.Column(db.String(100))
    national_id = db.Column(db.String(100))
    country = db.Column(db.String(100))
    confirmed = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    investments = db.relationship('Investment', backref='user', lazy=True)

class InvestmentPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    roi = db.Column(db.Float, nullable=False)
    duration_days = db.Column(db.Integer, nullable=False)
    min_amount = db.Column(db.Float, nullable=False)
    max_amount = db.Column(db.Float, nullable=False)

class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plan = db.Column(db.String(50))
    amount = db.Column(db.Float)
    roi = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime)
    is_withdrawn = db.Column(db.Boolean, default=False)
    is_withdrawal_requested = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def status(self):
        if self.is_withdrawn:
            return "Withdrawn"
        elif self.is_withdrawal_requested:
            return "Requested"
        elif datetime.utcnow() >= self.due_date:
            return "Matured"
        else:
            return "Pending"
