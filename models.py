from datetime import datetime
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

class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    plan = db.Column(db.String(50))
    amount = db.Column(db.Float)
    roi = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



