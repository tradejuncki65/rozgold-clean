# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # Basic account info
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

    # Email verification
    confirmed = db.Column(db.Boolean, default=False)

    # Wallet & Plan
    wallet_address = db.Column(db.String(256))
    plan = db.Column(db.String(50), default='Free')
    returns = db.Column(db.Float, default=0.0)

    # KYC Information
    full_name = db.Column(db.String(150))
    national_id = db.Column(db.String(100))
    country = db.Column(db.String(100))
    kyc_status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected

    # Admin flag
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<User {self.username} | {self.email}>"



