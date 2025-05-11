from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    
    confirmed = db.Column(db.Boolean, default=False)         # Email verification
    kyc_status = db.Column(db.String(20), default='Pending') # KYC: Pending, Approved, Rejected
    
    wallet_address = db.Column(db.String(256))
    plan = db.Column(db.String(50))
    returns = db.Column(db.Float, default=0.0)

