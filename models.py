# models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

    confirmed = db.Column(db.Boolean, default=False)  # Email verification status
    kyc_status = db.Column(db.String(20), default='Pending')  # 'Pending', 'Approved', 'Rejected'
    is_admin = db.Column(db.Boolean, default=False)  # Admin access flag

    wallet_address = db.Column(db.String(256))
    plan = db.Column(db.String(50), default='Free')
    returns = db.Column(db.Float, default=0.0)

    def __repr__(self):
        return f"<User {self.username} | {self.email}>"


