import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'roz_gold_secret_key')

    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email Configuration (for Gmail SMTP)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')  # set in Render env vars
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')  # set in Render env vars
