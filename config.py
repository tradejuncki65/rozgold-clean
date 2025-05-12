import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'rtbu updz dugu hsxd ')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'tradejunction65@gmail.com'
    MAIL_PASSWORD = 'rtbu updz dugu hsxd ' 
    MAIL_DEFAULT_SENDER = 'tradejunction65@gmail.com'
    MAIL_SUPPRESS_SEND = False
    MAIL_DEBUG = True

