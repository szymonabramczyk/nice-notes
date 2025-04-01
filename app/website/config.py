import os

DB_NAME = "database.db"
DATABASE_URI = f'sqlite:///{DB_NAME}'


class Config(object):
    DEBUG = False
    TESTING = False
    APP_NAME = "NiceNotes"
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MB

    CSRF_ENABLED = True
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SECRET_KEY_SECRET_TOKEN = os.environ.get('SECRET_KEY_SECRET_TOKEN')
    SECRET_KEY_RESET_PASSWORD_TOKEN = os.environ.get('SECRET_KEY_RESET_PASSWORD_TOKEN')
    SECRET_KEY_ENCODE_ID = os.environ.get('SECRET_KEY_ENCODE_ID')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # protect against cross-site request forgery
    PERMANENT_SESSION_LIFETIME = 15 * 60  # 15 mins

    # database
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # flask-wtf
    WTF_CSRF_ENABLED = True

    # debug
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False

    # password hashing
    BCRYPT_LOG_ROUNDS = 13

    # password reset token
    RESET_PASS_TOKEN_MAX_AGE = 15 * 60

    # mail
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('DEFAULT_MAIL_SENDER')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    DEFAULT_MAIL_SENDER = ('NiceNotes', os.environ.get('DEFAULT_MAIL_SENDER'))
