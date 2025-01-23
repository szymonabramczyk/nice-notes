import os

DB_NAME = "database.db"
DATABASE_URI = f'sqlite:///{DB_NAME}'


class Config(object):
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_LOG_ROUNDS = 13
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    APP_NAME = "NiceNotes"
    MAX_CONTENT_LENGTH= 1 * 1024 * 1024  # 1 MB
    SESSION_COOKIE_HTTPONLY = True
    # SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Lax' # prevents cookies from being sent in requests between domains

    RESET_PASS_TOKEN_MAX_AGE = 15 * 60
    PERMANENT_SESSION_LIFETIME = 15 * 60 # 15 mins

    # mail configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('DEFAULT_MAIL_SENDER')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    DEFAULT_MAIL_SENDER = ('NiceNotes', os.environ.get('DEFAULT_MAIL_SENDER'))


# class ProductionConfig(Config):
#     DEBUG = False
#     DEBUG_TB_ENABLED = False