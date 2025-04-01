import os
from os import path
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mailman import Mail
from flask_talisman import Talisman
from flask_paranoid import Paranoid
from dotenv import load_dotenv


project_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../.env'))
load_dotenv(project_path)

from .config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
csrf = CSRFProtect()
limiter = Limiter(get_remote_address)
mail = Mail()
paranoid = Paranoid()

DB_NAME = "database.db"

def create_app():

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    paranoid.init_app(app)

    paranoid.redirect_view = '/'

    csp = {
        'default-src': [
            '\'self\''
        ],
        'img-src': [
            'https:',
            'data:'
        ],
        'style-src': [
            '\'self\'',
            'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css'
        ],
        'script-src': [
            '\'self\'',
            'https://code.jquery.com/jquery-3.7.1.min.js',
            'https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js',
            'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.min.js'
        ]
    }

    talisman = Talisman(app, content_security_policy=csp, content_security_policy_nonce_in=['style-src', 'script-src'])

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models.note import Note
    from .models.user import User
    from .models.device_login import DeviceLogin

    create_database(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.filter(User.id == user_id).first()

    return app

def create_database(app):
    with app.app_context():
        if not path.exists('instance/' + DB_NAME):
            db.create_all()
            print('Created database!')




