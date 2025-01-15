import base64
import hashlib

import pyotp
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy.dialects.postgresql import JSON

from . import db, bcrypt
from datetime import datetime

from .config import Config


class User(db.Model, UserMixin):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_two_factor_authentication_enabled = db.Column(
        db.Boolean, nullable=False, default=False)
    secret_token = db.Column(db.String, unique=True)
    public_key = db.Column(db.Text, nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)

    # Relation with DeviceLogin
    device_logins = db.relationship('DeviceLogin', backref='user', lazy=True)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password, rounds=Config.BCRYPT_LOG_ROUNDS)
        self.created_at = datetime.now()
        self.secret_token = pyotp.random_base32()

        # generate RSA private key
        tmp_key = RSA.generate(2048)
        private_key = tmp_key.export_key().decode()

        # encrypt private key
        encryption_key = hashlib.sha256(Config.SECRET_KEY.encode()).digest()
        cipher = AES.new(encryption_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(private_key.encode())

        self.encrypted_private_key = base64.b64encode(cipher.nonce + ciphertext).decode()
        self.public_key = tmp_key.publickey().export_key().decode('utf-8')

    def update_password(self, password):
        self.password = bcrypt.generate_password_hash(password, rounds=Config.BCRYPT_LOG_ROUNDS)

    def get_authentication_setup_uri(self):
        return pyotp.totp.TOTP(self.secret_token).provisioning_uri(
            name=self.username, issuer_name=Config.APP_NAME)

    def is_otp_valid(self, user_otp):
        totp = pyotp.parse_uri(self.get_authentication_setup_uri())
        return totp.verify(user_otp)

    def generate_reset_password_token(self):
        serializer = URLSafeTimedSerializer(Config.SECRET_KEY)

        return serializer.dumps(self.email, salt=self.password)

    def validate_reset_password_token(token: str, user_id: int):
        user = db.session.get(User, user_id)

        if user is None:
            return None

        serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
        try:
            token_user_email = serializer.loads(
                token,
                max_age=Config.RESET_PASS_TOKEN_MAX_AGE,
                salt=user.password,
            )
        except (BadSignature, SignatureExpired):
            return None

        if token_user_email != user.email:
            return None

        return user

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    nonce = db.Column(db.LargeBinary, nullable=True)
    tag = db.Column(db.LargeBinary, nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    shared_with = db.Column(JSON, nullable=True)
    signature = db.Column(db.Text, nullable=True)

    # Relation with User
    author = db.relationship('User', backref='notes', lazy=True)


class DeviceLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=False)
    login_time = db.Column(db.DateTime, default=db.func.now())



