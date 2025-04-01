import base64
import hashlib
import uuid

import pyotp
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from .. import db, bcrypt, Config
from ..utils import decrypt_secret


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.String(36), primary_key=True, default=lambda: User.generate_unique_id(), unique=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_two_factor_authentication_enabled = db.Column(
        db.Boolean, nullable=False, default=False)
    secret_token = db.Column(db.Text, unique=True)
    public_key = db.Column(db.Text, nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)

    # Relation with DeviceLogin
    device_logins = db.relationship('DeviceLogin', backref='user', lazy=True)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password, rounds=Config.BCRYPT_LOG_ROUNDS)

        # generate secret token
        raw_secret_token = pyotp.random_base32()

        # encrypt secret token
        encryption_key = hashlib.sha256(Config.SECRET_KEY_SECRET_TOKEN.encode()).digest()
        aes = AES.new(encryption_key, AES.MODE_GCM)
        ciphertext, tag = aes.encrypt_and_digest(raw_secret_token.encode())
        self.secret_token = base64.b64encode(aes.nonce + tag + ciphertext).decode()

        # generate RSA private key
        tmp_key = RSA.generate(2048)
        private_key = tmp_key.export_key().decode()

        # encrypt private key
        aes = AES.new(encryption_key, AES.MODE_GCM)
        ciphertext, tag = aes.encrypt_and_digest(private_key.encode())
        self.encrypted_private_key = base64.b64encode(aes.nonce + tag + ciphertext).decode()
        self.public_key = tmp_key.publickey().export_key().decode('utf-8')

    @staticmethod
    def generate_unique_id():
        while True:
            new_id = str(uuid.uuid4())
            if not User.query.filter_by(id=new_id).first():
                return new_id

    def update_password(self, password):
        self.password = bcrypt.generate_password_hash(password, rounds=Config.BCRYPT_LOG_ROUNDS)

    def get_authentication_setup_uri(self):
        return pyotp.totp.TOTP(decrypt_secret(self.secret_token)).provisioning_uri(
            name=self.username, issuer_name=Config.APP_NAME)

    def is_otp_valid(self, user_otp):
        totp = pyotp.parse_uri(self.get_authentication_setup_uri())
        return totp.verify(user_otp)

    def generate_reset_password_token(self):
        serializer = URLSafeTimedSerializer(Config.SECRET_KEY_RESET_PASSWORD_TOKEN)

        return serializer.dumps(self.email, salt=self.password)

    @staticmethod
    def validate_reset_password_token(token, user_id):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return None

        serializer = URLSafeTimedSerializer(Config.SECRET_KEY_RESET_PASSWORD_TOKEN)
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
