import base64
from io import BytesIO

import qrcode
from base64 import b64encode

import nh3
from flask import request
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA


def get_b64encoded_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")


def sanitize_content(content):
    allowed_tags = {'b', 'i', 'u', 'a', 'p', 'br', 'em', 'strong', 'h1', 'h2', 'h3', 'h4', 'h5', 'img'}
    cleaned = nh3.clean(content.strip(), tags=allowed_tags)
    return cleaned


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr


def generate_signature(content, private_key_pem, is_encrypted):
    try:
        private_key = RSA.import_key(private_key_pem)
        content_bytes = content if is_encrypted else content.encode()
        hash_obj = SHA256.new(content_bytes)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return base64.b64encode(signature).decode()
    except Exception:
        return None


def verify_signature(content, signature, public_key_pem, is_encrypted):
    if not public_key_pem:
        return False
    try:
        public_key = RSA.import_key(public_key_pem)
        content_bytes = content if is_encrypted else content.encode()
        hash_obj = SHA256.new(content_bytes)
        pkcs1_15.new(public_key).verify(hash_obj, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False
