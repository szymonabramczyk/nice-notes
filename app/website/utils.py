from io import BytesIO

import qrcode
from base64 import b64encode

from Crypto.Cipher import AES
import nh3
from flask import url_for, render_template_string, request
from flask_mailman import EmailMessage


def get_b64encoded_qr_image(data):
    print(data)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")


def encrypt(plaintext, key):
  aes = AES.new(key, AES.MODE_GCM)
  ciphertext, tag = aes.encrypt_and_digest(plaintext)
  return ciphertext, tag, aes.nonce


def decrypt(content, key, nonce, tag):
    aes = AES.new(key, AES.MODE_GCM, nonce)
    return aes.decrypt_and_verify(content, tag)


def sanitize_content(content):
    allowed_tags = {'b', 'i', 'u', 'a', 'p', 'br', 'em', 'strong', 'h1', 'h2', 'h3', 'h4', 'h5', 'img'}
    print(content)
    cleaned = nh3.clean(content.strip(), tags=allowed_tags)
    print(cleaned)
    return cleaned


def send_reset_password_email(user):
    reset_password_url = url_for(
        "auth.reset_password",
        token=user.generate_reset_password_token(),
        user_id=user.id,
        _external=True,
    )

    reset_password_email_html_content = """
    <h1> Nice Notes </h1>
    <p>You are receiving this email because someone requested a password reset for your account.</p>
    <p>
        To reset your password
        <a href="{{ reset_password_url }}">click here</a>.
    </p>
    <p>
        Alternatively, you can paste the following link in your browser's address bar: <br>
        {{ reset_password_url }}
    </p>
    <p>If it is not you, who have requested a password reset, please change your password immediately.</p>
    <p>
        Thank you!
    </p>
    """

    email_body = render_template_string(
        reset_password_email_html_content, reset_password_url=reset_password_url
    )

    message = EmailMessage(
        subject="Reset your password",
        body=email_body,
        to=[user.email],
    )
    message.content_subtype = "html"

    message.send()


def notify_new_device(user, device):

    notify_new_device_email_html_content = """
    <h1> Nice Notes </h1>
    <p>A new device has accessed your account:</p>

    <p>IP Address: {{ ip_address }}</p>
    <p>User Agent: {{ user_agent }}</p>
    <p>Time: {{ login_time }}</p>

    <p>If this was not you, please change your password immediately and review your account security.</p>
    """

    email_body = render_template_string(
        notify_new_device_email_html_content,
        ip_address = device.ip_address,
        user_agent = device.user_agent,
        login_time = device.login_time
    )
    message = EmailMessage(
        subject="New device detected on your account",
        body=email_body,
        to=[user.email]
    )
    message.content_subtype = "html"

    message.send()



def get_client_ip():
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr
    # return request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
