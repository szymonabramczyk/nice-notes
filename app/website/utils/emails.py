from flask import url_for, render_template_string
from flask_mailman import EmailMessage




def send_reset_password_email(user):
    from . import encode_id

    reset_password_url = url_for(
        "auth.reset_password",
        token=user.generate_reset_password_token(),
        encoded_id=encode_id(user.id),
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
