import random
import time

from flask import Blueprint, flash, redirect, url_for, render_template, request, session
from flask_limiter import RateLimitExceeded
from flask_login import login_user, login_required, logout_user, current_user

from . import bcrypt, db, limiter
from .forms import RegistrationForm, LoginForm, TwoFactorForm, ResetPasswordRequestForm, ResetPasswordForm, \
    ProfileForm
from .models import User, DeviceLogin
from .utils import get_b64encoded_qr_image, send_reset_password_email, notify_new_device, get_client_ip, decrypt_secret

HOME_URL = 'views.list_notes'
SETUP_2FA_URL = 'auth.setup_two_factor_auth'
VERIFY_2FA_URL = 'auth.verify_two_factor_auth'

auth = Blueprint('auth', __name__)

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash('You are already registered.', 'info')
            return redirect(url_for(HOME_URL))
        else:
            flash('You have not enabled 2-Factor Authentication. Please enable first to login.', 'info')
            return redirect(url_for(SETUP_2FA_URL))
    form = RegistrationForm(request.form)
    if form.validate_on_submit():
        try:
            user = User(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data
            )
            db.session.add(user)
            db.session.commit()
            device_login = DeviceLogin(
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(device_login)
            db.session.commit()
            session['uid'] = user.id
            flash('You are registered. You have to enable 2-Factor Authentication first to login.', 'success')
            return redirect(url_for(SETUP_2FA_URL))
        except Exception:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')
    return render_template('register.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=['POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash('You are already logged in.', 'info')
            return redirect(url_for(HOME_URL))
        else:
            flash('You have not enabled 2-Factor Authentication. Please enable first to login.', 'info')
            return redirect(url_for(SETUP_2FA_URL))

    form = LoginForm(request.form)

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                ip_address = get_client_ip()
                user_agent = request.user_agent.string

                # check if the device is new
                existing_device = DeviceLogin.query.filter_by(
                    user_id=user.id, ip_address=ip_address, user_agent=user_agent
                ).first()

                if not existing_device:
                    device_login = DeviceLogin(
                        user_id=user.id,
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                    db.session.add(device_login)
                    db.session.commit()

                    # send a notifying email
                    notify_new_device(user, device_login)

                session['uid'] = user.id
                if not user.is_two_factor_authentication_enabled:
                    flash(
                        'You have not enabled 2-Factor Authentication. Please enable first to login.', 'info')
                    return redirect(url_for(SETUP_2FA_URL))
                return redirect(url_for(VERIFY_2FA_URL))
            else:
                time.sleep(0.5)
                flash('Invalid username and/or password.', 'danger')
        else:
            time.sleep(0.5)
            flash('Invalid username and/or password.', 'danger')

    return render_template('login.html', form=form)


@auth.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    flash("Too many requests. Please try again later.", "danger")
    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('uid', default=None)
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))


@auth.route('/setup-2fa')
def setup_two_factor_auth():
    if current_user.is_authenticated:
        user = current_user
    else:
        tmp_uid = session.get('uid')
        user = User.query.filter_by(id=tmp_uid).first()

    secret = decrypt_secret(user.secret_token)
    uri = user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template('setup-2fa.html', secret=secret, qr_image=base64_qr_image)


@auth.route('/verify-2fa', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=['POST'])
def verify_two_factor_auth():
    if current_user.is_authenticated:
        return redirect(url_for('views.home'))

    tmp_uid= session.get('uid')
    if not tmp_uid:
        flash('Session expired or invalid access. Please log in again.', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(id=tmp_uid).first()
    if not user:
        flash('Invalid user. Please try again.', 'danger')
        return redirect(url_for('auth.login'))

    form = TwoFactorForm(request.form)
    if form.validate_on_submit():
        if user.is_otp_valid(form.otp.data):
            if user.is_two_factor_authentication_enabled:
                login_user(user)
                session.permanent = True
                flash('2FA verification successful. You are logged in!', 'success')
                return redirect(url_for(HOME_URL))
            else:
                try:
                    user.is_two_factor_authentication_enabled = True
                    db.session.commit()
                    login_user(user)
                    session.permanent = True
                    flash('2FA setup successful. You are logged in!', 'success')
                    return redirect(url_for(HOME_URL))
                except Exception:
                    db.session.rollback()
                    flash('2FA setup failed. Please try again.', 'danger')
                    return redirect(url_for(VERIFY_2FA_URL))
        else:
            time.sleep(0.3)
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for(VERIFY_2FA_URL))
    return render_template('verify-2fa.html', form=form)


@auth.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)  # fill the form with current user's data
    if form.validate_on_submit():
        current_user.username = form.username.data
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating the profile. Please try again.', 'danger')
        return redirect(url_for('auth.profile'))

    return render_template('profile.html', form=form)


@auth.route("/reset-password", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=['POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for("views.home"))

    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            send_reset_password_email(user)
            time.sleep(random.uniform(0, 0.2))
        else:
            time.sleep(random.uniform(0.8, 1.8)) # delay to hide the information whether the email exists

        flash(
        "Instructions to reset your password were sent to your email address,"
        " if it exists in our system.", "info"
        )

        return redirect(url_for("auth.reset_password_request"))

    return render_template(
        "reset-password-request.html", title="Reset Password", form=form
    )

@auth.route("/reset-password/<token>/<int:user_id>", methods=["GET", "POST"])
def reset_password(token, user_id):
    if current_user.is_authenticated:
        return redirect(url_for("views.home"))

    user = User.validate_reset_password_token(token, user_id)
    if not user:
        flash("Failed to update password!", "danger")
        return redirect(url_for("auth.login"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.update_password(form.password.data)
        db.session.commit()

        flash("Password updated successfully!", "success")
        return redirect(url_for("views.home"))

    return render_template(
        "reset-password.html", title="Reset Password", form=form
    )

@auth.errorhandler(Exception)
def handle_exception(e):
    db.session.rollback()
    flash('An error occurred.', 'danger')
    return redirect(url_for('auth.login'))