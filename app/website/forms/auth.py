from flask import flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, ValidationError, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, Email, EqualTo, InputRequired
from zxcvbn import zxcvbn

from ..models import User


class RegistrationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Length(min=3, max=40),
            Regexp(
                r'^[a-zA-Z0-9_.-]+$',
                message='Username can only contain letters, numbers, dots, underscores, and dashes.')]
    )
    email = StringField(
        'E-mail address',
        validators=[DataRequired(), Length(min=3, max=40), Email()]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=8)]
    )
    confirm_password = PasswordField(
        'Confirm password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match.')
        ])


    def validate_password(self, password):
        analysis = zxcvbn(password.data)
        score = analysis['score']
        if score < 3:
            raise ValidationError('Password is too weak. Try adding more complexity.')
        suggestions = ", ".join(analysis['feedback']['suggestions'])
        if suggestions:
            flash(f'Password suggestions: {suggestions}', 'info')

    def validate(self, extra_validators):
        if not super().validate():
            return False

        # check if given username or email already exists
        if User.query.filter_by(username=self.username.data).first() or User.query.filter_by(email=self.email.data).first():
            flash('Please choose a different email or username.', 'danger')
            return False

        return True



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=40)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])


class TwoFactorForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[
                      InputRequired(), Length(min=6, max=6)])


class ResetPasswordRequestForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])

class ResetPasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField(
        "Repeat password", validators=[DataRequired(), EqualTo("password")]
    )

    def validate_password(self, password):
        analysis = zxcvbn(password.data)
        score = analysis['score']
        if score < 3:
            raise ValidationError('Password is too weak. Try adding more complexity.')
        suggestions = ", ".join(analysis['feedback']['suggestions'])
        if suggestions:
            flash(f'Password suggestions: {suggestions}', 'info')


class ProfileForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Length(min=3, max=40),
            Regexp(
                r'^[a-zA-Z0-9_.-]+$',
                message='Username can only contain letters, numbers, dots, underscores, and dashes.')]
    )
