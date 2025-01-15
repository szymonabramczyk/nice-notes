from flask import flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, InputRequired, Optional, Email, Regexp
from zxcvbn import zxcvbn
import re


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


    @staticmethod
    def validate_password(self, password):
        analysis = zxcvbn(password.data)
        score = analysis['score']
        if score < 3:
            raise ValidationError('Password is too weak. Try adding more complexity.')
        suggestions = ", ".join(analysis['feedback']['suggestions'])
        if suggestions:
            flash(f'Password suggestions: {suggestions}', 'info')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=40)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])

class TwoFactorForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[
                      InputRequired(), Length(min=6, max=6)])

class ResetPasswordRequestForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Submit")

class ResetPasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField(
        "Repeat password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Confirm password reset")

    @staticmethod
    def validate_password(self, password):
        analysis = zxcvbn(password.data)
        score = analysis['score']
        if score < 3:
            raise ValidationError('Password is too weak. Try adding more complexity.')
        suggestions = ", ".join(analysis['feedback']['suggestions'])
        if suggestions:
            flash(f'Password suggestions: {suggestions}', 'info')

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=120)])
    content = TextAreaField('Content', validators=[DataRequired()])
    is_encrypted = BooleanField('Encrypt this note?')
    secret_key = PasswordField('Secret key (required for encryption)', default="", validators=[Optional()])
    is_public = BooleanField('Make public?')
    shared_with = StringField('Share with (emails separated by commas)', validators=[Optional()], description='Everyone')

    @staticmethod
    def validate_shared_with(form, field):
        if field.data:
            emails = [email.strip() for email in field.data.split(',')]
            for email in emails:
                if not re.match(r'^[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$', email):
                    raise ValidationError(f"Invalid email: {email}")

class DecryptForm(FlaskForm):
    secret_key = PasswordField('Decryption key', validators=[DataRequired()])
    submit = SubmitField('Decrypt')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=40)])
    submit = SubmitField('Save changes')
