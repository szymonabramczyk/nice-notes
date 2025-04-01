from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, ValidationError, Optional
import re


class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=120)])
    content = TextAreaField('Content', validators=[DataRequired(), Length(max=2000)])
    is_encrypted = BooleanField('Encrypt this note?')
    secret_key = PasswordField('Secret key (required for encryption)', default="", validators=[Optional()])
    is_public = BooleanField('Make public?')
    shared_with = StringField('Share with (emails separated by commas)', validators=[Optional()], description='Everyone')

    def validate_shared_with(form, field):
        if field.data:
            emails = [email.strip() for email in field.data.split(',')]
            for email in emails:
                if not re.match(r'^[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$', email):
                    raise ValidationError(f"Invalid email: {email}")

    def validate(self, extra_validators):
        if not super().validate():
            return False

        # secret key is required when note should be encrypted
        if self.is_encrypted.data and not self.secret_key.data:
            self.secret_key.errors.append("Secret key is required when encryption is enabled.")
            return False

        return True

class DecryptForm(FlaskForm):
    secret_key = PasswordField('Decryption key', validators=[DataRequired()])
    submit = SubmitField('Decrypt')

