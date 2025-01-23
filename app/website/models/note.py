from datetime import datetime

from sqlalchemy.dialects.postgresql import JSON

from .. import db


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
