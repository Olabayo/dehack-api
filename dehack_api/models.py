from datetime import datetime
import uuid

from sqlalchemy.dialects.postgresql import UUID
from .app import db

class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=False, nullable=False)
    first_name = db.Column(db.String(120), unique=False, nullable=False)
    last_name = db.Column(db.String(120), unique=False, nullable=False)
    status = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, email, password, first_name, last_name):
        self.email = email
        self.password = password
        self.first_name = first_name
        self.last_name = last_name

    def __repr__(self):
        return '<User %r>' % self.first_name


class RegistrationProfile(db.Model):

    __tablename = 'registration_profiles'

    user_id = db.Column(UUID(as_uuid=True), primary_key=False, unique=True, nullable=False)
    activation_key = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, user_id):
        self.user_id = user_id

    def __repr__(self):
        return '<RegistrationProfile %r>' % self.user_id


class PasswordReset(db.Model):

    __tablename = 'password_resets'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    reset_key = db.Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, email):
        self.email = email

    def __repr__(self):
        return '<PasswordReset %r>' % self.email
