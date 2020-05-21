from datetime import datetime
import uuid

from sqlalchemy.dialects.postgresql import UUID

from sqlalchemy_serializer import SerializerMixin
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


class Company(db.Model):

    __tablename__ = 'companies'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    user_id = db.Column(UUID(as_uuid=True), primary_key=False, unique=True, nullable=False)
    name = db.Column(db.String(120), unique=False, nullable=False)
    phone = db.Column(db.String(16), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __init__(self, user_id, name, phone, email):
        self.user_id = user_id
        self.name = name
        self.phone = phone
        self.email = email

    def __repr__(self):
        return '<Company %r>' % self.name


class CompanyAddress(db.Model):

    __tablename__ = 'company_addresses'

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(UUID(as_uuid=True), primary_key=False, unique=True, nullable=False)
    street = db.Column(db.String(120), unique=False, nullable=False)
    state_id = db.Column(db.Integer, nullable=False)
    city_id = db.Column(db.Integer, nullable=False)
    zip_code = db.Column(db.String(10), unique=False, nullable=True)

    def __init__(self, company_id, street, state_id, city_id):
        self.company_id = company_id
        self.street = street
        self.state_id = state_id
        self.city_id = city_id

    def __repr__(self):
        return '<CompanyAddress %r>' % self.id


class CompanyUser(db.Model):

    __tablename__ = 'company_users'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(UUID(as_uuid=True), primary_key=False, unique=True, nullable=False)
    company_id = db.Column(UUID(as_uuid=True), primary_key=False, unique=False, nullable=False)
    role = db.Column(db.Integer, nullable=True, default=1)

    def __init__(self, user_id, company_id):
        self.user_id = user_id
        self.company_id = company_id

    def __repr__(self):
        return '<CompanyUser %r>' % self.company_id

class State(db.Model, SerializerMixin):

    __tablename__ = 'states'

    id = db.Column(db.Integer, primary_key=True)
    state_code = db.Column(db.String(2), unique=False, nullable=False)
    state_name = db.Column(db.String(50), unique=False, nullable=False)

    def __init__(self, state_code, state_name):
        self.state_code = state_code
        self.state_name = state_name

    def __repr__(self):
        return '<State %r>' % self.state_name


class City(db.Model, SerializerMixin):

    __tablename__ = 'cities'

    id = db.Column(db.Integer, primary_key=True)
    state_id = db.Column(db.Integer)
    city = db.Column(db.String(50), unique=False, nullable=False)
    county = db.Column(db.String(50), unique=False, nullable=False)
    latitude = db.Column(db.Numeric(), nullable=False)
    longitude = db.Column(db.Numeric(), nullable=False)

    def __init__(self, state_id, city, county, latitude, longitude):
        self.state_id = state_id
        self.city = city
        self.county = county
        self.latitude = latitude
        self.longitude = longitude

    def __repr__(self):
        return '<City %r>' % self.city
