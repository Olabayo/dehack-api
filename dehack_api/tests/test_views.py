import os
import tempfile

import pytest
import json

import jwt as jwtmain

from passlib.hash import sha256_crypt

from .. import app
from ..models import User, RegistrationProfile, PasswordReset, Company, CompanyAddress, CompanyUser, \
State, City, Profile, Education, WorkExperience, Job

from datetime import datetime, timedelta
import uuid

from .factory_model import UserFactory, EducationFactory, ExperienceFactory, ProfileFactory, \
CompanyFactory, CompanyAddressFactory, JobFactory


CONFIG_DEFAULTS = {
    'JWT_DEFAULT_REALM': 'Login Required',
    'JWT_AUTH_URL_RULE': '/auth',
    'JWT_AUTH_ENDPOINT': 'jwt',
    'JWT_AUTH_USERNAME_KEY': 'username',
    'JWT_AUTH_PASSWORD_KEY': 'password',
    'JWT_ALGORITHM': 'HS256',
    'JWT_LEEWAY': timedelta(seconds=10),
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'JWT_EXPIRATION_DELTA': timedelta(seconds=300),
    'JWT_NOT_BEFORE_DELTA': timedelta(seconds=0),
    'JWT_VERIFY_CLAIMS': ['signature', 'exp', 'nbf', 'iat'],
    'JWT_REQUIRED_CLAIMS': ['exp', 'iat', 'nbf']
}

def default_jwt_payload_handler(identity):
    iat = datetime.utcnow()
    exp = iat + CONFIG_DEFAULTS.get('JWT_EXPIRATION_DELTA')
    nbf = iat + CONFIG_DEFAULTS.get('JWT_NOT_BEFORE_DELTA')
    identity = identity['id']
    return {'exp': exp, 'iat': iat, 'nbf': nbf, 'identity': identity}

def gen_key(identity):
    payload = default_jwt_payload_handler(identity)
    return jwtmain.encode(payload, "super-secret", algorithm="HS256", headers=None)


@pytest.fixture
def client():
    #db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL_TEST']
    app.app.config['TESTING'] = True

    with app.app.test_client() as client:
        with app.app.app_context():
            app.init_db()
        yield client

    #os.close(db_fd)
    #os.unlink(app.config['DATABASE'])
    app.truncate_db()

def test_health(client):
    """Start with a blank database."""

    response = client.get('/')
    
    assert b'Welcome to SweetBread' in response.data

def test_create_user(client):
    """Start with a blank database."""

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehack@yahoo.com',
        'password': 'dehack'
    }
    url = '/users'
    with app.mail.record_messages() as outbox:
    
        response = client.post(url, data=json.dumps(data), headers=headers)
        ifUserExist = User.query.filter_by(email=data["email"]).first()
        ifRegProfileExist = RegistrationProfile.query.filter_by(user_id=ifUserExist.id).first()
        #assert b'Welcome to SweetBread' in rv.data
        assert bool(ifUserExist) == True
        assert bool(ifRegProfileExist) == True
        assert ifUserExist.status == False
        assert response.content_type == mimetype
        assert response.json['msg'] == 'user created'
        assert len(outbox) == 1
        #assert outbox[0].subject == "testing"

def test_activate_user(client):    

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }  
    data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehack@yahoo.com',
        'password': 'dehack'
    } 
    pass_hash = sha256_crypt.hash(data["password"])
    user = User(data["email"], pass_hash, data["first_name"], data["last_name"])
    app.db.session.add(user)
    app.db.session.flush()
    registrationProfile = RegistrationProfile(user.id)
    app.db.session.add(registrationProfile)
    app.db.session.commit()
    url = f'/activate/{registrationProfile.activation_key}'
    response = client.get(url, headers=headers)
    ifUserExist = User.query.filter_by(email=data["email"]).first()

    assert response.json['msg'] == 'user activated'
    assert ifUserExist.status == True


def test_password_reset(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    user_data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehack@yahoo.com',
        'password': 'dehack'
    } 
    pass_hash = sha256_crypt.hash(user_data["password"])
    user = User(user_data["email"], pass_hash, user_data["first_name"], user_data["last_name"])
    app.db.session.add(user)
    app.db.session.commit()
    data = {
        'email': 'dehack@yahoo.com'
    } 
    url = "/getresetkey"
    response = client.post(url, data= json.dumps(data), headers=headers)
    ifResetPassExist = PasswordReset.query.filter_by(email=data["email"]).first()
    assert bool(ifResetPassExist) == True
    assert response.json['msg'] == 'password reset setup'


def test_use_reset_key(client): 

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    user_data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehack@yahoo.com',
        'password': 'dehack'
    }
    data = {
        'password': 'password2',
        'confirm_password': 'password2'
    } 
    pass_hash = sha256_crypt.hash(user_data["password"])
    user = User(user_data["email"], pass_hash, user_data["first_name"], user_data["last_name"])
    app.db.session.add(user)
    app.db.session.flush()
    resetKey = PasswordReset(user.email)
    app.db.session.add(resetKey)
    app.db.session.commit()

    url = f'/resetpassword/{resetKey.reset_key}'
    response = client.post(url, data = json.dumps(data), headers = headers)
    userResetPass = User.query.filter_by(email = user_data["email"]).first()
    assert sha256_crypt.verify(data["password"], userResetPass.password) == True
    assert response.json['msg'] == 'password reset'


def test_auth_login(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    user_data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehack@yahoo.com',
        'password': 'dehack'
    }
    data = {
        'username': 'dehack@yahoo.com',
        'password': 'dehack'
    } 
    pass_hash = sha256_crypt.hash(user_data["password"])
    user = User(user_data["email"], pass_hash, user_data["first_name"], user_data["last_name"])
    app.db.session.add(user)
    app.db.session.commit()

    url = "/auth"
    response = client.post(url, data = json.dumps(data), headers = headers)

    assert 'access_token' in response.json


def test_protected_url(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    user_data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehack@yahoo.com',
        'password': 'dehack'
    }
    data = {
        'username': 'dehack@yahoo.com',
        'password': 'dehack'
    } 
    pass_hash = sha256_crypt.hash(user_data["password"])
    user = User(user_data["email"], pass_hash, user_data["first_name"], user_data["last_name"])
    myuuid = uuid.uuid4()
    user.id = myuuid
    app.db.session.add(user)
    app.db.session.commit()

    url = "/auth"
    #response = client.post(url, data = json.dumps(data), headers = headers)
    #assert 'access_token' in response.json
    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8') #response.json["access_token"]
    url = "/protected"
    response = client.get(url, headers = headers)
    #assert str(myuuid) == access_token.decode('utf-8')
    assert response.json["msg"] == "dehack@yahoo.com"


def test_password_change(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    user_data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehack@yahoo.com',
        'password': 'dehack'
    }
    data = {
        'username': 'dehack@yahoo.com',
        'password': 'dehack'
    } 
    pass_hash = sha256_crypt.hash(user_data["password"])
    user = User(user_data["email"], pass_hash, user_data["first_name"], user_data["last_name"])
    app.db.session.add(user)
    app.db.session.commit()

    url = "/auth"
    response = client.post(url, data = json.dumps(data), headers = headers)
    headers["Authorization"] = "JWT " + response.json["access_token"]
    data = {
        'current_password': 'dehack',
        'password': 'password2'
    }
    url = "/changepassword"
    response = client.post(url, data = json.dumps(data), headers = headers)

    assert response.json["msg"] == "password changed"
    userResetPass = User.query.filter_by(email = user_data["email"]).first()
    assert sha256_crypt.verify(data["password"], userResetPass.password) == True 


def test_create_employer(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    url = "/employers"
    data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehack@yahoo.com',
        'password': 'dehack',
        'company_name': 'Cool company name',
        'company_phone': '9893399393939',
        'company_email': 'coolcompany@email.com'
    }
    response = client.post(url, data = json.dumps(data), headers = headers)
    ifUserExist = User.query.filter_by(email=data["email"]).first()
    ifCompanyExist = Company.query.filter_by(user_id=ifUserExist.id).first()
    ifCompanyUser = CompanyUser.query.filter_by(user_id=ifUserExist.id, company_id=ifCompanyExist.id).first()
    assert bool(ifUserExist) == True
    assert bool(ifCompanyExist) == True
    assert bool(ifCompanyUser) == True
    assert response.json["msg"] == "employer created"


def test_get_states(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    url = "/states"

    stateA = State("MA", "Massachusetts")
    stateB = State("AZ", "Arizona")
    app.db.session.add(stateA)
    app.db.session.add(stateB)
    app.db.session.commit()
    response = client.get(url, headers=headers)

    assert len(response.json["states"]) > 0


def test_get_city(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    url = "/cities?state_id=1"

    stateA = State("MA", "Massachusetts")
    stateB = State("AZ", "Arizona")
    app.db.session.add(stateA)
    app.db.session.add(stateB)
    app.db.session.flush()
    cityA = City(stateA.id, "Lynn", "Essex", 42.463378,-70.945516)
    app.db.session.add(cityA)
    app.db.session.commit()
    response = client.get(url, headers=headers)

    assert len(response.json["cities"]) > 0

def test_add_company_address(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    user_data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehackk@yahoo.com',
        'password': 'dehack'
    }
    
    pass_hash = sha256_crypt.hash(user_data["password"])
    user = User(user_data["email"], pass_hash, user_data["first_name"], user_data["last_name"])
    app.db.session.add(user)
    app.db.session.flush()
    company = Company(user.id, "Cool company", "7647362765923", "coolcompany@email.com")
    app.db.session.add(company)
    app.db.session.flush()
    companyUser = CompanyUser(user.id, company.id)
    app.db.session.add(companyUser)
    app.db.session.commit()
    address_data = {
        'company_id': str(company.id),
        'state_id': 1,
        'city_id': 1000,
        'street': 'Test Street',
        'zip_code': '01905'
    }

    url = "/addresses"

    response = client.post(url, data = json.dumps(address_data), headers = headers)
    ifCompanyAddressExist = CompanyAddress.query.filter_by(company_id=company.id).first()

    assert response.json["msg"] == "address created"
    assert bool(ifCompanyAddressExist) == True


def test_create_profile(client):  

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    user_data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehackk@yahoo.com',
        'password': 'dehack'
    }
    
    pass_hash = sha256_crypt.hash(user_data["password"])
    user = User(user_data["email"], pass_hash, user_data["first_name"], user_data["last_name"])
    myuuid = uuid.uuid4()
    user.id = myuuid
    app.db.session.add(user)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8') #response.json["access_token"]

    url = "/profiles"

    profile_data = {
        'phone': '8794445768',
        'email': 'test@email.com',
        'linkedin_url': 'https://linkedin.com/olabayo',
        'street': 'Street test',
        'state_id': 1,
        'city_id': 1,
        'zip_code': '01903'
    }

    response = client.post(url, data=json.dumps(profile_data), headers=headers)
    ifProfileExists = Profile.query.filter_by(user_id=myuuid).first()
    assert bool(ifProfileExists) == True
    assert response.json["msg"] == "profile created"


def test_create_experience(client):  

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    user_data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehackk@yahoo.com',
        'password': 'dehack'
    }
    
    pass_hash = sha256_crypt.hash(user_data["password"])
    user = User(user_data["email"], pass_hash, user_data["first_name"], user_data["last_name"])
    myuuid = uuid.uuid4()
    user.id = myuuid
    app.db.session.add(user)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8') #response.json["access_token"]

    url = "/experiences"

    exp_data = {
        'company': 'Org name',
        'role': 'Role',
        'description': 'What i did',
        'experience_type_id': 1
    }

    response = client.post(url, data=json.dumps(exp_data), headers=headers)
    ifExperienceExists = WorkExperience.query.filter_by(user_id=myuuid).first()
    assert bool(ifExperienceExists) == True
    assert response.json["msg"] == "experience created"


def test_create_education(client):  

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    user_data = {
        'first_name': 'Olabayo',
        'last_name': 'Onile-Ere',
        'email': 'dehackk@yahoo.com',
        'password': 'dehack'
    }
    
    pass_hash = sha256_crypt.hash(user_data["password"])
    user = User(user_data["email"], pass_hash, user_data["first_name"], user_data["last_name"])
    myuuid = uuid.uuid4()
    user.id = myuuid
    app.db.session.add(user)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8') #response.json["access_token"]

    url = "/education"

    education_data = {
        'institution': 'Org name',
        'date_from': '05/06/2009',
        'date_to': '05/06/2020',
        'award': 'Certificate',
        'education_type_id': 1,
        'program_length': '53',
        'industry': 'Software Engineering'
    }

    response = client.post(url, data=json.dumps(education_data), headers=headers)
    ifEducationExists = Education.query.filter_by(user_id=myuuid).first()
    assert bool(ifEducationExists) == True
    assert response.json["msg"] == "education created"    
