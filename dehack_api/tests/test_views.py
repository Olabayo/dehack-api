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


def test_get_profile(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    
    

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    profile = ProfileFactory(user_id=myuuid)
    experience = ExperienceFactory(user_id=myuuid)
    #experience.user_id = myuuid
    experience2 = ExperienceFactory(user_id=myuuid)
    #experience2.user_id = myuuid
    education = EducationFactory(user_id=myuuid)
    #education.user_id = myuuid
    education2 = EducationFactory(user_id=myuuid)
    #education2.user_id = myuuid
    app.db.session.add(user)
    app.db.session.add(profile)
    app.db.session.add(education)
    app.db.session.add(experience)
    app.db.session.add(education2)
    app.db.session.add(experience2)
    app.db.session.commit()

    url = "/profiles"

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8') #response.json["access_token"]
    response = client.get(url, headers = headers)
    assert response.status_code == 200


def test_get_education(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    
    

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    experience = ExperienceFactory(user_id=myuuid)
    #experience.user_id = myuuid
    experience2 = ExperienceFactory(user_id=myuuid)
    #experience2.user_id = myuuid
    education = EducationFactory(user_id=myuuid)
    #education.user_id = myuuid
    education2 = EducationFactory(user_id=myuuid)
    #education2.user_id = myuuid
    app.db.session.add(user)
    app.db.session.add(education)
    app.db.session.add(experience)
    app.db.session.add(education2)
    app.db.session.add(experience2)
    app.db.session.commit()

    url = "/user/education/" + str(myuuid)

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8') #response.json["access_token"]
    response = client.get(url, headers = headers)
    assert response.status_code == 200


def test_get_experience(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }
    
    

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    experience = ExperienceFactory(user_id=myuuid)
    #experience.user_id = myuuid
    experience2 = ExperienceFactory(user_id=myuuid)
    #experience2.user_id = myuuid
    education = EducationFactory(user_id=myuuid)
    #education.user_id = myuuid
    education2 = EducationFactory(user_id=myuuid)
    #education2.user_id = myuuid
    app.db.session.add(user)
    app.db.session.add(education)
    app.db.session.add(experience)
    app.db.session.add(education2)
    app.db.session.add(experience2)
    app.db.session.commit()

    url = "/user/experiences/" + str(myuuid)

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8') #response.json["access_token"]
    response = client.get(url, headers = headers)
    assert response.status_code == 200


def test_profile_overview(client):

    mimetype = 'application/json'

    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    profile = ProfileFactory(user_id=myuuid)
    experience = ExperienceFactory(user_id=myuuid)
    #experience.user_id = myuuid
    experience2 = ExperienceFactory(user_id=myuuid)
    #experience2.user_id = myuuid
    education = EducationFactory(user_id=myuuid)
    #education.user_id = myuuid
    education2 = EducationFactory(user_id=myuuid)
    #education2.user_id = myuuid
    app.db.session.add(user)
    app.db.session.add(profile)
    app.db.session.add(education)
    app.db.session.add(experience)
    app.db.session.add(education2)
    app.db.session.add(experience2)
    app.db.session.commit()

    url = '/profileoverview'   

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers = headers)
    assert response.status_code == 200
    assert bool("overview" in response.json) == True
    assert len(response.json["overview"]["experience"]) == 2
    assert response.json["overview"]["profile"]["email"] == "test@email.com"


def test_get_education_id(client):

    mimetype = 'application/json'

    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    profile = ProfileFactory(user_id=myuuid)
    experience = ExperienceFactory(user_id=myuuid)
    #experience.user_id = myuuid
    experience2 = ExperienceFactory(user_id=myuuid)
    #experience2.user_id = myuuid
    education = EducationFactory(user_id=myuuid, institution="Hack Reactor")
    #education.user_id = myuuid
    education2 = EducationFactory(user_id=myuuid)
    #education2.user_id = myuuid
    app.db.session.add(user)
    app.db.session.add(profile)
    app.db.session.add(education)
    app.db.session.add(experience)
    app.db.session.add(education2)
    app.db.session.add(experience2)
    app.db.session.commit()

    url = '/education/1'

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers = headers)
    assert response.status_code == 200
    assert response.json["education"]["institution"] == "Hack Reactor"


def test_get_experience_id(client):

    mimetype = 'application/json'

    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    profile = ProfileFactory(user_id=myuuid)
    experience = ExperienceFactory(user_id=myuuid, company="HubSpot")
    #experience.user_id = myuuid
    experience2 = ExperienceFactory(user_id=myuuid)
    #experience2.user_id = myuuid
    education = EducationFactory(user_id=myuuid, institution="Hack Reactor")
    #education.user_id = myuuid
    education2 = EducationFactory(user_id=myuuid)
    #education2.user_id = myuuid
    app.db.session.add(user)
    app.db.session.add(profile)
    app.db.session.add(education)
    app.db.session.add(experience)
    app.db.session.add(education2)
    app.db.session.add(experience2)
    app.db.session.commit()

    url = '/experiences/1'

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers = headers)
    assert response.status_code == 200
    assert response.json["experience"]["company"] == "HubSpot"


def test_update_education_id(client):

    mimetype = 'application/json'

    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    profile = ProfileFactory(user_id=myuuid)
    experience = ExperienceFactory(user_id=myuuid, company="HubSpot")
    #experience.user_id = myuuid
    experience2 = ExperienceFactory(user_id=myuuid)
    #experience2.user_id = myuuid
    education = EducationFactory(user_id=myuuid, institution="Hack Reactor")
    #education.user_id = myuuid
    education2 = EducationFactory(user_id=myuuid)
    #education2.user_id = myuuid
    app.db.session.add(user)
    app.db.session.add(profile)
    app.db.session.add(education)
    app.db.session.add(experience)
    app.db.session.add(education2)
    app.db.session.add(experience2)
    app.db.session.commit()

    url = '/education/1'

    data = {
        'institution' : 'Udacity'
    }


    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.put(url, data=json.dumps(data), headers = headers)
    assert response.status_code == 200
    assert response.json["education"]["institution"] == "Udacity"


def test_update_experience_id(client):

    mimetype = 'application/json'

    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    profile = ProfileFactory(user_id=myuuid)
    experience = ExperienceFactory(user_id=myuuid, company="HubSpot")
    #experience.user_id = myuuid
    experience2 = ExperienceFactory(user_id=myuuid)
    #experience2.user_id = myuuid
    education = EducationFactory(user_id=myuuid, institution="Hack Reactor")
    #education.user_id = myuuid
    education2 = EducationFactory(user_id=myuuid)
    #education2.user_id = myuuid
    app.db.session.add(user)
    app.db.session.add(profile)
    app.db.session.add(education)
    app.db.session.add(experience)
    app.db.session.add(education2)
    app.db.session.add(experience2)
    app.db.session.commit()

    url = '/experiences/1'

    data = {
        'company' : 'Microsoft'
    }


    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.put(url, data=json.dumps(data), headers = headers)
    assert response.status_code == 200
    assert response.json["experience"]["company"] == "Microsoft"



def test_update_profile(client):

    mimetype = 'application/json'

    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    profile = ProfileFactory(user_id=myuuid)
    experience = ExperienceFactory(user_id=myuuid, company="HubSpot")
    #experience.user_id = myuuid
    experience2 = ExperienceFactory(user_id=myuuid)
    #experience2.user_id = myuuid
    education = EducationFactory(user_id=myuuid, institution="Hack Reactor")
    #education.user_id = myuuid
    education2 = EducationFactory(user_id=myuuid)
    #education2.user_id = myuuid
    app.db.session.add(user)
    app.db.session.add(profile)
    app.db.session.add(education)
    app.db.session.add(experience)
    app.db.session.add(education2)
    app.db.session.add(experience2)
    app.db.session.commit()

    url = '/profiles'

    data = {
        'zip_code' : '00000'
    }


    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.put(url, data=json.dumps(data), headers = headers)
    assert response.status_code == 200
    assert response.json["profile"]["zip_code"] == "00000"


def test_create_job(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    url = "/jobs"
    data = {
        'title': 'Fullstack Engineer',
        'description': 'This role is in need of a fullstack engineer',
        'requirements': 'Ability to think through problems, and relevant projects or personal side projects',
        'skills': 'php,java,devops'
    }
    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id = myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id = myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.post(url, data=json.dumps(data), headers = headers)

    assert response.status_code == 200


def test_update_job(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    url = "/jobs"
    data = {
        'title': 'Backend Engineer'
    }
    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company)
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    url = "/jobs/1"  
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.put(url, data=json.dumps(data), headers = headers)

    assert response.status_code == 200
    assert response.json["job"]["title"] == "Backend Engineer" 


def test_get_company(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company)
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.commit()

    url = "/companies/" + str(myuuid_company) 

    access_token = gen_key({'id': str(myuuid)})  
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers = headers)

    assert response.status_code == 200
    assert response.json["company"]["name"] == "Cool company"


def test_get_job(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company)
    job2 = JobFactory(company_id=myuuid_company, title="Android developer")
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.add(job2)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    url = "/jobs?c=10&p=1"  
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers = headers)

    assert response.status_code == 200
    assert len(response.json["jobs"]) == 2


def test_show_job(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    
    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company)
    job2 = JobFactory(company_id=myuuid_company, title="Android developer")
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.add(job2)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    url = "/jobs/1"  
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers = headers)

    assert response.status_code == 200
    assert response.json["job"]["title"] == "Software Engineer"


def test_show_guest_job(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    
    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company)
    job2 = JobFactory(company_id=myuuid_company, title="Android developer")
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.add(job2)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    url = "/guestjobs/1"  

    response = client.get(url, headers = headers)

    assert response.status_code == 200
    assert response.json["job"]["title"] == "Software Engineer"    


def test_browse_job(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    
    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company, title="Clojure developer")
    job2 = JobFactory(company_id=myuuid_company, title="Android developer")
    job3 = JobFactory(company_id=myuuid_company, title="IOS developer")
    job4 = JobFactory(company_id=myuuid_company, title="Java Developer")
    job5 = JobFactory(company_id=myuuid_company, title="Elixir developer")
    job6 = JobFactory(company_id=myuuid_company, title="Kotlin developer")
    job7 = JobFactory(company_id=myuuid_company, title="Python developer")
    job8 = JobFactory(company_id=myuuid_company, title="Php developer")
    job9 = JobFactory(company_id=myuuid_company, title="Reactjs developer")
    job10 = JobFactory(company_id=myuuid_company, title="React Ntive developer")
    job11 = JobFactory(company_id=myuuid_company, title="NET developer")
    job12 = JobFactory(company_id=myuuid_company, title="Xamarin developer")
    job13 = JobFactory(company_id=myuuid_company, title="Android developer II")
    job14 = JobFactory(company_id=myuuid_company, title="Devops Engineer")
    job15 = JobFactory(company_id=myuuid_company, title="Wordpress developer")
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.add(job2)
    app.db.session.add(job3)
    app.db.session.add(job4)
    app.db.session.add(job5)
    app.db.session.add(job6)
    app.db.session.add(job7)
    app.db.session.add(job8)
    app.db.session.add(job9)
    app.db.session.add(job10)
    app.db.session.add(job11)
    app.db.session.add(job12)
    app.db.session.add(job13)
    app.db.session.add(job14)
    app.db.session.add(job15)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    url = "/browse/jobs?c=10&p=1"  
    #headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers=headers)

    assert response.status_code == 200
    assert len(response.json["jobs"]) == 10


def test_get_resumes(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid2 = uuid.uuid4()
    myuuid3 = uuid.uuid4()
    myuuid4 = uuid.uuid4()
    myuuid5 = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash, email="user@yahoo.com")
    user.id = myuuid
    profile = ProfileFactory(user_id=myuuid, email="user@yahoo.com")
    user2 = UserFactory(password=pass_hash, email="user2@yahoo.com")
    user2.id = myuuid2
    profile2 = ProfileFactory(user_id=myuuid2, email="user2@yahoo.com", linkedin_url="https://linkedin.com/247weolaa")
    user3 = UserFactory(password=pass_hash, email="user3@yahoo.com")
    user3.id = myuuid3
    profile3 = ProfileFactory(user_id=myuuid3, email="user3@yahoo.com", linkedin_url="https://linkedin.com/347weolaa")
    user4 = UserFactory(password=pass_hash, email="user4@yahoo.com")
    user4.id = myuuid4
    profile4 = ProfileFactory(user_id=myuuid4, email="user4@yahoo.com", linkedin_url="https://linkedin.com/447weolaa")
    user5 = UserFactory(password=pass_hash, email="user5@yahoo.com")
    user5.id = myuuid5
    profile5 = ProfileFactory(user_id=myuuid5, email="user5@yahoo.com", linkedin_url="https://linkedin.com/547weolaa")
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company)
    job2 = JobFactory(company_id=myuuid_company, title="Android developer")
    app.db.session.add(user)
    app.db.session.add(user2)
    app.db.session.add(user3)
    app.db.session.add(user4)
    app.db.session.add(user5)
    #app.db.session.add(profile)
    app.db.session.add(profile2)
    app.db.session.add(profile3)
    app.db.session.add(profile4)
    app.db.session.add(profile5)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.add(job2)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    url = "/browse/resumes?c=10&p=1"  
    headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers = headers)

    assert response.status_code == 200
    assert len(response.json["resumes"]) == 4



def test_search_browse_job(client):

    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    
    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company, title="Clojure developer")
    job2 = JobFactory(company_id=myuuid_company, title="Android developer")
    job3 = JobFactory(company_id=myuuid_company, title="IOS developer")
    job4 = JobFactory(company_id=myuuid_company, title="Java Developer")
    job5 = JobFactory(company_id=myuuid_company, title="Elixir developer")
    job6 = JobFactory(company_id=myuuid_company, title="Kotlin developer")
    job7 = JobFactory(company_id=myuuid_company, title="Python developer")
    job8 = JobFactory(company_id=myuuid_company, title="Php developer")
    job9 = JobFactory(company_id=myuuid_company, title="Reactjs developer")
    job10 = JobFactory(company_id=myuuid_company, title="React Native developer")
    job11 = JobFactory(company_id=myuuid_company, title="NET developer")
    job12 = JobFactory(company_id=myuuid_company, title="Xamarin developer")
    job13 = JobFactory(company_id=myuuid_company, title="Android developer II")
    job14 = JobFactory(company_id=myuuid_company, title="Devops Engineer")
    job15 = JobFactory(company_id=myuuid_company, title="Wordpress developer")
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.add(job2)
    app.db.session.add(job3)
    app.db.session.add(job4)
    app.db.session.add(job5)
    app.db.session.add(job6)
    app.db.session.add(job7)
    app.db.session.add(job8)
    app.db.session.add(job9)
    app.db.session.add(job10)
    app.db.session.add(job11)
    app.db.session.add(job12)
    app.db.session.add(job13)
    app.db.session.add(job14)
    app.db.session.add(job15)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    url = "/browse/jobs?c=10&p=1&q=developer"  
    #headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers=headers)

    assert response.status_code == 200
    assert len(response.json["jobs"]) == 10
    assert response.json["page_count"] == 2

# merging encoded and case insensitivity test
def test_search_browse_encoded_job(client):
    
    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    
    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company, title="Clojure developer")
    job2 = JobFactory(company_id=myuuid_company, title="Android developer")
    job3 = JobFactory(company_id=myuuid_company, title="IOS developer")
    job4 = JobFactory(company_id=myuuid_company, title="Java Developer")
    job5 = JobFactory(company_id=myuuid_company, title="Elixir developer")
    job6 = JobFactory(company_id=myuuid_company, title="Kotlin developer")
    job7 = JobFactory(company_id=myuuid_company, title="Python developer")
    job8 = JobFactory(company_id=myuuid_company, title="Php developer")
    job9 = JobFactory(company_id=myuuid_company, title="Reactjs developer")
    job10 = JobFactory(company_id=myuuid_company, title="React Native developer")
    job11 = JobFactory(company_id=myuuid_company, title="NET developer")
    job12 = JobFactory(company_id=myuuid_company, title="Xamarin developer")
    job13 = JobFactory(company_id=myuuid_company, title="Android developer II")
    job14 = JobFactory(company_id=myuuid_company, title="Devops Engineer")
    job15 = JobFactory(company_id=myuuid_company, title="Wordpress developer")
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.add(job2)
    app.db.session.add(job3)
    app.db.session.add(job4)
    app.db.session.add(job5)
    app.db.session.add(job6)
    app.db.session.add(job7)
    app.db.session.add(job8)
    app.db.session.add(job9)
    app.db.session.add(job10)
    app.db.session.add(job11)
    app.db.session.add(job12)
    app.db.session.add(job13)
    app.db.session.add(job14)
    app.db.session.add(job15)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    url = '/browse/jobs?c=10&p=1&q=android%20develo'  
    #headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers=headers)

    assert response.status_code == 200
    assert len(response.json["jobs"]) == 2
    assert response.json["page_count"] == 1



# merging encoded and case insensitivity test
def test_search_browse_unique_job_titles(client):
    
    mimetype = 'application/json'
    headers = {
        'Content-Type': mimetype,
        'Accept': mimetype
    }

    
    pass_hash = sha256_crypt.hash("password")
    myuuid = uuid.uuid4()
    myuuid_company = uuid.uuid4()
    user = UserFactory(password=pass_hash)
    user.id = myuuid
    company = CompanyFactory(user_id=myuuid)
    company.id = myuuid_company
    company_address = CompanyAddressFactory(company_id=myuuid_company)
    company_user = CompanyUser(myuuid, myuuid_company)
    job = JobFactory(company_id=myuuid_company, title="Clojure developer")
    job2 = JobFactory(company_id=myuuid_company, title="Android developer")
    job3 = JobFactory(company_id=myuuid_company, title="IOS developer")
    job4 = JobFactory(company_id=myuuid_company, title="Java Developer")
    job5 = JobFactory(company_id=myuuid_company, title="Elixir developer")
    job6 = JobFactory(company_id=myuuid_company, title="Kotlin developer")
    job7 = JobFactory(company_id=myuuid_company, title="Python developer")
    job8 = JobFactory(company_id=myuuid_company, title="Php developer")
    job9 = JobFactory(company_id=myuuid_company, title="Reactjs developer")
    job10 = JobFactory(company_id=myuuid_company, title="React Native developer")
    job11 = JobFactory(company_id=myuuid_company, title="NET developer")
    job12 = JobFactory(company_id=myuuid_company, title="Xamarin developer")
    job13 = JobFactory(company_id=myuuid_company, title="Android developer II")
    job14 = JobFactory(company_id=myuuid_company, title="Devops Engineer")
    job15 = JobFactory(company_id=myuuid_company, title="Wordpress developer")
    job16 = JobFactory(company_id=myuuid_company, title="Wordpress developer")
    app.db.session.add(user)
    app.db.session.add(company)
    app.db.session.add(company_address)
    app.db.session.add(company_user)
    app.db.session.add(job)
    app.db.session.add(job2)
    app.db.session.add(job3)
    app.db.session.add(job4)
    app.db.session.add(job5)
    app.db.session.add(job6)
    app.db.session.add(job7)
    app.db.session.add(job8)
    app.db.session.add(job9)
    app.db.session.add(job10)
    app.db.session.add(job11)
    app.db.session.add(job12)
    app.db.session.add(job13)
    app.db.session.add(job14)
    app.db.session.add(job15)
    app.db.session.add(job16)
    app.db.session.commit()

    access_token = gen_key({'id': str(myuuid)})
    url = '/search/jobs?c=10&q=Wordpress%20developer'  
    #headers["Authorization"] = "JWT " + access_token.decode('utf-8')

    response = client.get(url, headers=headers)

    assert response.status_code == 200
    assert len(response.json["jobs"]) == 1        
