import os
import tempfile

import pytest
import json

from passlib.hash import sha256_crypt

from .. import app
from ..models import User, RegistrationProfile, PasswordReset, Company, CompanyAddress, CompanyUser, \
State, City


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
    app.db.session.add(user)
    app.db.session.commit()

    url = "/auth"
    response = client.post(url, data = json.dumps(data), headers = headers)

    assert 'access_token' in response.json
    headers["Authorization"] = "JWT " + response.json["access_token"]
    url = "/protected"
    response = client.get(url, headers = headers)

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
