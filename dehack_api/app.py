from datetime import timedelta

from flask import Flask
from flask import request
from flask_sqlalchemy import SQLAlchemy
import os
from flask_cors import CORS
from flasgger import Swagger
from flask.json import jsonify

from passlib.hash import sha256_crypt
from flask_mail import Mail
from flask_migrate import Migrate

from flask_jwt import JWT, jwt_required, current_identity

from .utils import activation_email, user_activated_email, reset_password_email


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'youremail@email.com'
app.config['MAIL_PASSWORD'] = os.environ['FLASK_MAIL_PASSWORD']
app.config['MAIL_DEFAULT_SENDER'] = 'youremail@email.com'
app.config['MAIL_SUPPRESS_SEND'] = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['JWT_EXPIRATION_DELTA'] = timedelta(seconds=86400)

CORS(app, resources={r"/*": {"origins": "*"}})
swagger = Swagger(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

from .models import User, RegistrationProfile, PasswordReset, Company, \
CompanyUser, State, City, CompanyAddress, Profile, WorkExperience, Education, \
Job  

def init_db():
    db.create_all()

def truncate_db():
    db.drop_all()

class JwtUser(object):
    id = ""


def default_auth_response_handler(access_token, identity):
    user = User.query.filter_by(id=identity.id).first()
    company_id = ""
    company = Company.query.filter_by(user_id=identity.id).first()
    if bool(company):
        company_id = str(company.id)
    return jsonify({'access_token': access_token.decode('utf-8'),
                     'first_name': user.first_name, 'last_name': user.last_name,
                     'company_id': company_id})

def authenticate(username, password):

    user = User.query.filter_by(email=username).first()
    if user and sha256_crypt.verify(password, user.password):
        jwtUser = JwtUser()
        jwtUser.id = str(user.id)
        return jwtUser

def identity(payload):
    user_id = payload['identity']
    return User.query.filter_by(id=user_id).first()

jwt = JWT(app, authenticate, identity)

jwt.auth_response_callback = default_auth_response_handler

@app.route('/helloworld')
def hello_world():
    user = User.query.filter_by(id=1).first()
    return jsonify({"msg": "Hello, World!"}), 200

@app.route('/')
def root_view():
    """Endpoint to check api health
    This is using docstrings for specifications.
    ---
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
    responses:
      200:
        description: Api health status
        schema:
          $ref: '#/definitions/Status'
    """
    return jsonify({"msg": "Welcome to SweetBread"}), 200


#/employers
#HTTP Method: POST
#Create a employer object
@app.route('/employers', methods=['POST'])
def store_employer():

    """Endpoint for creating an employer
    This is using docstrings for specifications.
    ---
    parameters:
      - in: body
        name: body
        description: JSON parameters.
        schema:
          properties:
            first_name:
              type: string
              description: First name.
              example: Alice
              required: true
            last_name:
              type: string
              description: Last name.
              example: Smith
              required: true
            email:
              type: string
              description: Email.
              example: test@email.com
              required: true
            password:
              type: string
              description: Password.
              example: password
              required: true
            company_name:
              type: string
              description: Company name.
              example: password
              required: true
            company_phone:
              type: string
              description: Company name.
              example: Cool company
              required: true
            company_email:
              type: string
              description: Company email.
              example: coolcompany@email.com
              required: true            
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string          
    responses:
      200:
        description: Employer created
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'    
      500:
        description: Server error
        schema:
          $ref: '#/definitions/Status'
    """

    content = request.json
    if 'password' in content and 'email' in content and 'first_name' in content and 'last_name' in content and  'company_name' in content and  'company_phone' in content and  'company_email' in content:
        try:
            pass_hash = sha256_crypt.hash(content["password"])
            user = User(content["email"], pass_hash, content["first_name"], content["last_name"])
            db.session.add(user)
            db.session.flush()
            registrationProfile = RegistrationProfile(user.id)
            db.session.add(registrationProfile)
            company = Company(user.id, content["company_name"], content["company_phone"], content["company_email"])
            db.session.add(company)
            db.session.flush()
            companyUser = CompanyUser(user.id, company.id)
            db.session.add(companyUser)
            db.session.commit()
            activation_email(user.email, registrationProfile.activation_key, mail)
            return jsonify({"msg": "employer created"}), 200
        except Exception:
             return jsonify({"msg": "server error"}), 500
    else:
        return jsonify({"msg": "Bad request"}), 400


#/users
#HTTP Method: POST
#Create a user object
@app.route('/users', methods=['POST'])
def store_user():
    """Endpoint for creating a user
    This is using docstrings for specifications.
    ---
    parameters:
      - in: body
        name: body
        description: JSON parameters.
        schema:
          properties:
            first_name:
              type: string
              description: First name.
              example: Alice
            last_name:
              type: string
              description: Last name.
              example: Smith
            email:
              type: string
              format: date
              description: Email.
              example: test@email.com
            password:
              type: string
              description: Password.
              example: password
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
    responses:
      200:
        description: User created
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'
      500:
        description: Server error
        schema:
          $ref: '#/definitions/Status'
    """

    content = request.json
    if 'password' in content and 'email' in content and 'first_name' in content and 'last_name' in content:
        try:
            pass_hash = sha256_crypt.hash(content["password"])
            user = User(content["email"], pass_hash, content["first_name"], content["last_name"])
            db.session.add(user)
            db.session.flush()
            registrationProfile = RegistrationProfile(user.id)
            db.session.add(registrationProfile)
            db.session.commit()
            activation_email(user.email, registrationProfile.activation_key, mail)
            return jsonify({"msg": "user created"}), 200
        except Exception:
             return jsonify({"msg": "server error"}), 500
    else:
        return jsonify({"msg": "Bad request"}), 400


#/activate/<activation_key>
#HTTP Method: GET
@app.route('/activate/<string:activation_key>', methods=['GET'])
def activate_user(activation_key):
    """Endpoint for activating a user by using a activation key
    This is using docstrings for specifications.
    ---
    parameters:
      - name: activation_key
        in: path
        type: string
        required: true
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
    responses:
      200:
        description: Actiavtion success
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Activation error
        schema:
          $ref: '#/definitions/Status'
    """

    registrationProfile = RegistrationProfile.query.filter_by(activation_key=activation_key).first()
    if bool(registrationProfile) and registrationProfile.used == False:
        user = User.query.filter_by(id=registrationProfile.user_id).first()
        if bool(user):
            user.status = True
            registrationProfile.used = True
            db.session.commit()
            user_activated_email(user.email, mail)
            return jsonify({"msg": "user activated"}), 200
        else:
            return jsonify({"msg": "user activation error"}), 400
    elif bool(registrationProfile) and registrationProfile.used == True:
        return jsonify({"msg": "user activated"}), 200
    else:
        return jsonify({"msg": "user activation error"}), 400


#/getresetkey
#HTTP Method: POST
#Create a user object
@app.route('/getresetkey', methods=['POST'])
def reset_password_request():

    """Endpoint for requesting password reset key
    This is using docstrings for specifications.
    ---
    parameters:
      - in: body
        name: body
        description: JSON parameters.
        schema:
          properties:
            email:
              type: string
              description: Email.
              example: test@email.com
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
    responses:
      200:
        description: Password reset setup
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request
        schema:
          $ref: '#/definitions/Status'
    """

    content = request.json
    if 'email' in content:
        user = User.query.filter_by(email=content["email"]).first()
        if bool(user):
            passwordReset = PasswordReset(content["email"])
            db.session.add(passwordReset)
            db.session.commit()
            reset_password_email(content["email"], passwordReset.reset_key, mail)
            return jsonify({"msg": "password reset setup"}), 200
        else:
            return jsonify({"msg": "Bad request"}), 400
    else:
        return jsonify({"msg": "Bad request"}), 400


#/getresetkey
#HTTP Method: POST
#Create a user object
@app.route('/resetpassword/<string:reset_key>', methods=['POST'])
def use_password_reset_key(reset_key):

    """Endpoint for reseting the password
    This is using docstrings for specifications.
    ---
    parameters:
      - in: body
        name: body
        description: JSON parameters.
        schema:
          properties:
            password:
              type: string
              description:  Password.
              example: password
            confirm_password:
              type: string
              description: Pasword.
              example: password
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
    responses:
      200:
        description: Password reset
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request
        schema:
          $ref: '#/definitions/Status'
    """

    content = request.json
    if 'password' in content and 'confirm_password' in content:
        resetRow = PasswordReset.query.filter_by(reset_key = reset_key).first()
        if bool(resetRow) and resetRow.used == False:
            user = User.query.filter_by(email=resetRow.email).first()
            if bool(user):
                user.password = sha256_crypt.hash(content["password"])
                resetRow.used = True
                db.session.commit()
                return jsonify({"msg": "password reset"}), 200
            else:
                return jsonify({"msg": "Bad request"}), 400
        else:
            return jsonify({"msg": "Bad request"}), 400
    else:
        return jsonify({"msg": "Bad request"}), 400


@app.route('/protected', methods=["GET"])
@jwt_required()
def protected():

    """Endpoint for testing authenticated request
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
    responses:
      200:
        description: user email
        schema:
          $ref: '#/definitions/Status'
    """

    #return '%s' % current_identity
    return jsonify({"msg": current_identity.email}), 200


@app.route('/changepassword', methods=["POST"])
@jwt_required()
def change_password():

    """Endpoint for authenticated user change of password
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - in: body
        name: body
        description: JSON parameters.
        schema:
          properties:
            current_password:
              type: string
              description: Current Password.
              example: password
            password:
              type: string
              description: New Password.
              example: password
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
    responses:
      200:
        description: password changed
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request
        schema:
          $ref: '#/definitions/Status'
    """

    #return '%s' % current_identity
    content = request.json
    if sha256_crypt.verify(content["current_password"], current_identity.password):
        current_identity.password = sha256_crypt.hash(content["password"])
        db.session.commit()
        return jsonify({"msg": "password changed"}), 200
    else:
        return jsonify({"msg": "bad request"}), 400


@app.route('/states', methods=["GET"])
def state_index():

    """Endpoint used for listing states
    This is using docstrings for specifications.
    ---
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      State:
        type: object
        properties:
          id:
            type: integer
          state_code:
            type: string  
          state_name:
            type: string
      ResponseState:
          type: object
          properties:
            msg:
              type: string
            states:
              type: array 
              items:
                $ref: '#/definitions/State'                           
    responses:
      200:
        description: States
        schema:
          $ref: '#/definitions/ResponseState'  
      400:
        description: Bad request
        schema:
          $ref: '#/definitions/Status'    
    """

    state_list = State.query.all()
    result = [s.to_dict() for s in state_list]
    return jsonify({"msg": "success", "states": result}), 200

#/cities?state_id=1
#HTTP Method: GET
@app.route('/cities', methods=['GET'])
def city_index():

    """Endpoint used for listing cities by their state
    This is using docstrings for specifications.
    ---
    parameters:
      - name: state_id
        in: query
        type: integer
        required: true
        description: State id for the cities 
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      City:
        type: object
        properties:
          id:
            type: integer
          state_id:
            type: integer  
          city:
            type: string
          county:
            type: string
          longitude:
            type: string
          latitude:
            type: string
      ResponseCity:
          type: object
          properties:
            msg:
              type: string
            cities:
              type: array 
              items:
                $ref: '#/definitions/City'                           
    responses:
      200:
        description: Cities
        schema:
          $ref: '#/definitions/ResponseCity'  
      400:
        description: Bad request
        schema:
          $ref: '#/definitions/Status'    
    """

    try:
        state_id = int(request.args.get('state_id'))
        city_list = City.query.filter_by(state_id=state_id).all()
        result = [c.to_dict() for c in city_list]
        return jsonify({"msg": "success", "cities": result}), 200
    except Exception:
        return jsonify({"msg": "Invalid page params"}), 400

@app.route('/addresses', methods=['POST'])
def store_address():

    """Endpoint for creating company address
    This is using docstrings for specifications.
    ---
    parameters:
      - in: body
        name: body
        description: JSON parameters.
        schema:
          properties:
            company_id:
              type: string
              description: Company id.
              example: 1222-121231-474765-df4444
              required: true
            street:
              type: string
              description: Street.
              example: 76 test street
              required: true
            state_id:
              type: integer
              description: State id.
              example: 1
              required: true
            city_id:
              type: integer
              description: City id.
              example: 1109
              required: true            
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string          
    responses:
      200:
        description: Address created
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'
    """

    content = request.json

    if 'company_id' in content and 'state_id' in content and 'city_id' in content and 'street' in content:
        companyAddress = CompanyAddress(content["company_id"], content["street"], content["state_id"], content["city_id"])
        db.session.add(companyAddress)
        db.session.commit()
        return jsonify({"msg": "address created"}), 200 
    else:
        return jsonify({"msg": "Bad request"}), 400


@app.route('/profiles', methods=["POST"])
@jwt_required()
def store_profile():

    """Endpoint for creating an profile
    This is using docstrings for specifications.
    ---
    parameters:
      - in: body
        name: body
        description: JSON parameters.
        schema:
          properties:
            phone:
              type: string
              description: Phone.
              example: 37367666666
              required: true
            email:
              type: string
              description: Email.
              example: myemail@email.com
              required: true
            street:
              type: string
              description: Street address.
              example: Test Street
              required: true
            state_id:
              type: integer
              description: State id.
              example: 1
              required: true
            city_id:
              type: integer
              description: City id.
              example: 1009
              required: true
            linkedin_url:
              type: string
              description:  Linkedin url.
              example: https://linkedin.com/oakallll
              required: true
            zip_code:
              type: string
              description: Address zipcode.
              example: 98937
              required: true            
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string          
    responses:
      200:
        description: Employer created
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'    
    """

    content = request.json

    if 'phone' in content and  'email' in content and 'linkedin_url' in content and 'street' in content \
        and 'state_id' in content and 'city_id' in content and 'zip_code' in content:
        profile = Profile(current_identity.id,  content["phone"], content["email"], content["linkedin_url"], content["street"], 
        content["state_id"], content["city_id"], content["zip_code"])
        db.session.add(profile)
        db.session.commit()
        return jsonify({"msg": "profile created"}), 200
    else:
        return jsonify({"msg": "bad request"}), 400


@app.route('/experiences', methods=["POST"])
@jwt_required()
def store_experience():

    """Endpoint for creating an experience
    This is using docstrings for specifications.
    ---
    parameters:
      - in: body
        name: body
        description: JSON parameters.
        schema:
          properties:
            company:
              type: string
              description: Company.
              example: Awesome company
              required: true
            role:
              type: string
              description: Role.
              example: Senior developer
              required: true
            experience_type_id:
              type: integer
              description: Experience type id.
              example: 1
              required: true           
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string          
    responses:
      200:
        description: Experience created
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'    
    """

    content = request.json

    if 'company' in content and  'role' in content and 'description' in content and 'experience_type_id' in content:
        experience = WorkExperience(current_identity.id,  content["company"], content["role"], content["description"], content["experience_type_id"])
        if 'skills' in content and content["skills"]:
            skills = content["skills"].strip()
            experience.skills = skills
            experience.skills_array = skills.split(',')
        db.session.add(experience)
        db.session.commit()
        return jsonify({"msg": "experience created"}), 200
    else:
        return jsonify({"msg": "bad request"}), 400


@app.route('/education', methods=["POST"])
@jwt_required()
def education_experience():

    """Endpoint for creating an education
    This is using docstrings for specifications.
    ---
    parameters:
      - in: body
        name: body
        description: JSON parameters.
        schema:
          properties:
            institution:
              type: string
              description: Institution.
              example: Code academy
              required: true
            date_from:
              type: string
              description: Start date.
              example: 05/12/2008
              required: true
            date_to:
              type: string
              description: End date.
              example: 05/12/2020
              required: true
            award:
              type: string
              description: Award or certificate.
              example: Bsc
              required: true
            education_type_id:
              type: integer
              description: Education type.
              example: 1
              required: true
            program_length:
              type: integer
              description: Length in months.
              example: 52
              required: true
            industry:
              type: string
              description: Industry.
              example: Engineering
              required: true                  
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string          
    responses:
      200:
        description: Experience created
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'    
    """

    content = request.json

    if 'institution' in content and  'date_from' in content and 'date_to' in content and \
     'award' in content and 'education_type_id' in content and 'program_length' in content and 'industry' in content:
        education = Education(current_identity.id,  content["institution"], content["date_from"], 
        content["date_to"], content["award"], content["education_type_id"], content["program_length"], content["industry"])
        if 'skills' in content and content["skills"]:
            skills = content["skills"].strip()
            education.skills = skills
            education.skills_array = skills.split(',')
        db.session.add(education)
        db.session.commit()
        return jsonify({"msg": "education created"}), 200
    else:
        return jsonify({"msg": "bad request"}), 400


#/activate/<activation_key>
#HTTP Method: GET
@app.route('/profiles', methods=['GET'])
@jwt_required()
def show_profile():

    """Endpoint for retrieving user profile 
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
    definitions:    
      Status:
        type: object
        properties:
          msg:
            type: string
      ProfileObj:
        type: object
        properties:
          id:
            type: integer
          user_id: 
            type: string
          cover_story:
            type: string
          phone:
            type: string
          email:
            type: string
          linkedin_url:
            type: string
          street:
            type: string
          state_id:
            type: integer
          city_id:
            type: integer
          zip_code:
            type: string           
      ResponseProfile:
        type: object
        properties:
          msg:
            type: string
          profile:
            type: object
            properties:
               id:
                  type: integer
               user_id: 
                type: string
               cover_story:
                  type: string
               phone:
                  type: string
               email:
                 type: string
               linkedin_url:
                 type: string
               street:
                 type: string
               state_id:
                 type: integer
               city_id:
                 type: integer
               zip_code:
                 type: string 
    responses:
      200:
        description: Profile success
        schema:
          $ref: '#/definitions/ResponseProfile'
      400:
        description: Request error
        schema:
          $ref: '#/definitions/Status'    
    """

    profile = Profile.query.filter_by(user_id=current_identity.id).first()
    if bool(profile) == False:
        return jsonify({"msg": "bad request"}), 400   
    else:
        return jsonify({"msg": "profile", "profile": profile.to_dict()}), 200


#/activate/<user_id>
#HTTP Method: GET
@app.route('/user/education/<string:user_id>', methods=['GET'])
@jwt_required()
def show_education(user_id):

    """Endpoint for retrieving education rows
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: user_id
        in: path
        type: string
        required: true
    definitions:    
      Status:
        type: object
        properties:
          msg:
            type: string
      EducationObj:
        type: object
        properties:
          id:
            type: integer
          user_id: 
            type: string
          institution:
            type: string
          date_from:
            type: string
          date_to:
            type: string
          award:
            type: string
          education_type_id:
            type: integer
          program_length:
            type: integer
          industry:
            type: string
          skills:
            type: string
                        
      ResponseEducation:
        type: object
        properties:
          msg:
            type: string
          education:
            type: array
            items:
               $ref: '#/definitions/EducationObj' 
    responses:
      200:
        description: Request success
        schema:
          $ref: '#/definitions/ResponseEducation'
      400:
        description: Request error
        schema:
          $ref: '#/definitions/Status'    
    """

    education = Education.query.filter_by(user_id=user_id).all()
    result = [{}]
    result = [s.to_dict() for s in education]
    return jsonify({"msg": "success", "education": result}), 200
    


#/experiences/<user_id>
#HTTP Method: GET
@app.route('/user/experiences/<string:user_id>', methods=['GET'])
@jwt_required()
def show_experience(user_id):

    """Endpoint for retrieving experience rows
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: user_id
        in: path
        type: string
        required: true
    definitions:    
      Status:
        type: object
        properties:
          msg:
            type: string
      ExperienceObj:
        type: object
        properties:
          id:
            type: integer
          user_id: 
            type: string
          company:
            type: string
          role:
            type: string
          description:
            type: string
          skills:
            type: string
          experience_type_id:
            type: integer              
      ResponseExperience:
        type: object
        properties:
          msg:
            type: string
          experience:
            type: array
            items:
               $ref: '#/definitions/ExperienceObj' 
    responses:
      200:
        description: Request success
        schema:
          $ref: '#/definitions/ResponseExperience'
      400:
        description: Request error
        schema:
          $ref: '#/definitions/Status'    
    """

    experiences = WorkExperience.query.filter_by(user_id=user_id).all()
    result = [{}]
    result = [s.to_dict() for s in experiences]
    return jsonify({"msg": "success", "experiences": result}), 200

@app.route('/profileoverview', methods=['GET'])
@jwt_required()
def show_profile_overview():
    """Endpoint for retrieving profile overview
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
    definitions:    
      Status:
        type: object
        properties:
          msg:
            type: string
      ExperienceObj:
        type: object
        properties:
          id:
            type: integer
          user_id: 
            type: string
          company:
            type: string
          role:
            type: string
          description:
            type: string
          skills:
            type: string
          experience_type_id:
            type: integer              
      ResponseProfileOverview:
        type: object
        properties:
          msg:
            type: string
          overview:
            type: object
            properties:
              profile:
               type: object
               properties:
                 id:
                  type: integer
                 user_id: 
                   type: string 
                 cover_story:
                   type: string
                 phone:
                   type: string
                 email:
                   type: string
                 linkedin_url:
                   type: string
                 street:
                   type: string
                 state_id:
                   type: integer
                 city_id:
                   type: integer
                 zip_code:
                   type: string
              experience:
               type: array
               items:
                 $ref: '#/definitions/ExperienceObj'
              education:
               type: array
               items:
                 $ref: '#/definitions/EducationObj'   
    responses:
      200:
        description: Request success
        schema:
          $ref: '#/definitions/ResponseProfileOverview'
      400:
        description: Request error
        schema:
          $ref: '#/definitions/Status'    
    """

    profile = Profile.query.filter_by(user_id=current_identity.id).first()
    profile_to_dict = {}
    if bool(profile):
        profile_to_dict = profile.to_dict()
    education_list = Education.query.filter_by(user_id=current_identity.id).all()
    education_list_dict = [e.to_dict() for e in education_list]
    experience_list = WorkExperience.query.filter_by(user_id=current_identity.id).all()
    experience_list_dict = [ex.to_dict() for ex in experience_list]
    return jsonify({"msg": "profile overview", "overview": {"profile": profile_to_dict, "education": education_list_dict,
     "experience": experience_list_dict}}), 200


#/activate/<id>
#HTTP Method: GET
@app.route('/education/<string:id>', methods=['GET'])
@jwt_required()
def show_education_by_id(id):

    """Endpoint for retrieving education row
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: user_id
        in: path
        type: string
        required: true
    definitions:    
      Status:
        type: object
        properties:
          msg:
            type: string
      EducationObj:
        type: object
        properties:
          id:
            type: integer
          user_id: 
            type: string
          institution:
            type: string
          date_from:
            type: string
          date_to:
            type: string
          award:
            type: string
          education_type_id:
            type: integer
          program_length:
            type: integer
          industry:
            type: string
          skills:
            type: string
                        
      ResponseEducationId:
        type: object
        properties:
          msg:
            type: string
          education:
            type: object
            properties:
              id:
                type: integer
              user_id: 
                type: string
              institution:
                type: string
              date_from:
                type: string
              date_to:
               type: string
              award:
                type: string
              education_type_id:
                type: integer
              program_length:
                type: integer
              industry:
               type: string
              skills:
                type: string 
    responses:
      200:
        description: Request success
        schema:
          $ref: '#/definitions/ResponseEducationId'
      404:
        description: Not found
        schema:
          $ref: '#/definitions/Status'    
    """

    education = Education.query.filter_by(id=id).first()
    if bool(education):
        return jsonify({"msg": "success", "education": education.to_dict()}), 200   
    else:
        return jsonify({"msg": "not found"}), 404


#/experiences/<id>
#HTTP Method: GET
@app.route('/experiences/<string:id>', methods=['GET'])
@jwt_required()
def show_experience_id(id):

    """Endpoint for retrieving experience row
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: user_id
        in: path
        type: string
        required: true
    definitions:    
      Status:
        type: object
        properties:
          msg:
            type: string
      ExperienceObj:
        type: object
        properties:
          id:
            type: integer
          user_id: 
            type: string
          company:
            type: string
          role:
            type: string
          description:
            type: string
          skills:
            type: string
          experience_type_id:
            type: integer              
      ResponseExperienceId:
        type: object
        properties:
          msg:
            type: string
          experience:
            type: object
            properties:
              id:
                type: integer
              user_id: 
                type: string
              company:
                type: string
              role:
                type: string
              description:
                type: string
              skills:
                type: string
              experience_type_id:
                type: integer 
    responses:
      200:
        description: Request success
        schema:
          $ref: '#/definitions/ResponseExperienceId'
      404:
        description: Not found
        schema:
          $ref: '#/definitions/Status'    
    """

    experience = WorkExperience.query.filter_by(id=id).first()
    if bool(experience):
        return jsonify({"msg": "success", "experience": experience.to_dict()}), 200
    else:
        return jsonify({"msg": "not found"}), 404


#/education/<id>
#HTTP Method: PUT
@app.route('/education/<string:id>', methods=["PUT"])
@jwt_required()
def update_education_experience(id):

    """Endpoint for updating education row
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: id
        in: path
        type: string
        required: true
      - name: body
        in: body
        description: JSON parameters.
        schema:
          properties:
            institution:
              type: string
              description: Institution.
              example: Code academy
              required: false
            date_from:
              type: string
              description: Start date.
              example: 05/12/2008
              required: false
            date_to:
              type: string
              description: End date.
              example: 05/12/2020
              required: false
            award:
              type: string
              description: Award or certificate.
              example: Bsc
              required: false
            education_type_id:
              type: integer
              description: Education type.
              example: 1
              required: false
            program_length:
              type: integer
              description: Length in months.
              example: 52
              required: false
            industry:
              type: string
              description: Industry.
              example: Engineering
              required: false
            skills:
              type: string
              description: Comma seperated skillsets.
              example: php,scala,java
              required: false  
    definitions:    
      Status:
        type: object
        properties:
          msg:
            type: string
      EducationObj:
        type: object
        properties:
          id:
            type: integer
          user_id: 
            type: string
          institution:
            type: string
          date_from:
            type: string
          date_to:
            type: string
          award:
            type: string
          education_type_id:
            type: integer
          program_length:
            type: integer
          industry:
            type: string
          skills:
            type: string
                        
      ResponseEducationId:
        type: object
        properties:
          msg:
            type: string
          education:
            type: object
            properties:
              id:
                type: integer
              user_id: 
                type: string
              institution:
                type: string
              date_from:
                type: string
              date_to:
               type: string
              award:
                type: string
              education_type_id:
                type: integer
              program_length:
                type: integer
              industry:
               type: string
              skills:
                type: string 
    responses:
      200:
        description: Request success
        schema:
          $ref: '#/definitions/ResponseEducationId'
      404:
        description: Not found
        schema:
          $ref: '#/definitions/Status'    
    """

    content = request.json
    education = Education.query.filter_by(id=id).first()

    if bool(education) == False:
        return jsonify({"msg": "not found"}), 404

    if 'institution' in content:
        education.institution = content["institution"]
    if 'date_from' in content:
        education.institution = content["institution"]
    if'date_to' in content:
        education.institution = content["institution"]
    if'award' in content: 
        education.institution = content["institution"]
    if 'education_type_id' in content:
        education.institution = content["institution"]
    if 'program_length' in content:
        education.program_length = content["program_length"]
    if 'industry' in content:
        education.industry = content["industry"]
        
    if 'skills' in content and content["skills"]:
        skills = content["skills"].strip()
        education.skills = skills
        education.skills_array = skills.split(',')
    db.session.add(education)
    db.session.commit()
    return jsonify({"msg": "education updated", "education": education.to_dict()}), 200


#/experiences/<id>
#HTTP Method: PUT
@app.route('/experiences/<string:id>', methods=["PUT"])
@jwt_required()
def update_experience(id):

    """Endpoint for updating education row
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: id
        in: path
        type: string
        required: true
      - name: body
        in: body
        description: JSON parameters.
        schema:
          properties:
            company:
              type: string
              description: Company.
              example: HubSpot
              required: false
            role:
              type: string
              description: Role.
              example: Software Engineer
              required: false
            description:
              type: string
              description: Description.
              example: I was responsible for deploying their summary app
              required: false
            skills:
              type: string
              description: Skills.
              example: pp, java
              required: false
            experience_type_id:
              type: integer
              description: Experience type.
              example: 1
              required: false 
    definitions:    
      Status:
        type: object
        properties:
          msg:
            type: string 
    responses:
      200:
        description: Request success
        schema:
          $ref: '#/definitions/ResponseExperienceId'
      404:
        description: Not found
        schema:
          $ref: '#/definitions/Status'    
    """

    content = request.json
    experience = WorkExperience.query.filter_by(id=id).first()

    if bool(experience) == False:
        return jsonify({"msg": "not found"}), 404

    if 'company' in content:
        experience.company = content["company"]
    if 'role' in content:
        experience.role = content["role"]
    if'description' in content:
        experience.description = content["description"]
    if 'experience_type_id' in content:
        experience.experience_type_id = content["experience_type_id"]        
    if 'skills' in content and content["skills"]:
        skills = content["skills"].strip()
        experience.skills = skills
        experience.skills_array = skills.split(',')
    db.session.add(experience)
    db.session.commit()
    return jsonify({"msg": "experience updated", "experience": experience.to_dict()}), 200


#/profiles
#HTTP Method: PUT
@app.route('/profiles', methods=["PUT"])
@jwt_required()
def update_profile():

    """Endpoint for updating a profile
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: body
        in: body
        description: JSON parameters.
        schema:
          properties:
            phone:
              type: string
              description: Phone.
              example: 37367666666
              required: false
            email:
              type: string
              description: Email.
              example: myemail@email.com
              required: false
            street:
              type: string
              description: Street address.
              example: Test Street
              required: false
            state_id:
              type: integer
              description: State id.
              example: 1
              required: false
            city_id:
              type: integer
              description: City id.
              example: 1009
              required: false
            linkedin_url:
              type: string
              description:  Linkedin url.
              example: https://linkedin.com/oakallll
              required: false
            zip_code:
              type: string
              description: Address zipcode.
              example: 98937
              required: false
            cover_story:
              type: string
              description: Overview of profile.
              example: I am a team player
              required: false             
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      ResponseProfileUpdate:
        type: object
        properties:
          msg:
            type: string
          profile:
            type: object
            properties:
              phone:
                type: String
              email: 
                type: string
              street:
                type: string
              state_id:
                type: integer
              city_id:
               type: integer
              linkedin_url:
                type: string
              zip_code:
                type: string
              cover_story:
                type: string               
    responses:
      200:
        description: Employer created
        schema:
          $ref: '#/definitions/ResponseProfileUpdate'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'    
    """

    content = request.json
    profile = Profile.query.filter_by(user_id=current_identity.id).first()
    if bool(profile) == False:
        return jsonify({"msg": "not found"}), 404

    if 'phone' in content:
         profile.phone = content['phone']
    if'email' in content:
         profile.email = content['email']
    if'cover_story' in content:
         profile.cover_story = content['cover_story']     
    if 'linkedin_url' in content:
         profile.linkedin_url = content['linkedin_url']
    if 'street' in content:
         profile.street = content['street']
    if 'state_id' in content:
         profile.state_id = content['state_id']
    if 'city_id' in content:
         profile.city_id = content['city_id']
    if 'zip_code' in content:
         profile.zip_code = content['zip_code']

    db.session.add(profile)
    db.session.commit()
    return jsonify({"msg": "profile updated", "profile": profile.to_dict()}), 200


#/jobs
#HTTP Method: POST
@app.route('/jobs', methods=["POST"])
@jwt_required()
def add_job():

    """Endpoint for creating a job
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: body
        in: body
        description: JSON parameters.
        schema:
          properties:
            title:
              type: string
              description: Job title.
              example: Software Engineer
              required: true
            description:
              type: string
              description: Job description.
              example: Smith
              required: true
            requirements:
              type: string
              description: Requirements.
              example: 2 years web development experience
              required: true
            skills:
              type: string
              description: Comma seperated skills
              example: php, fullstack, jave
              required: false           
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string          
    responses:
      200:
        description: Employer created
        schema:
          $ref: '#/definitions/Status'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'
    """

    content = request.json
    company = Company.query.filter_by(user_id=current_identity.id).first()
    if bool(company) == False:
        return jsonify({"msg": "bad request"}), 400
    if 'title' in content and 'description' in content and 'requirements' in content:
        job = Job(company_id=company.id, title=content['title'], description=content['description'], requirements=content['requirements'])
        if 'skills' in content and content["skills"]:
            skills = content["skills"].strip()
            job.skills = skills
            job.skills_array = skills.split(',')
        db.session.add(job)
        db.session.commit()
        return jsonify({"msg": "job created"}), 200
    else:
        return jsonify({"msg": "bad request"}), 400


#/jobs/<id>
#HTTP Method: PUT
@app.route('/jobs/<string:id>', methods=["PUT"])
@jwt_required()
def update_job(id):

    """Endpoint for updating a job
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: id
        in: path
        type: string
        required: true  
      - name: body
        in: body
        description: JSON parameters.
        schema:
          properties:
            title:
              type: string
              description: Job title.
              example: Software Engineer
              required: false
            description:
              type: string
              description: Job description.
              example: Smith
              required: false
            requirements:
              type: string
              description: Requirements.
              example: 2 years web development experience
              required: false
            skills:
              type: string
              description: Comma seperated skills
              example: php, fullstack, jave
              required: false            
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      ResponseJob:
        type: object
        properties:
          msg:
            type: string
          job:
            type: object
            properties:
              id:
                type: integer
              title:
                type: string
              description:
                type: string
              requirements:
                type: string
              skills:
                type: string    
    responses:
      200:
        description: Job updated
        schema:
          $ref: '#/definitions/ResponseJob'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'
    """

    content = request.json
    job = Job.query.filter_by(id=id).first()
    if bool(job) == True:
        company = Company.query.filter_by(user_id=current_identity.id, id=job.company_id)
        if bool(company) == False:
            return jsonify({"msg": "bad request"}), 400
    else:
        return jsonify({"msg": "bad request"}), 400

    if 'title' in content: 
        job.title = content['title']
    if 'description' in content: 
        job.description = content['description']
    if 'requirements' in content:
        job.requirements = content['requirements']
    if 'skills' in content and content["skills"]:
        skills = content["skills"].strip()
        job.skills = skills
        job.skills_array = skills.split(',')     
       
    db.session.add(job)
    db.session.commit()
    return jsonify({"msg": "job created", "job": job.to_dict()}), 200


#/companies/<id>
#HTTP Method: PUT
@app.route('/companies/<string:id>', methods=["GET"])
@jwt_required()
def get_company(id):

  """Endpoint for updating a job
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: id
        in: path
        type: string
        required: true              
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      ResponseCompany:
        type: object
        properties:
          msg:
            type: string
          company:
            type: object
            properties:
              id:
                type: string
              user_id:
                type: string
              name:
                type: string
              phone:
                type: string
              email:
                type: string    
    responses:
      200:
        description: Employer created
        schema:
          $ref: '#/definitions/ResponseCompany'
      404:
        description: Not found
        schema:
          $ref: '#/definitions/Status'
    """

  company = Company.query.filter_by(user_id=current_identity.id, id=id).first()
  if bool(company) == True:
      return jsonify({"msg": "company result", "company": company.to_dict()}), 200
  else:
      return jsonify({"msg": "not found"}), 404


#/jobs?c=10&p=1
#/jobs
# HTTP METHOD GET
@app.route("/jobs", methods=['get'])  
@jwt_required()
def list_job():

    """Endpoint for retrieving jobs
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: c
        in: query
        type: integer
        required: true
        description: Number of jobs returned
      - name: p
        in: query
        type: integer
        required: true 
        description: The offset used to traverse the list of jobs               
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      Job:
        type: object
        properties:
          id:
            type: integer
          title:
            type: string
          description:
            type: string
          requirements:
            type: string
          company_id:
            type: string
          skills:
            type: string        
      ResponseJobList:
        type: object
        properties:
          msg:
            type: string
          next:
            type: string
          prev:
            type: string    
          jobs:
            type: array
            items:
              $ref: '#/definitions/Job'  
    responses:
      200:
        description: Job listed
        schema:
          $ref: '#/definitions/ResponseJobList'
      404:
        description: Not found
        schema:
          $ref: '#/definitions/Status'
    """

    company = Company.query.filter_by(user_id=current_identity.id).first()
    if bool(company) == True:
        jobs_query = Job.query.filter_by(company_id=company.id)
        # to do
        job_count = jobs_query.count()
        next = None
        prev = None
        c = 10
        p = 1
        try:
            c = int(request.args.get('c'))
            p = int(request.args.get('p'))
        except Exception:
            return jsonify({"msg": "Invalid page params"}), 400
        if p > 1:
            check_prev = p - 1
            if job_count >= c * check_prev:
                prev = request.base_url + "?c=" + str(c) + "&p=" + str(check_prev)
        check_next = p + 1  
        if job_count >= c * check_next:
            next = request.base_url + "?c=" + str(c) + "&p=" + str(check_next)
        try:
            job_list = jobs_query.order_by(Job.id.asc()).paginate(p, per_page=c).items
            result = [d.to_dict() for d in job_list]
            return jsonify(msg="jobs result", jobs=result, next = next, prev = prev)      
        except Exception:
            return jsonify({"msg": "Pagination error"}), 400
    else:
        return jsonify({"msg": "not found"}), 404


#/jobs?c=10&p=1
#/jobs
# HTTP METHOD GET
@app.route("/browse/jobs", methods=['get'])  
def browse_job():

    """Endpoint for retrieving jobs
    This is using docstrings for specifications.
    ---
    parameters:
      - name: c
        in: query
        type: integer
        required: true
        description: Number of jobs returned
      - name: p
        in: query
        type: integer
        required: true 
        description: The offset used to traverse the list of jobs               
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      Job:
        type: object
        properties:
          id:
            type: integer
          title:
            type: string
          description:
            type: string
          requirements:
            type: string
          company_id:
            type: string
          skills:
            type: string        
      ResponseJobList:
        type: object
        properties:
          msg:
            type: string
          next:
            type: string
          prev:
            type: string    
          jobs:
            type: array
            items:
              $ref: '#/definitions/Job'  
    responses:
      200:
        description: Job listed
        schema:
          $ref: '#/definitions/ResponseJobList'
      404:
        description: Not found
        schema:
          $ref: '#/definitions/Status'
    """

    jobs_query = Job.query
    # to do
    job_count = jobs_query.count()
    next = None
    prev = None
    c = 10
    p = 1
    try:
        c = int(request.args.get('c'))
        p = int(request.args.get('p'))
    except Exception:
        return jsonify({"msg": "Invalid page params"}), 400
    if p > 1:
        check_prev = p - 1
        if job_count >= c * check_prev:
            prev = request.base_url + "?c=" + str(c) + "&p=" + str(check_prev)
    check_next = p + 1  
    if job_count >= c * check_next:
        next = request.base_url + "?c=" + str(c) + "&p=" + str(check_next)
    try:
        job_list = jobs_query.order_by(Job.id.asc()).paginate(p, per_page=c).items
        result = [d.to_dict() for d in job_list]
        return jsonify(msg="jobs result", jobs=result, next = next, prev = prev)      
    except Exception:
        return jsonify({"msg": "Pagination error"}), 400        


#/jobs/<id>
#HTTP Method: GET
@app.route('/jobs/<string:id>', methods=["GET"])
@jwt_required()
def show_job(id):

    """Endpoint for updating a job
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: id
        in: path
        type: string
        required: true         
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      ResponseJob:
        type: object
        properties:
          msg:
            type: string
          job:
            type: object
            properties:
              id:
                type: integer
              title:
                type: string
              description:
                type: string
              requirements:
                type: string
              skills:
                type: string    
    responses:
      200:
        description: job retrived
        schema:
          $ref: '#/definitions/ResponseJob'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'
    """
    job = Job.query.filter_by(id=id).first()
    if bool(job) == True:
        return jsonify({"msg": "job created", "job": job.to_dict()}), 200 
    else:
        return jsonify({"msg": "bad request"}), 400


#/jobs/<id>
#HTTP Method: GET
@app.route('/guestjobs/<string:id>', methods=["GET"])
def show_guest_job(id):

    """Endpoint for updating a job
    This is using docstrings for specifications.
    ---
    parameters:
      - name: id
        in: path
        type: string
        required: true         
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      ResponseJob:
        type: object
        properties:
          msg:
            type: string
          job:
            type: object
            properties:
              id:
                type: integer
              title:
                type: string
              description:
                type: string
              requirements:
                type: string
              skills:
                type: string    
    responses:
      200:
        description: job retrived
        schema:
          $ref: '#/definitions/ResponseJob'
      400:
        description: Bad request missing post param
        schema:
          $ref: '#/definitions/Status'
    """
    job = Job.query.filter_by(id=id).first()
    if bool(job) == True:
        return jsonify({"msg": "job created", "job": job.to_dict()}), 200 
    else:
        return jsonify({"msg": "bad request"}), 400



@app.route("/browse/resumes", methods=['get'])
@jwt_required()
def browse_resume():

    """Endpoint for retrieving resumes/profiles
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
      - name: c
        in: query
        type: integer
        required: true
        description: Number of resumes returned
      - name: p
        in: query
        type: integer
        required: true   
        description: The offset used to traverse the list of jobs       
    definitions:
      Status:
        type: object
        properties:
          msg:
            type: string
      ResumeUser:
        type: object
        properties:
          id:
            type: integer
          user_id:
            type: string
          cover_story:
            type: string
          phone:
            type: string
          email:
            type: string 
          linkedin_url:
            type: string
          street:
            type: string
          state_id:
            type: integer
          city_id:
            type: integer
          zip_code:
            type: string
          user:
            type: object
            properties:
              id:
                type: string
              email:
                type: string
              first_name:
                type: string
              last_name:
                type: string      
      ResponseResume:
        type: object
        properties:
          msg:
            type: string
          resumes:
            type: array
            items:
              $ref: '#/definitions/ResumeUser'
                                
    responses:
      200:
        description: job retrived
        schema:
          $ref: '#/definitions/ResponseResume'
      400:
        description: bad request
        schema:
          $ref: '#/definitions/Status'    
      403:
        description: forbidden request
        schema:
          $ref: '#/definitions/Status'
    """

    # Ensure user is a employer
    company = Company.query.filter_by(user_id=current_identity.id).first()
    if bool(company) == False:
        return jsonify({"msg": "unforbidden request"}), 403

    resumes_query = Profile.query
    # to do
    resume_count = resumes_query.count()
    next = None
    prev = None
    c = 10
    p = 1
    try:
        c = int(request.args.get('c'))
        p = int(request.args.get('p'))
    except Exception:
        return jsonify({"msg": "Invalid page params"}), 400
    if p > 1:
        check_prev = p - 1
        if resume_count >= c * check_prev:
            prev = request.base_url + "?c=" + str(c) + "&p=" + str(check_prev)
    check_next = p + 1  
    if resume_count >= c * check_next:
        next = request.base_url + "?c=" + str(c) + "&p=" + str(check_next)
    try:
        resumes_list = resumes_query.order_by(Profile.id.asc()).paginate(p, per_page=c).items
        result = [r.to_dict() for r in resumes_list]
        return jsonify(msg="jobs result", resumes=result, next = next, prev = prev)      
    except Exception:
        return jsonify({"msg": "Pagination error"}), 400