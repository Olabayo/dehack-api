import factory

from ..models import User, RegistrationProfile, PasswordReset, Company, CompanyAddress, CompanyUser, \
State, City, Profile, Education, WorkExperience, Job, Company, CompanyAddress

class UserFactory(factory.Factory):
    class Meta:
        model = User

    first_name = "Olabayo"
    last_name = "Onile-Ere"
    email = "dehacklll@yahoo.com"


class ProfileFactory(factory.Factory):
    class Meta:
        model = Profile  

    phone = "8456778767"
    email = "test@email.com"
    linkedin_url = "https://linkedin.com/47weolaa"
    street = "Test street"
    state_id = 1
    city_id = 1000
    zip_code = "09278"

class EducationFactory(factory.Factory):
    class Meta:
        model = Education

    institution = "Code Academy"
    date_from = "05/06/2018"
    date_to = "05/06/2020"
    award = "Fullstack proficiency"
    education_type_id = 1
    program_length = 23
    industry = "Software Engineering"


class CompanyFactory(factory.Factory):
    class Meta:
        model = Company

    name = "Cool company"
    phone = "6786667878"
    email = "Cool Company"


class CompanyAddressFactory(factory.Factory): 
    class Meta:
        model = CompanyAddress

    street = "Test street"
    state_id  = 1
    city_id  = 1009  


class ExperienceFactory(factory.Factory):
    class Meta:
        model = WorkExperience    

    company = "Cool company"
    role = "Software Engineer"
    description = "Developed new apis to expose 2 factor" 
    experience_type_id = 1


class JobFactory(factory.Factory):

    class Meta:
        model = Job

    title = "Software Engineer"
    description = "This role is in need of a fullstack engineer"
    requirements = "Ability to think through problems, and relevant projects or personal side projects"                