from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from config import NHS_TRUSTS, MEDICAL_SPECIALTIES, YEARS
import re

def validate_nhs_email(form, field):
    """Proper NHS email validation"""
    pattern = r'^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.)*nhs\.(net|uk)$'
    if not re.match(pattern, field.data, re.IGNORECASE):
        raise ValidationError('Valid NHS emails must end with @nhs.net or @nhs.uk domains')

class ProjectForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message='Please enter your NHS email address'),
        Email(message='Invalid email format'),
        validate_nhs_email
    ])

class ProjectForm(FlaskForm):
    project_name = StringField('Project Name', validators=[
        DataRequired(message='Please enter a project name'),
        Length(max=200, message='Project name cannot exceed 200 characters')
    ])
    
    project_type = SelectField('Type', choices=[
        ('audit', 'Audit'), 
        ('qip', 'Quality Improvement Project')
    ])
    
    hospital = SelectField('Hospital Trust', choices=NHS_TRUSTS)
    year = SelectField('Year', choices=YEARS)
    specialty = SelectField('Specialty', choices=MEDICAL_SPECIALTIES)
    guidelines = StringField('Guidelines Used')
    background = TextAreaField('Background', validators=[
        DataRequired(message='Please provide background information')
    ])
    aims = TextAreaField('Aims', validators=[
        DataRequired(message='Please state the project aims')
    ])
    objectives = TextAreaField('Objectives', validators=[
        DataRequired(message='Please list the objectives')
    ])
    keywords = StringField('Keywords', validators=[
        DataRequired(message='Please add at least one keyword')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Please enter your NHS email address'),
        Email(message='Invalid email format'),
        validate_nhs_email  # Custom NHS validation
    ])
    data_protection = BooleanField('Data Protection Compliance', validators=[
        DataRequired(message='You must confirm data protection compliance')
    ])