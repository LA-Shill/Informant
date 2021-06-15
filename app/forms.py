# !/usr/bin/env python
# Name:     forms.py
# By:       LA-Shill
# Date:     23.04.2021
# Version   0.1
# -----------------------------------------------

from flask_wtf import FlaskForm
from wtforms import (StringField, BooleanField, IntegerField, SelectField, SelectMultipleField)
from wtforms.validators import (DataRequired, URL, IPAddress, Optional, NumberRange, Length)

class ScanForm(FlaskForm):
    """Homepage - IWS Scan Form"""

    scan_range = StringField('Scan Range', validators=[
        DataRequired(message='Please enter a valid IP/CIDR.'),
        Length(min=2, max=77, message='Invalid input.') # Worlds longest TLD is 77 chars
        # TODO: Create custom validation rule - Accept IPV4 and CIDR blocks only
    ])

    max_records =  IntegerField('max_records', validators=[
        DataRequired(), 
        NumberRange(min=1, max=1000, message="Please enter a valid record range (1 - 1000).")
    ])
        
    options = SelectMultipleField('options')


class SettingsForm(FlaskForm):
    """Settings - API Form"""

    shodanApiKey = StringField('shodanApiKey', validators=[
        Optional()
    ])
    censysUID = StringField('censysUID', validators=[
        Optional()
    ])
    censysApiKey = StringField('censysApiKey', validators=[
        Optional()
    ])
    beApiKey = StringField('beApiKey', validators=[
        Optional()
    ])
    onypheApiKey = StringField('onypheApiKey', validators=[
        Optional()
    ])
    farsightApiKey = StringField('farsightApiKey', validators=[
        Optional()
    ])
    highRiskPorts = StringField('highRiskPorts', validators=[
        Optional()
    ])
    geoLocation = StringField('geoLocation', validators=[
        Optional()
    ])


class newProjectForm(FlaskForm):
    """Homepage - New project creation"""

    project_name = StringField('Project Name', validators=[
        DataRequired(message='Please enter a valid Project Name.'),
        Length(min=1, max=128, message='Project Name longer than 128 chars not allowed.')
    ])

    scan_range = StringField('Scan Range', validators=[
        DataRequired(message='Please enter a valid IP/CIDR Range.'),
        Length(min=2, max=77, message='Invalid input.') # Worlds longest TLD is 77 chars
        # TODO: Create custom validation rule - Accept IPV4 and CIDR blocks only
    ])
        
    max_records =  IntegerField('max_records', validators=[
        DataRequired(),
        NumberRange(min=1, max=1000, message="Please enter a valid record range (1 - 1000).")
    ])


class aRescanForm(FlaskForm):
    """Project Overview - Asset Discovery Rescan Options"""
    options = SelectMultipleField('options')


class riskRescanForm(FlaskForm):
    """Project Overview - Risk Assessment Rescan Options"""
    options = SelectMultipleField('options')


class projectSettingsForm(FlaskForm):
    """Project Overview (Settings) Form"""
    project_name = StringField('Project Name', validators=[
        DataRequired(message='Please enter a valid Project Name.'),
        Length(min=1, max=128, message='Project Name longer than 128 chars not allowed.')
    ])

    scan_range = StringField('Scan Range', validators=[
            DataRequired(message='Please enter a valid IP/CIDR Range.'),
            Length(min=2, max=77, message='Invalid input.') # Worlds longest TLD is 77 chars
            # TODO: Create custom validation rule - Accept IPV4 and CIDR blocks only
    ])
        
    max_records =  IntegerField('max_records', validators=[
        DataRequired(),
        NumberRange(min=1, max=1000, message="Please enter a valid record range (1 - 1000).")
    ])


class projectSettingsDel(FlaskForm):
    """Project Overview (Del) Form"""
    project_name = StringField('Project Name', validators=[
        DataRequired(message='Please enter the current project name.'),
    ])