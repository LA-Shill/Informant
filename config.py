# !/usr/bin/env python
# Name:     config.py
# By:       LA-Shill
# Date:     22.04.2021
# Version   0.1
# -----------------------------------------------

from os import environ, path
from dotenv import load_dotenv
from datetime import timedelta

"""Load in .env file"""
basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))


class Config:
    """Base config - Inherited by all"""
    SECRET_KEY = environ.get('SECRET_KEY') # Environment variable 
    SESSION_COOKIE_NAME = environ.get('SESSION_COOKIE_NAME') # Environment variable 
    CORE_MONGO_DB = environ.get('CORE_MONGO_DB') # Environment variable 
    VUL_MONGO_DB = environ.get('VUL_MONGO_DB') # Environment variable 
    REDISTOGO_URL = environ.get('REDISTOGO_URL') # Environment variable 
    TMP_FOLDER = environ.get('TMP_FOLDER') # Environment variable 
    

class ProdConfig(Config):
    """Production config"""
    FLASK_ENV = 'production'
    DEBUG = False
    TESTING = False


class DevConfig(Config):
    """Development config"""
    FLASK_ENV = 'development'
    DEBUG = True
    TESTING = True