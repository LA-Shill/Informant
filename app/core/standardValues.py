# !/usr/bin/env python
# Name:     standardValues.py
# By:       LA-Shill
# Date:     30.01.2022
# Version   0.3.1
# -----------------------------------------------

import pymongo
from os import environ, path, getcwd
from dotenv import load_dotenv
from datetime import timedelta

"""Load in .env file"""
basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))

host = str(environ.get('DB_HOST'))
CORE_MONGO_DB = str(environ.get('CORE_MONGO_DB'))
VUL_MONGO_DB = str(environ.get('VUL_MONGO_DB'))
port = int(environ.get('DB_PORT'))

client = pymongo.MongoClient(host, port)
mainDB = client[CORE_MONGO_DB.rsplit('/', 1)[-1]]

try:
    if mainDB['settings'].count_documents({}) > 0:
        print("[INFORMANT] Settings DB file detected")
    else:
        settings = {'CENSYS_API_ID' : '', 'CENSYS_API_SECRET' : '', 'SHODAN_API_KEY' : '', 'BINARY_EDGE_API_KEY' : '', 'ONYPHE_API_KEY' : '', 'FARSIGHT_API_KEY' : '', 'HIGH_RISK_PORTS' : [], 'GEO_LOCATION' : ''}
        mainDB['settings'].insert(settings)
except Exception as e:
    print("Error on first run, check you have all DB dependencies installed. Error: " + str(e))


class StandardValues:
    """
    Default vaules used across program,
    can be stored in volatile memory if required
    """
    db_r = mainDB['settings'].find({})

    CENSYS_API_ID: str = db_r[0]['CENSYS_API_ID']
    CENSYS_API_SECRET: str =  db_r[0]['CENSYS_API_SECRET']
    SHODAN_API_KEY: str =  db_r[0]['SHODAN_API_KEY']
    BINARY_EDGE_API_KEY: str = db_r[0]['BINARY_EDGE_API_KEY']
    ONYPHE_API_KEY: str =  db_r[0]['ONYPHE_API_KEY']
    FARSIGHT_API_KEY: str = db_r[0]['FARSIGHT_API_KEY']
    HIGH_RISK_PORTS: list = db_r[0]['HIGH_RISK_PORTS']
    GEO_LOCATION: str = db_r[0]['GEO_LOCATION']

    CENSYS_DEFAULT_RESULTS_QUANTITY: int = 10000
    SHODAN_DEFAULT_RESULTS_QUANTITY: int = 10
    BINARYEDGE_DEFAULT_RESULTS_PAGE: int = 1

    THREATMINER_API_DELAY: int = 6
    ROBTEX_API_DELAY: int = 20
    THREATCROWD_API_DELAY: int = 10
    DALOO_API_DELAY: int = 5
    FARSIGHT_API_DELAY: int = 1

    DB_HOST: str = host
    DB_PORT: int = port
    MAIN_DB_NAME: str = CORE_MONGO_DB.rsplit('/', 1)[-1]
    VUL_DB_NAME: str = VUL_MONGO_DB.rsplit('/', 1)[-1]
