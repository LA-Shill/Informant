# !/usr/bin/env python
# Name:     cymru_whois.py
# By:       LA-Shill
# Date:     24.11.2020
# Version   0.1
# -----------------------------------------------

# Import libraries
import json
import requests
import time
import re
import urllib3
import pymongo
import socket
import argparse
from pymongo import UpdateMany, UpdateOne
from netaddr import IPNetwork
from standardValues import StandardValues

# Setup database
client = pymongo.MongoClient(StandardValues.DB_HOST, StandardValues.DB_PORT)
mainDB = client[StandardValues.MAIN_DB_NAME]
vulDB = client[StandardValues.VUL_DB_NAME]

def query(bulk_query, timeout):
    """ 
    Connects to the whois server and sends the bulk query.
    Returns query results.
    """
    try:
        data = ""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("whois.cymru.com", 43))
        s.sendall(bulk_query)
        reply = s.recv(4098)
        data = reply
        while True:
            reply = s.recv(1024)
            data += reply
    except socket.timeout:
        if data != '':
            pass
        else:
            raise
    except Exception as e:
        raise e
    finally:
        s.close()

    return data