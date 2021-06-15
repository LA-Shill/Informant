# !/usr/bin/env python
# Name:     robtexClass.py
# By:       LA-Shill
# Date:     22.11.2020
# Version   0.1
# -----------------------------------------------

# Import libraries
import json
import requests
import time
from datetime import datetime

# Import settings
from ..standardValues import StandardValues

class RobtexHandler:
    """
    Main class to retrieve information from Robtex API.
    """
    def __init__(self):
        """
        Initialize Robtex Class
        """

        try:
            resp = requests.get(url="https://freeapi.robtex.com/ipquery/8.8.8.8")            
            if (resp.status_code == 404):
                print(f"[ROBTEX] Robtex error: result not found.")
            elif (resp.status_code == 200):
                print("[ROBTEX] Robtex successfully authenticated.")
            elif (resp.status_code == 429):
                print("[ROBTEX] Robtex not authenticated. Rate limited.")
            else:
                print("[ROBTEX] Robtex not authenticated.")
        except:
            print(f"[ROBTEX]Robtex connection error occured.")

        self.results: list = []
        self.rdns: list = []
        

    def search(self, ips: list):
        """
        Function used to search hosts using Robtex
        API Docs @ https://www.robtex.com/api/
        """
        for ip in ips:
            try:
                time.sleep(StandardValues.ROBTEX_API_DELAY)
                resp = requests.get(url="https://freeapi.robtex.com/ipquery/" + str(ip))
                data = resp.json()
                if (data['status'] == "ok"):
                    for rdns in data['pas']:
                        rdns['last_seen'] = datetime.utcfromtimestamp(rdns['t'])
                        del rdns['t']
                        rdns['domain'] = rdns['o']
                        del rdns['o']
                        rdns['ip'] = ip
                        rdns['type'] = "pdns"
                        rdns['source'] = "_robtex"
                        self.results.append(rdns)
                else:
                    print("[ROBTEX] Robtex rate limited - Pausing scan.")
                    time.sleep(5)
                    print("[ROBTEX] Robtex scan resuming.")
            except Exception as e:
                print ("[ROBTEX] Robtex error: " + str(e))


    def raw_results(self):
        """
        Function to return Robtex data
        """
        return self.results