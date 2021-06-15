# !/usr/bin/env python
# Name:     threatCrowdClass.py
# By:       LA-Shill
# Date:     22.11.2020
# Version   0.1
# -----------------------------------------------

# Import libraries
import json
import requests
import time

# Import settings
from ..standardValues import StandardValues

class ThreatCrowdHandler:
    """
    Main class to retrieve information from ThreatCrowd API.
    """
    def __init__(self):
        """
        Initialize ThreatCrowd Class
        """

        try:
            resp = requests.get(url="https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=8.8.8.8")            
            if (resp.status_code == 404):
                print("[THREATCROWD] ThreatCrowd error: result not found.")
            elif (resp.status_code == 200):
                print("[THREATCROWD] ThreatCrowd successfully authenticated.")
            elif (resp.status_code == 429):
                print("[THREATCROWD] ThreatCrowd not authenticated. Rate limited.")
            else:
                print("[THREATCROWD] ThreatCrowd working in minimal mode.")
        except:
            print("[THREATCROWD] ThreatCrowd connection error occured.")

        self.results: list = []
        self.rdns: list = []
        

    def search(self, ips: list):
        """
        Function used to search hosts using ThreatCrowd
        API Docs @ https://github.com/AlienVault-OTX/ApiV2
        """
        for ip in ips:
            try:
                time.sleep(StandardValues.THREATCROWD_API_DELAY)
                resp = requests.get(url="https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=" + str(ip))
                data = resp.json()
                if data['response_code'] == "1":
                    print("[THREATCROWD] ThreatCrowd found PDNS data for " + ip)
                    for rdns in data['resolutions']:
                        rdns['last_seen'] = rdns['last_resolved']
                        del rdns['last_resolved']
                        rdns['ip'] = ip
                        rdns['type'] = "pdns"
                        rdns['source'] = "_threatcrowd"
                        self.results.append(rdns)
                elif data['response_code'] == "0":
                    print("[THREATCROWD] ThreatCrowd found no PDNS record for " + ip)
            except Exception as e:
                print ("[THREATCROWD] ThreatCrowd error: " + str(e))


    def raw_results(self):
        """
        Return raw ThreatCrowd data
        """
        return self.results