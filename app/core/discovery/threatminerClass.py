# !/usr/bin/env python
# Name:     threatMinerHandler.py
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

class ThreatMinerHandler:
    """
    Main class to retrieve information from ThreatMiner API.
    """
    def __init__(self):
        """
        Initialize ThreatMiner Class
        """

        try:
            resp = requests.get(url="https://api.threatminer.org/v2/host.php?q=8.8.8.8&rt=2")
            data = resp.json()
            if "404" in data['status_code']:
                print(f"[THREATMINER] ThreatMiner error: result not found.")
            elif "200" in data['status_code']:
                print("[THREATMINER] ThreatMiner successfully authenticated.")
            else:
                print("[THREATMINER] ThreatMiner not authenticated.")
        except:
            print(f"[THREATMINER] ThreatMiner connection error occured.")

        self.results: list = []
        self.rdns: list = []
        

    def search(self, ips: list, option: str):
        """
        Function used to search hosts using ThreatMiner
        Options found @ https://www.threatminer.org/api.php
        """
        for ip in ips:
            try:
                time.sleep(StandardValues.THREATMINER_API_DELAY)
                resp = requests.get(url="https://api.threatminer.org/v2/host.php?q=" + str(ip) + "&rt=" + option)
                data = resp.json()
                if data['status_code'] == "200":
                    print("[THREATMINER] ThreatMiner found PDNS data for " + ip)
                    for rdns in data['results']:
                        rdns['ip'] = ip
                        rdns['type'] = "pdns"
                        rdns['source'] = "_threatminer"
                        self.results.append(rdns)
                elif data['status_code'] == "404":
                    print("[THREATMINER] ThreatMiner found no PDNS record for " + ip)
                else:
                    print("[THREATMINER] ThreatMiner rate limited - Pausing scan.")
                    time.sleep(10)
                    print("[THREATMINER] ThreatMiner scan resuming.")
            except Exception as e:
                print ("[THREATMINER] ThreatMiner error: " + str(e))


    def raw_results(self):
        """
        Function to return raw ThreatMiner data
        """
        return self.results