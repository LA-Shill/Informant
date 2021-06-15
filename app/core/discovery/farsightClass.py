# !/usr/bin/env python
# Name:     farsightClass.py
# By:       LA-Shill
# Date:     25.11.2020
# Version   0.1
# -----------------------------------------------

# Import libraries
import json
import requests
import time
from dnsdb import Dnsdb

# Import settings
from ..standardValues import StandardValues

class FarSightHandler:
    """
    Main class to retrieve information from Farsight API.
    """
    def __init__(self):
        """
        Initialize Farsight Class
        """

        try:
            self.api = Dnsdb(StandardValues.FARSIGHT_API_KEY)
            print("[FARSIGHT] Farsight successfully authenticated.")
        except:
            print(f"[FARSIGHT] Farsight connection error occured.")

        self.results: list = []
        self.rdns: list = []
        

    def search(self, ips: list):
        """
        Function used to search hosts using Farsight
        API Docs @ https://docs.dnsdb.info/dnsdb-apiv2/
        """
        for ip in ips:
            time.sleep(StandardValues.FARSIGHT_API_DELAY)
            try:
                data = self.api.search(ip=ip)
                if (data.status_code == 404):
                    print(f"[FARSIGHT] Farsight found no results for: " + str(ip))
                elif (data.status_code == 200):
                    for record in data.records:
                        record['last_seen'] = record['time_last']
                        del record['time_last']
                        record['first_seen'] = record['time_first']
                        del record['time_first']
                        record['ip'] = record['rdata']
                        del record['rdata']
                        record['type'] = "pdns"
                        del record['rrtype']
                        record['source'] = "_farsight"
                        record['domain'] = record['rrname'][:-1]
                        del record['rrname']
                        self.results.append(record)
            except Exception as e:
                print ("[FARSIGHT] Farsight error: " + str(e))


    def search_CIDR(self, scan_range):
        """
        Function used to search hosts using Farsight
        API Docs @ https://docs.dnsdb.info/dnsdb-apiv2/
        """
        try:
            data = self.api.search(ip=scan_range)
            for record in data.records:
                record['last_seen'] = record['time_last']
                del record['time_last']
                record['first_seen'] = record['time_first']
                del record['time_first']
                record['ip'] = record['rdata']
                del record['rdata']
                record['type'] = "pdns"
                del record['rrtype']
                record['source'] = "_farsight"
                record['domain'] = record['rrname'][:-1]
                del record['rrname']
                self.results.append(record)
        except Exception as e:
            print ("[FARSIGHT] Farsight error: " + str(e))


    def out_results(self):
        """
        Function to return Farsight data
        """
        return self.results