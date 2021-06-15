# !/usr/bin/env python
# Name:     dalooClass.py
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

# Import settings
from ..standardValues import StandardValues

# Ignore TLS/SL warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DalooHandler:
    """
    Main class to retrieve information from Daloo API.
    """
    def __init__(self):
        """
        Initialize Daloo Class
        """
        print("[DALOO] Daloo successfully authenticated.")
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
        self.results: list = []
        

    def search(self, ips: list):
        """
        Function used to search hosts using Daloo
        Site @ https://pdns.daloo.de/
        """

        tmp = list()

        for ip in ips:
            time.sleep(StandardValues.DALOO_API_DELAY)
            resp = requests.get(url="https://pdns.daloo.de/search.php?alike=1&q=" + ip, headers=self.headers, verify=False)
            rows = re.findall(r'<tr>(.+?)</tr>', resp.content.decode('utf-8'), re.DOTALL)
            data = list()
            for row in rows:
                columns = re.findall(r'<td.*?>(.*?)</td>', row, re.DOTALL)
                if len(columns) == 0:
                    continue
                if len(columns) != 7:
                    continue
                data.append(columns)
                
            for record in data:
                tmp_domain = re.findall(r'>(.+?)<', record[2], re.DOTALL)
                if len(tmp_domain) > 1:
                    domain = tmp_domain[0]
                    
                tmp_ip = re.findall(r'>(.+?)<', record[4], re.DOTALL)
                if len(tmp_ip) == 1:
                    ip = tmp_ip[0]

                FIELDS = {
                    'source' : "_daloo",
                    'type' : "pdns",
                    'ip' : ip,
                    'domain' : domain,
                    'first_seen' : record[0],
                    'last_seen' : record[1],
                    'count' : record[6]
                    }
                tmp.append(FIELDS.copy())
        self.results += tmp


    def raw_results(self):
        """
        Function to return Daloo data
        """
        return self.results
        