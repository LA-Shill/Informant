# !/usr/bin/env python
# Name:     DNSGrepHandler.py
# By:       LA-Shill
# Date:     20.01.2021
# Version   0.1
# -----------------------------------------------

# Import libraries
import json
import requests
import time

class DNSGrepHandler:
    """
    Main class to retrieve information from DNSGrep.
    """
    def __init__(self):
        """
        Initialize DNSGrep Class
        """

        try:
            resp = requests.get(url="http://dns.bufferover.run/")
            if "OK" in str(resp.content):
                print(f"[DNSGrep] DNSGrep authenticated.")
            else:
                print("[DNSGrep] DNSGrep not authenticated.")
        except:
            print(f"[DNSGrep] DNSGrep connection error occured.")

        self.results: list = []
        self.rdns: list = []
        self.rdns_data: list = []
        self.fdns_data: list = []
        

    def search(self, domain_list: list):
        """
        Function used to search hosts using DNSGrep
        Options found @ https://github.com/erbbysam/DNSGrep
        """
        
        for domain in domain_list:
            try:
                resp = requests.get(url="http://dns.bufferover.run/dns?q=" + str(domain))
                data = resp.json()
                if resp.status_code == 200:
                    domains = list()
                    print("[DNSGrep] DNSGrep found DNS data for " + domain)
                    # Forward DNS A records
                    fdns = data.get("FDNS_A")
                    if fdns:
                        for r in fdns:
                            try:
                                ip, domain = r.split(',')
                            except Exception:
                                continue
                            
                            tmp = {
                            'source' : "_dnsgrep",
                            'type' : "pdns",
                            'ip' : ip,
                            'domain' : domain,
                            'first_seen' : '',
                            'last_seen' : '',
                            'count' : 0
                            }

                            self.fdns_data.append(tmp)

                    # Reverse DNS records
                    rdns = data.get("RDNS")
                    if rdns:
                        for r in rdns:
                            try:
                                ip, domain = r.split(',')
                            except Exception:
                                continue
                        
                            tmp = {
                            'source' : "_dnsgrep",
                            'type' : "pdns",
                            'ip' : ip,
                            'domain' : domain,
                            'first_seen' : '',
                            'last_seen' : '',
                            'count' : 0
                            }

                            self.rdns_data.append(tmp)
                else:
                    print("[DNSGrep] DNSGrep found no foward DNS record for " + domain)
                
                self.results = self.rdns_data + self.fdns_data
            except Exception as e:
                print ("[DNSGrep] DNSGrep error: " + str(e))