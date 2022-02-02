# !/usr/bin/env python
# Name:     censysClass.py
# By:       LA-Shill
# Date:     02.02.2022
# Version   0.21
# -----------------------------------------------

# TODO: Limitations with Censys implementation, write own API wrapper from scratch when time allows
# Hotfix applied to supported Censys v2 API


# Import libraries
from censys.search import CensysHosts
import os
import math
from datetime import datetime

# Import settings
from ..standardValues import StandardValues

# Set enviroment variables for Censys API Wrapper
os.environ["CENSYS_API_ID"] = StandardValues.CENSYS_API_ID
os.environ["CENSYS_API_SECRET"] = StandardValues.CENSYS_API_SECRET

class CensysHandler:
    """
    Main class to retrieve information from Censys API.
    """
    def __init__(self):
        """
        Initialize Censys Search Engine API
        """
        try:
            self.api = CensysHosts()
            print("[CENSYS] Censys successfully authenticated.")
        except Exception as e:
            print(f"[CENSYS] Censys API error: {e}")

        self.results: list = []
        self.censys_device_list: list = []
        self.resultTotal: int = 0
        
    def search(self, query: str, max_records: int = StandardValues.CENSYS_DEFAULT_RESULTS_QUANTITY):
        """
        Function used to search hosts using Censys
        """
        try:
            if max_records < 100:
                self.results = list(self.api.search(query, per_page=max_records))
            else:
                pages = math.ceil(max_records/100)
                self.results = list(self.api.search(query, per_page=100, pages=pages))
        except Exception as e:
            print(f"[CENSYS] Censys API error: {e}")
        self.resultTotal = len(self.results)


    def formatted_results(self):
        """
        Return formatted results
        """

        tmp_censys_device_list: list = []

        for i in range(len(self.results[0])):
            CENSYS_FIELDS = {
                'source' : "_censys",
                'ip' : str(self.results[0][i].get('ip', "unknown")),
                'asn': str(self.results[0][i]['autonomous_system'].get('asn', "unknown")), 
                'country' : str(self.results[0][i]['location'].get('country', "unknown")),
                'ports': [],
                'os': '',
                'banners': []
                }

            if 'operating_system' in self.results[0][i]:
                CENSYS_FIELDS['os'] = self.results[0][i].get('operating_system').get('product', "unknown")
            
            if 'services' in self.results[0][i]:
                ports = []
                services: list = []

                # Fetch further serivce info on host
                query = self.api.view(self.results[0][i].get('ip'))

                if 'services' in query:
                    for service in query['services']:
                        ports.append(service['port'])
                        port = service['port']
                        if 'software' in service:
                            tmp_stamp = datetime.strptime(query.get('last_updated_at', '1970-01-01T00:00:00.000000'), "%Y-%m-%dT%H:%M:%S.%fZ")
                            banner = {
                            "port": port,
                            "manufacturer": service['software'][0].get('vendor', 'unknown'),
                            "product": service['software'][0].get('product', 'unknown'),
                            "version": service['software'][0].get('version', 'unknown'),
                            "timestamp": str(tmp_stamp.strftime("%Y-%m-%d %H:%M:%S"))
                            }
                        services.append(banner.copy())
                """
                # This just uses one API endpoint not two (fetches less banner data but uses far less credits)
                for service_int in range (len(self.results[0][i]['services'])):
                    ports.append(self.results[0][i]['services'][service_int].get('port', "unknown"))
                    banner = {
                    "port": self.results[0][i]['services'][service_int].get('port', "unknown"),
                    "manufacturer": '',
                    "product": self.results[0][i]['services'][service_int].get('service_name', "unknown"),
                    "version": '',
                    "timestamp": ''
                    }
                    services.append(banner.copy())
                """
                    
            CENSYS_FIELDS['ports'] = ports
            CENSYS_FIELDS['banners'] = services
            
                
            tmp_censys_device_list.append(CENSYS_FIELDS)

        # Remove duplicates from list
        for i in tmp_censys_device_list:
            if i not in self.censys_device_list:
                self.censys_device_list.append(i)

        return self.censys_device_list


    def raw_results(self):
        """
        Function to return raw Censys data
        """
        return self.results


    def total_results(self):
        """
        Function to return total amount of results
        """
        return self.resultTotal

    def account_stats(self):
        """
        Function to return total amount of results
        """
        return self.api.account()
