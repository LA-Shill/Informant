# !/usr/bin/env python
# Name:     shodanClass.py
# By:       LA-Shill
# Date:     13.10.2020
# Version   0.2
# -----------------------------------------------

# Import libraries
from shodan import Shodan
from shodan.exception import APIError, APITimeout
import time
import requests
from datetime import datetime

# Import settings
from ..standardValues import StandardValues

class ShodanHandler:
    """
    Main class to retrieve information from Shodan API.
    """
    def __init__(self, api_key=StandardValues.SHODAN_API_KEY):
        self.api = Shodan(api_key)
        self.results: list = []
        self.shodan_device_list: list = []
        self.shodan_results_count: int = 0
        self.shodan_real_results_count: int = 0

        try:
            con_check = requests.get("https://api.shodan.io/api-info?key={0}".format(api_key))
            if (con_check.status_code == 401):
                print(f"[SHODAN] Shodan error: no/invalid API key given.")
            elif (con_check.status_code == 200):
                print("[SHODAN] Shodan successfully authenticated.")
        except:
            print(f"[SHODAN] Shodan API error occured.")


    def search(self, query: str, max_records=StandardValues.SHODAN_DEFAULT_RESULTS_QUANTITY):
        """
        Search for defined query in Shodan database
        """
        try:
            temp_results = self.api.search(query, limit=max_records)
            print(len(temp_results))

            tmp_ips = []
            ips = []

            for result in (temp_results['matches']):
                tmp_ips.append(result['ip_str'])
                print(result['ip_str'])
            
            ips = list(set(tmp_ips))
            print(ips)
            for ip in ips:
                time.sleep(1)
                try:
                    print("[SHODAN] Gathering data on: " + str(ip))
                    hostinfo = self.api.host(ip)
                    self.results.append(hostinfo)
                except:
                    continue
            time.sleep(1)
            try:
                self.shodan_results_count = self.api.count(query).get("total")
            except Exception:
                print("[SHODAN] Shodan count error - ignore, code needs updated")
        except (APIError, APITimeout) as apiError:
            print(f"[SHODAN] Shodan API error: {apiError}")
        
        self.shodan_real_results_count = len(list(self.formatted_results()))


    def banner_grabber(self, index):
        """
        Grab service banners
        """
        banners: list = []
        for service in self.results[index]['data'] :
            services = {
                "port": '',
                "product": '',
                "version": '',
                "timestamp": ''
                }
            try:
                services['port'] = service.get('port', '')
                services['product'] = service.get('product', '')
                services['version'] = service.get('version', '')
                tmp_stamp = datetime.strptime(service.get('timestamp', '1970-01-01T00:00:00.000000'), "%Y-%m-%dT%H:%M:%S.%f")
                services['timestamp'] = str(tmp_stamp.strftime("%Y-%m-%d %H:%M:%S"))
            except Exception:
                continue

            if (services['port'] == "" or (services['product'] == "" and services['version'] == "")):
                continue
            else:
                banners.append(services)
            
        return (banners)


    def formatted_results(self):
        """
        Return formatted results
        """

        tmp_shodan_device_list: list = []

        for i in range(len(self.results)):
            SHODAN_FIELDS = {
                'source' : "_shodan",
                'ip' : str(self.results[i].get('ip_str', 'unknown')),
                'domains' : self.results[i].get('domains', 'unknown'),
                'hostnames' : self.results[i].get('hostnames', 'unknown'),
                'org' : str(self.results[i].get('org', 'unknown')),
                'asn': str(self.results[i].get('asn', 'unknown')),
                'country' : str(self.results[i].get('country_name', 'unknown')),
                'ports': self.results[i].get('ports', 'unknown'),
                'banners': self.banner_grabber(i),
                }

            tmp_shodan_device_list.append(SHODAN_FIELDS)

            # Remove duplicates from list
            for i in tmp_shodan_device_list:
                if i not in self.shodan_device_list :
                    self.shodan_device_list.append(i)

        return self.shodan_device_list 


    def raw_results(self):
        """
        Return Shodan results
        """
        return self.results


    def total_results(self):
        """
        Return quantity of results from Shodan database
        """
        return self.shodan_results_count


    def total_real_results(self):
        """
        Return real quantity of results that
        was successfully gained from Shodan
        """
        return self.shodan_real_results_count


    def account_stats(self):
        """
        Return account stats
        """
        return (self.api.info)