# !/usr/bin/env python
# Name:     onypheClass.py
# By:       LA-Shill
# Date:     14.10.2020
# Version   0.1
# -----------------------------------------------

# Import libraries
import json
import requests
import time
import requests
import itertools

# Import settings
from ..standardValues import StandardValues

class OnypheHandler:
    """
    Main class to retrieve information from Onyphe API.
    """
    def __init__(self, api_key: str = StandardValues.ONYPHE_API_KEY):
        """
        Initialize Onyphe Search Engine Class
        """

        self.api = api_key

        try:
            conCheck = requests.get("https://www.onyphe.io/api/v2/user/?apikey={0}".format(self.api))
            if "nok" in str(conCheck.text):
                print("[ONYPHE] Onyphe error: no/invalid API key given.")
            elif "Success" in str(conCheck.text):
                print("[ONYPHE] Onyphe successfully authenticated.")
        except:
            print("[ONYPHE] Onyphe API error occured.")

        self.results: list = []
        self.onyphe_device_list: list = []
        self.resultTotal: int = 0
        

    def search_host(self, query: str):
        """
        Function used to search hosts using Onyphe
        """
        try:
            tempResults = requests.get("https://www.onyphe.io/api/v2/summary/ip/{0}?apikey={1}".format(query, self.api))
            t1 = json.loads(tempResults.text)
            self.results.append(t1)
        except Exception as e:
            print ("[ONYPHE] Onyphe API error: " + str(e))


    def search_CIDR(self, ipList: list):
        """
        Function used to search hosts using Onyphe
        """
        for ip in range(len(ipList)):
            try:
                time.sleep(1)
                tempResults = requests.get("https://www.onyphe.io/api/v2/summary/ip/{0}?apikey={1}".format(ipList[ip], self.api))
                t1 = json.loads(tempResults.text)
                self.results.append(t1)

            except Exception as e:
                print ("[ONYPHE] Onyphe API error: " + str(e))


    def raw_results(self):
        """
        Return raw Censys data
        """
        return self.results


    def format_helper (self, data):
        ip = ''
        domains = []
        hostnames = []
        ports = []
        os = []
        osDistro = []

        # IP Sorter
        for ip in data['results']:
            try:
                if isinstance(ip.get('ip'), list):
                    ip = str(ip.get('ip')[0])
                    break
                else:
                    ip = str(ip.get('ip'))
            except:
                pass

        # OS Check
        try:
            for opS in data['results']:
                os.append(str(opS.get('os', '')))
        except:
            print("[ONYPHE] Error")
            pass
        # Domain Check
        try:
            for domain in data['results']:
                if type(domain['domain']) is list:
                    for x in range(len(domain['domain'])):
                        domains.append(str(domain.get('domain', '')[x]))
                else:
                    domains.append(str(domain.get('domain', '')))
        except:
            pass
        # Hostname Check
        try:
            for hostname in data['results']:
                if type(hostname['hostname']) is list:
                    for x in range(len(hostname['hostname'])):
                        hostnames.append(str(hostname.get('hostname', '')[x]))
                else:
                    hostnames.append(str(hostname.get('hostname')))
        except:
            pass
        # Port Check
        try:
            for port in data['results']:
                ports.append(int(port.get('port', '')))
        except:
            pass
        # OS Distro Check
        try:
            for distro in data['results']:
                if type(distro['osdistribution']) is list:
                    for x in range(len(distro['osdistribution'])):
                        osDistro.append(str(distro.get('osdistribution', '')[x]))
                else:
                    osDistro.append(str(distro.get('osdistribution', '')))
        except:
            pass
        
        # Tidy up data before return
        domains = list(filter(None, domains))
        hostnames = list(filter(None, hostnames))
        ports = list(filter(None, ports))
        os = list(filter(None, os))
        osDistro = list(filter(None, os))

        return ip, list(set(domains)), list(set(hostnames)), list(set(ports)), list(set(os)), list(set(osDistro))


    def banner_grabber(self, index):
        """
        Grab service banners
        """
        banners: list = []
        for service in self.results[index]['results'] :
            services = {
            "port": '',
            "manufacturer": '',
            "product": '',
            "version": '',
            "timestamp": ''
            }

            if (service.get('port', '') == '' or service.get('port', '') == ''):
                services['port'] = service.get('port', '')
            else:
                services['port'] = int(service.get('port', ''))

            services['manufacturer'] = service.get('productvendor', '')
            services['product'] = service.get('product', '')
            services['version'] = service.get('productversion', '')
            services['timestamp'] = str(service.get('seen_date', '1970-01-01') + " 00:00:00")

            if (services['port'] == "" or (services['manufacturer'] == "" and services['product'] == "" and services['version'] == "")):
                continue
            else:
                banners.append(services)

        banners = [dict(tupleized) for tupleized in set(tuple(item.items()) for item in banners)]

        return (banners)


    def formatted_results(self):
        """
        Return formatted results
        """
        for i in range(len(self.results)):

            ip, domains, hostnames, ports, osList, distro = self.format_helper(self.results[i])

            if (isinstance(osList, list)):
                if (len(osList) == 1):
                    os = osList[0]
                else:
                    os = osList
            else:
                os = osList

            try:
                ONYPHE_FIELDS = {
                    'source' : "_onyphe",
                    'ip' : ip,
                    'domains' : domains,
                    'hostnames' : hostnames,
                    'org' : self.results[i].get('results', "unknown")[0].get('organization', "unknown"),
                    'asn': self.results[i].get('results', "unknown")[0].get('asn', "unknown"),
                    'country' : self.results[i].get('results', "unknown")[0].get('country', "unknown"),
                    'ports' : ports,
                    'banners': self.banner_grabber(i),
                    'os' : os,
                    'os_distro' : distro,
                    }

                self.onyphe_device_list.append(ONYPHE_FIELDS)
            except Exception as e:
                print("[ONYPHE] Device not added (index: " + str(i) + "). Error occured: " + str(e))

        return self.onyphe_device_list


    def total_results(self):
        """
        Return quantity of results from Shodan database
        """
        if(len(self.onyphe_device_list) == 0):
            temp = self.formatted_results()
            return (len(temp))
        else:
            return (len(self.onyphe_device_list))