# !/usr/bin/env python
# Name:     censysClass.py
# By:       LA-Shill
# Date:     30.09.2020
# Version   0.1
# -----------------------------------------------

# TODO: Limitations with Censys implementation, write own API wrapper from scratch when time allows

# Import libraries
from censys.ipv4 import CensysIPv4
from censys.base import (
    CensysRateLimitExceededException,
    CensysJSONDecodeException,
    CensysException
)
from datetime import datetime

# Import settings
from ..standardValues import StandardValues

class CensysHandler:
    """
    Main class to retrieve information from Censys API.
    """
    def __init__(self, api_id: str = StandardValues.CENSYS_API_ID, api_secret: str = StandardValues.CENSYS_API_SECRET):
        """
        Initialize Censys Search Engine API
        """
        try:
            self.api = CensysIPv4(api_id=api_id, api_secret=api_secret)
            print("[CENSYS] Censys successfully authenticated.")
        except CensysException as apiErr:
            print(f"[CENSYS] Censys API error: {apiErr}")

        self.results: list = []
        self.censys_device_list: list = []
        self.resultTotal: int = 0
        self.searchFields = [
            "ip",
            "autonomous_system.asn",
            "location.country",
            "ports",
            "protocols",
            "metadata.os_description",
            "21.ftp.banner.metadata.manufacturer",
            "21.ftp.banner.metadata.product",
            "21.ftp.banner.metadata.version",
            "143.imap.starttls.metadata.product",
            "80.http.get.metadata.manufacturer",
            "80.http.get.metadata.product",
            "80.http.get.metadata.version",
            "22.ssh.v2.metadata.manufacturer",
            "22.ssh.v2.metadata.product",
            "22.ssh.v2.metadata.version",
            "443.https.get.metadata.manufacturer",
            "443.https.get.metadata.product",
            "443.https.get.metadata.version",
            "updated_at"
        ]
        
    def search(self, query: str, max_records: int = StandardValues.CENSYS_DEFAULT_RESULTS_QUANTITY):
        """
        Function used to search hosts using Censys
        """
        try:
            self.results = list(self.api.search(query, fields=self.searchFields, max_records=max_records))
        except (CensysRateLimitExceededException, CensysJSONDecodeException, CensysNotFoundException, CensysUnauthorizedException) as apiErr:
            print(f"[CENSYS] Censys API error: {apiErr}")
        except AttributeError as apiNotDefined:
            print(f"[CENSYS] Censys API was not initialized: {apiNotDefined}")
        except CensysException as resultsExceeded:
            if "Only the first 1,000 search results are available" in str(resultsExceeded):
                print("[CENSYS] Only the first 1,000 search results are available. Retry search with 1,000 results limit.")
                self.search(query, max_records=StandardValues.CENSYS_FREE_PLAN_RESULTS_QUANTITY)
            else:
                print(f"[CENSYS] Censys API core exception: {resultsExceeded}")
        self.resultTotal = len(self.results)


    def banner_grabber(self, index):
        """
        Function to sort service banner data
        """

        services: list = []
        banners = {
            "port": '',
            "manufacturer": '',
            "product": '',
            "version": '',
            "timestamp": ''
        }

        timestamp = datetime.strptime(self.results[index].get('updated_at', '0000-00-00T00:00:00+00:00'), "%Y-%m-%dT%H:%M:%S+%f:00")
        
        if ('21.ftp.banner.metadata.manufacturer' in self.results[index] or '21.ftp.banner.metadata.product' in self.results[index] or '21.ftp.banner.metadata.version' in self.results[index]) :
            banners['port'] = 21
            banners['manufacturer'] = self.results[index].get('21.ftp.banner.metadata.manufacturer', '')
            banners['product'] = self.results[index].get('21.ftp.banner.metadata.product', '')
            banners['version'] = self.results[index].get('21.ftp.banner.metadata.version', '')
            banners['timestamp'] = str(timestamp)
            services.append(banners.copy())


        if ('80.http.get.metadata.manufacturer' in self.results[index] or '80.http.get.metadata.product' in self.results[index] or '80.http.get.metadata.version' in self.results[index]):
            banners['port'] = 80
            banners['manufacturer'] = self.results[index].get('80.http.get.metadata.manufacturer', '')
            banners['product'] = self.results[index].get('80.http.get.metadata.product', '')
            banners['version'] = self.results[index].get('80.http.get.metadata.version', '')
            banners['timestamp'] = str(timestamp)
            services.append(banners.copy())


        if ('443.https.get.metadata.manufacturer' in self.results[index] or '443.https.get.metadata.product'  in self.results[index] or '443.https.get.metadata.version' in self.results[index]) :
            banners['port'] = 443
            banners['manufacturer'] = self.results[index].get('443.https.get.metadata.manufacturer', '')
            banners['product'] = self.results[index].get('443.https.get.metadata.product', '')
            banners['version'] = self.results[index].get('443.https.get.metadata.version', '')
            banners['timestamp'] = str(timestamp)
            services.append(banners.copy())

        if ('22.ssh.v2.metadata.manufacturer' in self.results[index] or '22.ssh.v2.metadata.product' in self.results[index] or '22.ssh.v2.metadata.version' in self.results[index]) :
            banners['port'] = 22
            banners['manufacturer'] = self.results[index].get('22.ssh.v2.metadata.manufacturer', '')
            banners['product'] = self.results[index].get('22.ssh.v2.metadata.product', '')
            banners['version'] = self.results[index].get('22.ssh.v2.metadata.version', '')
            banners['timestamp'] = str(timestamp)
            services.append(banners.copy())

        if ('110.pop3.starttls.metadata.manufacturer' in self.results[index] or '110.pop3.starttls.metadata.product' in self.results[index] or '110.pop3.starttls.metadata.version' in self.results[index]) :
            banners['port'] = 110
            banners['manufacturer'] = self.results[index].get('110.pop3.starttls.metadata.manufacturer', '')
            banners['product'] = self.results[index].get('110.pop3.starttls.metadata.product', '')
            banners['version'] = self.results[index].get('110.pop3.starttls.metadata.version', '')
            banners['timestamp'] = str(timestamp)
            services.append(banners.copy())
        
        if ('143.imap.starttls.metadata.manufacturer' in self.results[index] or '143.imap.starttls.metadata.product' in self.results[index] or '143.imap.starttls.metadata.version') in self.results[index] :
            banners['port'] = 143
            banners['manufacturer'] = self.results[index].get('143.imap.starttls.metadata.manufacturer', '')
            banners['product'] = self.results[index].get('143.imap.starttls.metadata.product', '')
            banners['version'] = self.results[index].get('143.imap.starttls.metadata.version', '')
            banners['timestamp'] = str(timestamp)
            services.append(banners.copy())

        return services


    def formatted_results(self):
        """
        Return formatted results
        """
        
        tmp_censys_device_list: list = []

        for i in range(len(self.results)):
            CENSYS_FIELDS = {
                'source' : "_censys",
                'ip' : str(self.results[i].get('ip', "unknown")),
                'asn': str(self.results[i].get('autonomous_system.asn', "unknown")), 
                'country' : str(self.results[i].get('location.country', "unknown")),
                'ports': self.results[i].get('ports', "unknown"),
                'protocols': self.results[i].get('protocols', "unknown"),
                'os': self.results[i].get('metadata.os_description', "unknown"),
                'banners': self.banner_grabber(i)
                }

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
        Function to return account stats
        """
        return self.api.account()
