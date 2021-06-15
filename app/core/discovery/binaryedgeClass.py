# !/usr/bin/env python
# Name:     binaryedgeClass.py
# By:       LA-Shill
# Date:     09.02.2021
# Version   0.3
# -----------------------------------------------

# Import libraries
import math
import itertools
import requests
from datetime import datetime
from pybinaryedge import BinaryEdge
from pybinaryedge import BinaryEdgeException, BinaryEdgeNotFound
from itertools import islice
import time

# Import settings
from ..standardValues import StandardValues

class BinaryEdgeHandler:
    """
    Main class to retrieve information from BinaryEdge API.
    """

    def __init__(self, api_key: str = StandardValues.BINARY_EDGE_API_KEY):
        """
        Initialize BinaryEdge Search Engine API
        """
        try:
            r = requests.get("https://api.binaryedge.io/v2/user/subscription", headers={'X-Key': api_key})
            if r.status_code == 200:
                print("[BE] BinaryEdge successfully authenticated.")
            else :
                print("[BE] BinaryEdge error: no/invalid API key given.")
        except :
            print("[BE] BinaryEdge API error occured.")
        
        self.api = BinaryEdge(api_key)
        self.results: list = []
        self.be_device_list: list = []
        self.be_results_count: int = 0
        self.be_real_results_count: int = 0

    def search(self, query: str, max_records: int = StandardValues.BINARYEDGE_DEFAULT_RESULTS_PAGE):
        """
        Function used to search hosts using BinaryEdge.
        1 credit = 1 page (20 results)
        """
        pages = max_records

        # Check if max_records is not an increment of 20
        if (pages != StandardValues.BINARYEDGE_DEFAULT_RESULTS_PAGE):
            pages = (math.ceil(max_records/20))

        # Converted to max_records e.g. 20 = 1 page, 8 = 1 page, 122 = 7 pages (round up)
        page_index = 0
        tmp_new = 999999
        for x in range(pages):
            tmp_results: list = []
            page_index += 1
            try:
                max_run_pages = (math.ceil(tmp_new/20))
                print(max_run_pages)
                if (page_index <=0 or page_index > max_run_pages):
                    break
                else:
                    print(page_index)
                    time.sleep(2)
                    tmp_records = self.api.host_search(query, page=page_index)
                    tmp_new = tmp_records['total']
                    if (tmp_records['total'] < max_records) :
                        max_records == tmp_records['total']
                    tmp_results = list(islice(tmp_records['events'], max_records))
                    for y in range(len(tmp_results)):
                        self.results.append(tmp_results[y])
                    max_records -= 20

            except (BinaryEdgeException, BinaryEdgeNotFound) as apiError:
                print(f"[BE] BinaryEdge API error: {apiError}")

        self.be_results_count = len(self.results)
        self.be_real_results_count = tmp_records['total']

    def port_formatting(self, ip_str):
        """
        Function to format gathered port
        information into a list
        """
        port_list = []

        for i in range(len(self.results)) :
            try:
                if (self.results[i]['target']['ip'] == ip_str):
                    port_list.append(self.results[i]['target']['port'])
                else:
                    pass
            except IndexError:
                pass
            continue

        port_list.sort()
        port_list = list(port_list for port_list,_ in itertools.groupby(port_list))

        return port_list

    def banner_grabber(self, ip_str):
        """
        Function to sort service banner
        data gathered from BE
        """

        banners = []
        
        for i in range(self.total_results()) :
            try:
                if (self.results[i]['target']['ip'] == ip_str):
                    services = {
                    "port": '',
                    "product": '',
                    "version": '',
                    "timestamp": ''
                    }
                    try:
                        test = (self.results[i]['result']['data']['service'].get('product', ''))
                        services['port'] = self.results[i]['target']['port']
                        services['product'] = self.results[i]['result']['data']['service'].get('product', '')
                        services['version'] = self.results[i]['result']['data']['service'].get('version', '')
                        services['timestamp'] = str(datetime.fromtimestamp(self.results[i]['origin'].get('ts', 0000000000000) // 1000))
                        if (services['port'] != ""  and services['product'] == "" and services['version'] == ""):
                            continue
                        else:
                            banners.append(services)
                    except Exception:
                        continue
                else:
                    continue
            except IndexError:
                continue
            continue

        # Find and dump duplicate information
        banners = [dict(tupleized) for tupleized in set(tuple(item.items()) for item in banners)]

        # Return list banners (dicts)
        return (banners)

    def formatted_results(self):
        """
        Return formatted results
        """
        
        index = 0
        tmpbe_device_list: list = []

        for i in range(len(self.results)):

            BE_FIELDS = {
                'source' : "_binaryedge",
                'ip' : str(self.results[i]['target']['ip']),
                'ports': self.port_formatting(self.results[i]['target']['ip']),
                'banners': self.banner_grabber(self.results[i]['target']['ip'])
                }
            tmpbe_device_list.append(BE_FIELDS)

        # Remove duplicates from list
        for i in tmpbe_device_list:
            if i not in self.be_device_list :
                self.be_device_list.append(i)

        return self.be_device_list

    def raw_results(self):
        """
        Return raw BE results
        """
        return self.results

    def total_results(self):
        """
        Return quantity of results from BE database
        """
        return self.be_results_count

    def total_real_results(self):
        """
        Return real quantity of results that
        was successfully gained from BE
        """
        return self.be_real_results_count

    def total_records(self):
        """
        ** Redundant function **
        Counts total records passed back
        """
        if(len(self.be_device_list) == 0):
            temp = self.formatted_results()
            return (len(temp))
        else:
            return (len(self.be_device_list))