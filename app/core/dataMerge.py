# !/usr/bin/env python
# Name:     dataMerge.py
# By:       LA-Shill
# Date:     20.11.2020
# Version   0.4
# -----------------------------------------------

import json
import operator
import collections
from itertools import chain
from operator import itemgetter

# NEEDS TIDIED UP AT LATER DATE

def mergeData(source1, source2):

    tempDict: dict = {
    'source' : '',
    'ip' : '',
    'domains' : '',
    'hostnames' : '',
    'org' : '',
    'asn': '',
    'country' : '',
    'ports' : '',
    'protocols': '',
    'banners': '',
    'os' : '',
    'os_distro' : '',
    }

    ip = source1['ip']

    try:
        # Combine and drop dupes from hostnames
        hostnames = list(set(source1.get('hostnames', [0]) + source2.get('hostnames', [0])))
        try:
            # Remove default hostname value is applicable
            hostnames.remove(0)
        except:
            pass
    except TypeError as e:
        hostnames: list = [] 
        print("Hostnames merging error occured: " + str(e) + ". Hostnames data may be unreliable. Try using a different combination of Internet-wide scanners.")
    except:
        hostnames: list = [] 
        print("Critical hostnames merging error occured, hostnames data may be unreliable. Try using a different combination of Internet-wide scanners.")

    try:
        ports = list(set(source1.get('ports', [0]) + source2.get('ports', [0])))
        try:
            ports.remove(0)
        except:
            pass
    except TypeError as e:
        ports: list = [] # shodan list of ports
        print("Port merging error occured: " + str(e) + ". Port data may be unreliable. Try using a different combination of Internet-wide scanners.")
    except:
        ports: list = [] # shodan list of ports
        print("Critical port merging error occured, port data may be unreliable. Try using a different combination of Internet-wide scanners.")

    try:
        domains = list(set(source1.get('domains', [0]) + source2.get('domains', [0])))
        try:
            domains.remove(0)
        except:
            pass
    except TypeError as e:
        domains: list = [] # shodan list of domains
        print("Domains merging error occured: " + str(e) + ". Domains data may be unreliable. Try using a different combination of Internet-wide scanners.")
    except:
        domains: list = [] # shodan list of domains
        print("Critical domains merging error occured, domains data may be unreliable. Try using a different combination of Internet-wide scanners.")

    try:
        protocols = list(set(source1.get('protocols', [0]) + source2.get('protocols', [0])))
        try:
            protocols.remove(0)
        except:
            pass
    except TypeError as e:
        protocols: list = [] # shodan list of domains
        print("Protocols merging error occured: " + str(e) + ". Protocols data may be unreliable. Try using a different combination of Internet-wide scanners.")
    except:
        protocols: list = [] # shodan list of domains
        print("Critical protocols merging error occured, protocols data may be unreliable. Try using a different combination of Internet-wide scanners.")

    if (len(source1.get('os_distro', [0])) == 0 and len(source2.get('os_distro', [0])) == 0):
        osDistro : list = []
        pass
    else:
        tempOS_distro = []
        if (isinstance(source1.get('os_distro'), list)):
            for distro in source1.get('os_distro', [0]):
                if(distro != "unknown"):
                    tempOS_distro.append(distro)
        else:
            if(source1.get('os_distro') != "unknown"):
                tempOS_distro.append(source1.get('os_distro'))

        if (isinstance(source2.get('os_distro'), list)):
            for distro in source2.get('os_distro', [0]):
                tempOS_distro.append(distro)
        else:
            tempOS_distro.append(source2.get('os_distro'))

        try:
            osDistro = list(set(tempOS_distro))
            try:
                osDistro.remove(None)
            except:
                pass
        except:
            osDistro: list = []
            print("Critical OS Distro merging error occured, OS data may be unreliable. Try using a different combination of Internet-wide scanners.")

    if (len(source1.get('os', [0])) == 0 and len(source2.get('os', [0])) == 0):
        os : list = []
        pass
    else:
        tempOS = []
        if (isinstance(source1.get('os'), list)):
            for oss in source1.get('os', [0]):
                if(oss != "unknown"):
                    tempOS.append(oss)
        else:
            if(source1.get('os') != "unknown"):
                tempOS.append(source1.get('os'))

        if (isinstance(source2.get('os'), list)):
            for oss in source2.get('os', [0]):
                if(oss != "unknown"):
                    tempOS.append(oss)
        else:
            if(source1.get('os') != "unknown"):
                tempOS.append(source2.get('os'))

        try:
            os = list(set(tempOS))
            try:
                os.remove(None)
            except:
                pass
        except:
            os: list = []
            print("Critical OS  merging error occured, OS data may be unreliable. Try using a different combination of Internet-wide scanners.")

   
    # Banner merge
    if (len(source1.get('banners', '')) == 0 and len(source2.get('banners', '')) == 0):
        banners : list = []
        pass
    else:
        banners : list = []
        if(len(source1.get('banners', '')) != 0):
            for lis in source1['banners']:
                banners.append(lis)
        
        if(len(source2.get('banners', '')) != 0):
            for lis in source2['banners']:
                banners.append(lis)


    tempDict['source'] = 'merged'
    tempDict['ip'] = ip
    tempDict['domains'] = domains
    tempDict['hostnames'] = hostnames
    tempDict['org'] = source1.get('org', source2.get('org',''))
    tempDict['asn'] = source1.get('asn', source2.get('asn',''))
    tempDict['country'] = source1.get('country', source2.get('country',''))
    tempDict['ports'] = ports
    tempDict['protocols'] = protocols
    tempDict['banners'] = banners
    tempDict['os'] = os
    tempDict['os_distro'] = osDistro

    return tempDict
    

def bannerMerge(banners):

    # Function to remove duplicate banner information based on timestamp
    bannersSorted = sorted(banners, key=itemgetter('port'))
    
    result = collections.defaultdict(list)
    for d in bannersSorted:
        result[d['port']].append(d)
    result_list = list(result.values()) 
    banners = []

    for item in result_list:
        tmp = []
        for value in item:
            tmp.append(value)
        tmp = sorted(tmp, key=lambda tmp: tmp['timestamp'])
        banners.append(tmp[-1])

    return banners


def merge(ipList, source1, source2):
    FinalResult: list = []
    try:
        # Merge (only matching records)
        for ip in ipList: 
            for rec in source1:
                if (rec['ip'] == ip):
                    for rec2 in source2:
                        if (rec2['ip'] == ip):
                            FinalResult.append(mergeData(rec, rec2))
            
        # Add left over records from data sources
        for ip in ipList: 
            if not any(item for item in FinalResult if item['ip'] == ip):
                for rec in source2: 
                    if ip in rec.values():
                        FinalResult.append(rec)
                for rec in source1: 
                    if ip in rec.values():
                        FinalResult.append(rec)
    except Exception as e:
        print(f'[INFORMANT] Critical merging error. Please report: {e}')

    return FinalResult
    
def final_merge_checks(source, timestamp):
    for rec in source:
        rec.update( {"timestamp": timestamp})
        if '_id' in rec:
            rec.pop('_id')
        if rec['source'] != 'merged':
            rec['source'] = 'merged'
    return source