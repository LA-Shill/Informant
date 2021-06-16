# !/usr/bin/env python
# Name:     dataHandler.py
# By:       LA-Shill
# Date:     20.04.2020
# Version   0.6
# -----------------------------------------------

# Import module handlers
from .discovery.censysClass import CensysHandler
from .discovery.shodanClass import ShodanHandler
from .discovery.binaryedgeClass import BinaryEdgeHandler
from .discovery.onypheClass import OnypheHandler
from .discovery.threatCrowdClass import ThreatCrowdHandler
from .discovery.threatminerClass import ThreatMinerHandler
from .discovery.farsightClass import FarSightHandler
from .discovery.robtexClass import RobtexHandler
from .discovery.dalooClass import DalooHandler
from .discovery.DNSGrepHandler import DNSGrepHandler

# Import further custom modules
from .standardValues import StandardValues
from .locationValidator import validate_loc
from .dataMerge import merge, bannerMerge, final_merge_checks
from .cpeExceptions import exceptions
from operator import itemgetter
from itertools import chain
from rapidfuzz import fuzz
from rapidfuzz import process

# Import core libraries
import pymongo
from pymongo import UpdateMany, UpdateOne
import operator
import json
import os
import codecs
import re
import socket
import csv
import argparse
from bs4 import BeautifulSoup
from bson.json_util import dumps, loads
from pyvis.network import Network
from .misc import tld_count, save_last_project_stats, overview_total_stats, latest_records, pdns_enrichment
from .vuls import gen_local_cpe_file
from ipwhois import IPWhois
from netaddr import IPNetwork
from datetime import datetime, timedelta
import ipaddress
import platform

# Setup database
client = pymongo.MongoClient(StandardValues.DB_HOST, StandardValues.DB_PORT)
mainDB = client[StandardValues.MAIN_DB_NAME]
vulDB = client[StandardValues.VUL_DB_NAME]


def save_project_stats(project_name):
    project_data = list(mainDB[project_name].find({'project_name' : project_name}))
    mainDB[project_name].update_one({"project_name": project_name}, {"$set": {"last_run": datetime.utcnow().replace(second=0, microsecond=0)}})

def ip_to_cidr(ips, scan_range):

    for i in range(0, (len(ips) - 1), 1) :
        if ips[i] is None:
            ips.pop(i)
        if ips[i] == "None":
            ips.pop(i)

    ips.sort()
    startip = ipaddress.IPv4Address(ips[0])
    endip = ipaddress.IPv4Address(ips[-1])


    try:
        return [ipaddr for ipaddr in ipaddress.summarize_address_range(startip, endip)]
    except Exception as e:
        print("[INFORMANT] Failed to generated CIDR from IP range")
        return [scan_range]


def rddos_prediction(project_name):

    # Update array
    bulk_updates = []

    # Misc info
    project_data = list(mainDB[project_name].find({'project_name' : project_name}))

    # Grab asset data
    data_tmp = list(mainDB[project_name].find({"source" : 'merged'}))
    assets = latest_records(data_tmp, project_data[0])

    # Grab rDDoS data
    with open('app/core/rddos/data.json', 'r') as jsondata:
        rddos_data = json.load(jsondata)
    
    # Check for ports susceptible to rDDoS
    for asset in assets:
        rddos_prediction = 0
        rddos_port = []
        if 'ports' in asset:
            for rddos in rddos_data['rddos']:
                if isinstance(rddos['port'], int):
                    if rddos['port'] in asset['ports']:
                        rddos_prediction += rddos['baf_max']
                        rddos_port.append(rddos['port']) 
                else:
                    for r_port in rddos['port']:
                        if r_port in asset['ports']:
                            rddos_prediction += rddos['baf_max']
                            rddos_port.append(rddos['port'])

        # Save rDDoS BAF if applicable
        if rddos_prediction != 0:
            bulk_updates.append(UpdateOne({'_id': asset['_id']}, {'$push': {'risks': {'rddos' : True, 'rDDoS_BAF' : rddos_prediction, 'port' : rddos_port}}}))
            
    # Send batched updates
    if len(bulk_updates) > 0:
        try:
            mainDB[project_name].bulk_write(bulk_updates)
        except Exception as e:
            print("[INFORMANT] rDDoS enrichment error: ")


def create_project(project_name, scan_range, max_records) :
    project = { "origin_scan_range" : scan_range, "last_scan_range" : scan_range, "project_name": project_name, "origin_params" : {}, "last_params" : {}, "max_records" : max_records, "created_at" : datetime.utcnow().replace(second=0, microsecond=0), "last_run" : datetime.utcnow().replace(second=0, microsecond=0)} 
    mainDB[project_name].insert_one(project)


def port_flag_check(scan_range):
    project_data = list(mainDB[scan_range].find({'project_name' : scan_range}))
    ports = []

    # Save old scan results
    timeline = str(project_data[0]['created_at'].date().strftime('%d/%m/%Y')) + "," + str(project_data[0]['last_run'].date().strftime('%d/%m/%Y'))
    totalAssets, secureAssets, riskyAssets, defaultConfig = overview_total_stats(project_data[0]['project_name'], 'IWS_1', timeline)
    mainDB[project_data[0]['project_name']].update_one({"project_name": project_data[0]['project_name']}, {"$set": {'last_stats': {'totalAssets': totalAssets, 'secureAssets' : secureAssets, 'risks': riskyAssets, 'defaultConfig' : defaultConfig}}}) 


    data = list(mainDB[scan_range].find({"source": 'merged'}).sort("timestamp", -1))
    assets = []
    filteredAssets = []
    validAssets = []

    # Remove duplicate based on timestamp being closes to maxtime
    for entry in data:
        assets.append(entry['ip'])

    filteredAssets = list(set(assets))
        
    for ip in filteredAssets:
        tempRecords = []
        for entry in data:
            if entry['ip'] == ip:
                tempRecords.append(entry)
            
        validAssets.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - project_data[0]['last_run'])))

    bulk = mainDB[scan_range].initialize_unordered_bulk_op()
    settings = mainDB['settings'].find({}).limit(1)

    for setting in settings:
        if 'HIGH_RISK_PORTS' in setting:
            ports = setting['HIGH_RISK_PORTS']

    for record in validAssets:
        if 'risks' in record:
            for issue in record['risks']:
                if 'ports' in issue:
                    bulk.find({"_id": record['_id']}).update({"$unset": {"risks": 1}})
                    
        if record['source'] == "merged":
            flagged = []
            for port in record['ports']:
                if (port in ports):
                    flagged.append(port)
                    portDict = {'ports' : flagged}
                    bulk.find({"_id": record['_id']}).update({"$push": {"risks": portDict.copy()}})
    try:
        r = bulk.execute()
    except Exception as e:
        print("Flag port check status: " + str(e))
    
    save_project_stats(scan_range) 


def flag_check(scan_range, main_asn):
    """
    data = mainDB[scan_range].find({"type" : 'pdns'})

    for record in data:
        if 'asn' in record and record['asn'] != main_asn :
            mainDB[scan_range].update_many({"ip": record['ip']},{"$set": {"flagged": True}})
        else:
            mainDB[scan_range].update_many({"ip": record['ip']},{"$set": {"flagged": False}})
    """
    project_data = list(mainDB[scan_range].find({'project_name' : scan_range}))

    # Save old scan results
    timeline = str(project_data[0]['created_at'].date().strftime('%d/%m/%Y')) + "," + str(project_data[0]['last_run'].date().strftime('%d/%m/%Y'))
    totalAssets, secureAssets, riskyAssets, defaultConfig = overview_total_stats(project_data[0]['project_name'], 'IWS_1', timeline)
    mainDB[project_data[0]['project_name']].update_one({"project_name": scan_range}, {"$set": {'last_stats': {'totalAssets': totalAssets, 'secureAssets' : secureAssets, 'risks': riskyAssets, 'defaultConfig' : defaultConfig}}}) 


    data = mainDB[scan_range].find({"type" : 'pdns'}) 
    #data = latest_records(data_tmp, project_data[0])

    bulk = mainDB[scan_range].initialize_unordered_bulk_op()

    for record in data:
        if 'asn' in record and record['asn'] != main_asn :
            bulk.find({"ip": record['ip']}).update({"$set": {"flagged": True}})
        if (record['ip'].islower() or record['ip'].isupper()):
            bulk.find({"ip": record['ip']}).update({"$set": {"cname": True}})
    try:
        r = bulk.execute()
    except Exception as e:
        print("Flag pdns check status: " + str(e))
        
    save_project_stats(scan_range) 


def location_verification(scan_range, origin):
    try:
        assets = mainDB[scan_range].find({})
    except Exception as e:
        print("Failed to obtain asset list from DB: " + str(e))
    

    trigger1 = False
    trigger2 = False

    for asset in assets:
        if 'risks' in asset:
            for item in asset['risks']:
                try:
                    if 'verification' in item:
                        trigger1 = True
                    
                    if 'ports' in item:
                        trigger2 = True

                except Exception:
                    pass
                
    if trigger1 and trigger2:
        for asset in mainDB[scan_range].find({}):
            mainDB[scan_range].update_one({"_id": asset['_id']},{"$unset": {"risks": 1}}, upsert=False)
        port_flag_check(scan_range)
    elif trigger1:
        for asset in mainDB[scan_range].find({}):
            mainDB[scan_range].update_one({"_id": asset['_id']},{"$unset": {"risks": 1}}, upsert=False)
        
    bulk = mainDB[scan_range].initialize_unordered_bulk_op()
    for asset in mainDB[scan_range].find({}):
        if asset['source'] == "merged":
            verification = validate_loc(host=asset['ip'], orign=origin, dest=asset['country'])
            ver = {'verification' : verification}
            bulk.find({"_id": asset['_id']}).update({"$push": {"risks": ver.copy()}})
    r = bulk.execute()


def map_data(data, server_color="#da03b3", hostname_color="#03DAC6", edge_color="#018786", server_shape="database", hostname_shape="ellipse", debug=False):
    g = Network(height="1500px", width="100%", bgcolor="#222222", font_color="white", directed=False)
    if debug == True:
        g.width = "75%"
        g.show_buttons(filter_="physics")
    for item in data:
        server = (item["ip"][0])
        hostnames = (item["hostnames"])
        g.add_node(server, color=server_color, shape=server_shape)
        for hostname in hostnames:
            g.add_node(hostname, color=hostname_color, shape=hostname_shape)
            g.add_edge(server, hostname, color=edge_color)
    #g.barnes_hut()
    g.force_atlas_2based(overlap=0.5, gravity=-200, central_gravity=0.01, spring_length=120, damping=1)
    #g.hrepulsion(node_distance=150)
    g.toggle_physics(True)
    file = './tmp/graph_latest.html' if platform.system().lower()=='windows' else './tmp/graph_latest.html'
    g.write_html(file)
    # Read in html file and filter out script data for graph
    data = codecs.open(file, "r", "utf-8")
    soup = BeautifulSoup(data, 'html.parser')
    graph = (soup.find('script', text = re.compile('drawGraph')))
    # Copy graph JS into flask dynamic page, pass in like nav items + need to dump DB and create JSON file first
    return graph


def generate_node_network(project_name, time_min, time_max):
    # Create JSON data for graph creation
    data = mainDB[project_name].find({"$and": [{'timestamp':{'$gte':time_min + timedelta(hours=24), '$lte':time_max + timedelta(hours=24)}}]})
    cur_list = []
    assets = []
    for rec in data:
        cur_list.append(rec)
    
    json_data_list = []

    for item in cur_list:
        json_data = {'ip' : '', 'hostnames': ''}
        mainServerIP = []
        if 'source' in item:
            if (item['source'] == "merged"):
                mainServerIP.append(item['ip'])
                json_data['ip'] = mainServerIP
                serverDomains = []
                for entry in cur_list:
                    if ('type' in entry and entry['type'] == "pdns" and entry['ip'] == mainServerIP[0]):
                        serverDomains.append(entry['domain'])
                    if ('type' not in entry and 'domains' in entry and len(entry['domains']) >= 1 and entry['ip'] == mainServerIP[0]):
                        for domain in entry['domains']:
                            serverDomains.append(domain)
                    if ('type' not in entry and 'hostnames' in entry and len(entry['hostnames']) >= 1 and entry['ip'] == mainServerIP[0]):
                        for hostname in entry['hostnames']:
                            serverDomains.append(hostname)
                json_data['hostnames'] = serverDomains
                json_data_list.append(json_data)
        else:
            pass
        assets = {'assets' : ''}
        assets['assets'] = json_data_list
    
    # Save file
    file = './tmp/graph_data.json' if platform.system().lower()=='windows' else './tmp/graph_data.json'

    with open(file, 'w') as outfile:
        json.dump(assets, outfile)
    
    # Load file
    with open (file, "r") as json_file:
        final_json = json.load(json_file)

    # Make graph
    graphScript = map_data(final_json['assets'], debug=False)

    return graphScript


def pdns_grabber(scan_range, threatcrowd, threatminer, robtex, daloo, farsight, dnsgrep, ipList, update, timestamp, project_name):

    # Hotfix - 29/03/21
    # Fix bug with none being passed as an IP
    for i in range(0, (len(ipList) - 1), 1) :
        if ipList[i] is None:
            ipList.pop(i)
        if ipList[i] == "None":
            ipList.pop(i)

    domainList = []
    state = False
    #scan_range += "_pdns"
    print(ipList)
    # Initialise selected data sources
    if threatcrowd:
        print("[INFORMANT] Retrieving data from ThreatCrowd")
        ThreatCrowd = ThreatCrowdHandler()
        ThreatCrowd.search(ipList)
        results = ThreatCrowd.raw_results()
        results.sort(key=operator.itemgetter('ip'))
        for item in results:
            item.update( {"timestamp": timestamp})
        try:
            mainDB[project_name].insert_many(results)
            for entry in results:
                domainList.append(entry['domain'])
            print("[INFORMANT] ThreatCrowd data retrieval complete")
        except Exception as e:
            print("[INFORMANT] Failed to save ThreatCrowd data to DB: " + str(e))
    
    if threatminer:
        print("[INFORMANT] Retrieving data from ThreatMiner")
        ThreatMiner = ThreatMinerHandler()
        ThreatMiner.search(ipList, "2")
        results = ThreatMiner.raw_results()
        results.sort(key=operator.itemgetter('ip'))
        for item in results:
            item.update( {"timestamp": timestamp})
        try:
            mainDB[project_name].insert_many(results)
            for entry in results:
                domainList.append(entry['domain'])
            print("[INFORMANT] ThreatMiner data retrieval complete")
        except Exception as e:
            print("[INFORMANT] Failed to save ThreatMiner data to DB: " + str(e))

    if robtex:
        print("[INFORMANT] Retrieving data from Robtex")
        Robtex = RobtexHandler()
        Robtex.search(ipList)
        results = Robtex.raw_results()
        results.sort(key=operator.itemgetter('ip'))
        for item in results:
            item.update( {"timestamp": timestamp})
        try:
            mainDB[project_name].insert_many(results)
            for entry in results:
                domainList.append(entry['domain'])
            print("[INFORMANT] Robtex data retrieval complete")
        except Exception as e:
            print("[INFORMANT] Failed to save Robtex data to DB: " + str(e))

    if daloo:
        print("[INFORMANT] Retrieving data from Daloo")
        Daloo = DalooHandler()
        Daloo.search(ipList)
        results = Daloo.raw_results()
        results.sort(key=operator.itemgetter('ip'))
        for item in results:
            item.update( {"timestamp": timestamp})
        try:
            mainDB[project_name].insert_many(results)
            for entry in results:
                domainList.append(entry['domain'])
            print("[INFORMANT] Daloo data retrieval complete")
        except Exception as e:
            print("[INFORMANT] Failed to save Daloo data to DB: " + str(e))

    if farsight:
        print("[INFORMANT] Retrieving data from Farsight")
        Farsight = FarSightHandler()
        if (len(ipList) <= 1):
            Farsight.search(ipList)
        else:
            #Farsight.search_CIDR(scan_range)
            # Eats credits if multiple IPs - Only option is to create CIDR block notation from IPs
            # Hotfix - 21/02/21
            cidr = ip_to_cidr(ipList, scan_range)
            Farsight.search_CIDR(scan_range)
        results = Farsight.out_results()
        results.sort(key=operator.itemgetter('ip'))
        for item in results:
            item.update({"timestamp": timestamp})
        try:
            mainDB[project_name].insert_many(results)
            for entry in results:
                domainList.append(entry['domain'])
            print("[INFORMANT] Farsight data retrieval complete")
        except Exception as e:
            print("[INFORMANT] Failed to save Farsight data to DB: " + str(e))



    if update:
        for record in mainDB[project_name].find({"type": "pdns"}):
            if 'domain' in record:
                domainList.append(record['domain'])
        for record in mainDB[project_name].find({"source": "merged"}):
            if 'domains' in record:
                for domain in record['domains']:
                    domainList.append(domain)
    


    domainList = tld_count(domainList)

    if dnsgrep:
        print("[INFORMANT] Retrieving data from DNSGrep")
        DNSGrep = DNSGrepHandler()
        DNSGrep.search(domainList)
        results = DNSGrep.results
        results.sort(key=operator.itemgetter('ip'))
        for item in results:
            item.update({"timestamp": timestamp})
        try:
            mainDB[project_name].insert_many(results)
            print("[INFORMANT] DNSGrep data retrieval complete")
        except Exception as e:
            print("[INFORMANT] Failed to save DNSGrep data to DB: " + str(e))
    
    enrich = True
  
    # Gen IP list
    if (enrich):
        # Call enrichment function
        pdns_enrichment(project_name, timestamp)

    print("[INFORMANT] Starting Flagging Process")

    # Get main ASN
    for doc in mainDB[project_name].find({'timestamp': timestamp}):
        if doc['source'] == 'merged':
            if 'asn' in doc:
                asn = str(doc['asn'])
                if not asn.islower() and asn.isupper():
                    asn = str(doc['asn'][2:])
    try:
        # Run flag check 
        flag_check(project_name, asn)
        state = True
        print("[INFORMANT] Flagging Process Complete")
    except Exception as e:
        print("[INFORMANT] Flagging Process Error (Proabably nothing detected to flag): " + str(e))

    # Update last_run time
    save_project_stats(project_name) 
    
    return state


def iws_grabber(addr, shodan, censys, be, onyphe, max, update, timestamp, project_name) :

    # Temp Variables
    ipList: list = []
    scanner_int: int = 0

    shodanResults: list = []
    censysResults: list = []
    beResults: list = []
    onypheResults: list = []

    print("\n[INFORMANT] Starting Internet-wide Data Ingest")

    # Initialise selected data sources
    if shodan:
        print("[INFORMANT] Retrieving data from Shodan")
        scanner_int +=1
        Shodan = ShodanHandler()
        Shodan.search(query="net:" + addr, max_records=max)
        for i in range(len(Shodan.formatted_results())) :
            ipList.append(Shodan.formatted_results()[i]['ip'])

        results = Shodan.formatted_results()
        results.sort(key=operator.itemgetter('ip'))
        for item in results:
            item.update( {"timestamp": timestamp})
        shodanResults = results
        try:
            mainDB[project_name].insert_many(results)
            print("[INFORMANT] Shodan data retrieval complete")
        except Exception as e:
            print("[INFORMANT] Failed to save Shodan data to DB: " + str(e))

    if censys:
        print("[INFORMANT] Retrieving data from Censys")
        scanner_int +=1
        Censys = CensysHandler()
        Censys.search(query=addr, max_records=max)
        for i in range(len(Censys.formatted_results())) :
            ipList.append(Censys.formatted_results()[i]['ip'])
            
        results = Censys.formatted_results()
        results.sort(key=operator.itemgetter('ip'))
        for item in results:
            item.update( {"timestamp": timestamp})
        censysResults = results
        try:
            mainDB[project_name].insert_many(results)
            print("[INFORMANT] Censys data retrieval complete")
        except Exception as e:
            print("[INFORMANT] Failed to save Censys data to DB: " + str(e))
            
    if be:
        print("[INFORMANT] Retrieving data from BinaryEdge")
        scanner_int +=1
        BinaryEdge = BinaryEdgeHandler()
        BinaryEdge.search(query='ip:"' + addr +'" AND type:service-simple', max_records=max)
        for i in range(len(BinaryEdge.formatted_results())) :
            ipList.append(BinaryEdge.formatted_results()[i]['ip'])
        
        results = BinaryEdge.formatted_results()
        results.sort(key=operator.itemgetter('ip'))
        for item in results:
            item.update( {"timestamp": timestamp})
        beResults = results
        try:
            mainDB[project_name].insert_many(results)
            print("[INFORMANT] BinaryEdge data retrieval complete")
        except Exception as e:
            print("[INFORMANT] Failed to save BinaryEdge data to DB: " + str(e))

    if onyphe:
        ipList = list(set(ipList))
        if (len(ipList) <= 500):
            print("[INFORMANT] Retrieving data from Onyphe")
            scanner_int +=1
            Onyphe = OnypheHandler()
            Onyphe.search_CIDR(ipList[:245])

            results = Onyphe.formatted_results()
            results.sort(key=operator.itemgetter('ip'))
            for item in results:
                item.update( {"timestamp": timestamp})
            onypheResults = results
            try:
                mainDB[project_name].insert_many(results)
                print("[INFORMANT] Onyphe data retrieval complete")
            except Exception as e:
                print("[INFORMANT] Failed to save Onyphe data to DB: " + str(e))
        else:
            print("[INFORMANT] Skipping Onyphe Check")
    else:
        ipList = list(set(ipList))

    print("[INFORMANT] Internet-wide Data Ingest Complete")

    print("[INFORMANT] Starting Data Merge")
    if (scanner_int == 1):
        mergedResults = results
        for server in mergedResults:
            server['source'] = "merged"
            server.pop('_id')
    else:
        print("Pre-merged: ")
        print(shodanResults)
        print(beResults)
        print(censysResults)
        print(onypheResults)
        # Fixed logical error, compared based on time
        mergedResults = merge(ipList, shodanResults, censysResults)
        print("Merge 1")
        print(mergedResults)
        mergedResults = merge(ipList, mergedResults, beResults)
        mergedResults = merge(ipList, mergedResults, onypheResults)
        print("Merged: ")
        print(mergedResults)

        # Banner merge
        for server in mergedResults:
            server['banners'] = bannerMerge(server['banners'])
        
        mergedResults = final_merge_checks(mergedResults, timestamp)

    try:
        print("Final")
        print(mergedResults)
        mainDB[project_name].insert_many(mergedResults)
    except Exception as e:
        print("Failed to save formatted data to DB: " + str(e))

    print("[INFORMANT] Data Merge Complete")
    
    # Update last_run time
    # save_project_stats(project_name)

    return ipList

def cve_lookup(cpe, version, service, score) :
    # Find known vulnerabilties matching vulnerable config
    cves = vulDB['cves'].find({"vulnerable_configuration" : cpe})
    cveList = []

    if (cves.count() > 0 and version != '') :
        print ("Vulnerabilities found:")
        for cve in cves :
            print("CVE: " + str(cve["id"]))
            cveFound = {'cve' : cve["id"], 'cvss2': cve["cvss"], 'vector' : cve["cvss-vector"], 'cpe' : cpe, "port": '', "manufacturer": '', "product": '', "version": '', "cpe_score": '', 'vul_by_default': False}
            cveFound['port'] = service.get('port', '')
            cveFound['manufacturer'] = service.get('manufacturer', '')
            cveFound['product'] = service.get('product', '')
            cveFound['version'] = service.get('version', '')
            cveFound['vul_by_default'] = default_check(cveFound)
            try:
                cveFound['cpe_score'] = score
            except:
                cveFound['cpe_score'] = 'Not found'

            cveList.append(cveFound)
            if (cve["cvss-vector"][:4] == "AV:N") :
                print("CVSS2: " + str(cve["cvss"]) + "                             Remotely exploitable.")
            elif (cve["cvss-vector"][:4] == "AV:L"):
                print("CVSS2: " + str(cve["cvss"]) + "                             Locally exploitable.")
            elif (cve["cvss-vector"][:4] == "AV:A"):
                print("CVSS2: " + str(cve["cvss"]) + "                             Exploitable via Adjcacent Network.")
            elif (cve["cvss-vector"][:4] == "AV:P"):
                print("CVSS2: " + str(cve["cvss"]) + "                             Physically exploitable.")
            else :
                print("CVSS2: " + str(cve["cvss"]))
        return cveList
    elif (version == '') :
        return 'obfuscated'
    else:
        print ("No vulnerabilities found.")
        print("---------------------------------------------------------------------")
        return None
    print("---------------------------------------------------------------------")


def banner_to_cpe(manufacturer, vendor, product, version, file_mode, cpe_list):
    jStr = ':'
    print("Original service: " + manufacturer + " " + vendor + " " +  product + " " + version)
    cpeArray = ['cpe:2.3', 'a', manufacturer, product, version, '*', '*', '*', '*', '*', '*', '*']
    p = jStr.join(cpeArray).lower()
    print("Original CPE: " + p)
    cpeString = exceptions(cpeArray[2].lower(), vendor.lower() ,cpeArray[3].lower(), cpeArray[4].lower())

    if file_mode:
        with open('cpedb.txt', 'r') as f:
            data = [line.strip() for line in f]
    else:
        data = cpe_list
        
    print("[INFORMANT] Verifying CPE Value")

    if cpeString != "cpe:2.3:a::::*:*:*:*:*:*:*:*":
        cpe = process.extractOne(cpeString, data, score_cutoff = 90)
        print("Generated CPE (after exceptions): " + cpeString)

    try:
        print("Predicted CPE: " + str(cpe[0]))
        print("Match Probability: " + str(cpe[1]) + "%")
        print("Similarity: " + str(round(fuzz.ratio(cpe[0], cpeString), 2)) + "%")
        return(cpe[0], cpe[1])
    except Exception:
        print("Generated CPE could not be verified. Using generated CPE value.")
        return(cpeString, 'No Match')


def default_check(cve):

    remote = False
    default = False

    if (cve["vector"][:4] == "AV:N") :
         remote = True
    if (cve["vector"][5:9] == "AC:L"):
        default = True
    
    if (remote and default):
        return True
    else:
        return False


def vul_scan(project_name):

    # Declare required vulnerables
    project_data = list(mainDB[project_name].find({'project_name' : project_name}))
    file_mode = True
    bulk_updates = []

    # Save histroical stats
    save_last_project_stats(project_name)

    # Generate local CPE file (.txt) - True = generate local .txt file | False = hold data in memory (Faster but more resource intensive)
    cpe_list, asset_list = gen_local_cpe_file(file_mode, project_name)

    # Validation/Error checking
    if (len(asset_list) == 0):
        print("[INFORMANT] No assets to check, run an Asset scan first.")
        exit(1)
    elif cpe_list is None:
        print("[INFORMANT] Using file-based fuzzer.")
    elif (len(cpe_list) >= 1):
        print("[INFORMANT] Using memory-based fuzzer.")
    else:
        print("[INFORMANT] No CPE data available, check the state of the CVE DB.")
        exit(1)

    validAssets = latest_records(asset_list, project_data[0])

    for asset in validAssets:
        try:
            mainDB[project_name].update({"_id": asset['_id']},{"$unset": {"cveData": 1}}, upsert=False)
            mainDB[project_name].update({"_id": asset['_id']},{"$unset": {"risks": 1}}, upsert=False)

            for service in asset['banners']:
                cpe_string, score = banner_to_cpe(service.get('manufacturer', ''),service.get('vendor', ''),service.get('product', ''),service.get('version', ''), file_mode, cpe_list)
                cves = cve_lookup(cpe_string, service.get('version', ''), service, score)
                if (cves is not None and cves != 'obfuscated'):
                    for cve in cves:
                        if default_check(cve):
                            cur_service = {'service' : service, 'cve' : cve, 'default' : True}
                            bulk_updates.append(UpdateOne({'_id': asset['_id']}, {'$push': {'risks': cur_service}}))
                    bulk_updates.append(UpdateOne({'_id': asset['_id']}, {'$push': {'cveData': cves}}))
                elif (cves == 'obfuscated'):
                    cur_service = {'service' : service, 'obfuscated' : True}
                    bulk_updates.append(UpdateOne({'_id': asset['_id']}, {'$push': {'risks': cur_service}}))
                else:
                    continue
            
        except Exception as e:
            print(f'[INFORMANT] Fatal CVE assignment error: {e}')

    # Update MongoDB in batches
    try:
        mainDB[project_name].bulk_write(bulk_updates)
    except Exception as e:
        print(str(e))

    # Need to rerun port flag and rddos check
    port_flag_check(project_name)
    rddos_prediction(project_name)
    
    # Update last_run time
    save_project_stats(project_name) 


def asset_scan(scan_range, shodan, censys, binaryedge, onyphe, max_records, threatcrowd, threatminer, robtex, daloo, farsight, dnsgrep, update, project_name):
    ipList = []
    timestamp = datetime.utcnow().replace(second=0, microsecond=0)
    data_ava = False
    project_data = mainDB[project_name].find({'project_name' : project_name})
    for r in project_data:
       project = r

    if (update) :
        # Save old scan results
        timeline = str(project['created_at'].date().strftime('%d/%m/%Y')) + "," + str(project['last_run'].date().strftime('%d/%m/%Y'))

        totalAssets, secureAssets, riskyAssets, defaultConfig = overview_total_stats(project['project_name'], 'IWS_1', timeline)

        mainDB[project_name].update_one({"project_name": project_name}, {"$set": {'last_stats': {'totalAssets': totalAssets, 'secureAssets' : secureAssets, 'risks': riskyAssets, 'defaultConfig' : defaultConfig}}}) 

        # IWS Scan
        if (shodan == True or censys == True or binaryedge == True or onyphe == True):
            ipList = iws_grabber(scan_range, shodan, censys, binaryedge, onyphe, max_records, update, timestamp, project_name)
        else:
            for record in mainDB[project_name].find({}):
                if 'ip' in record:
                    if (not record['ip'].islower() and not record['ip'].isupper()):
                        ipList.append(record['ip'])
            ipList = list(set(ipList))
        
        # PDNS Scan
        if (threatcrowd == True or threatminer == True or robtex == True or daloo == True or farsight == True or dnsgrep == True):
            print("[INFORMANT] Starting PDNS Enrichment")
            data_ava = pdns_grabber(scan_range, threatcrowd, threatminer, robtex, daloo, farsight, dnsgrep, ipList, update, timestamp, project_name)
            print("[INFORMANT] PDNS Enrichment Complete\n")

    else:
        ipList = iws_grabber(scan_range, shodan, censys, binaryedge, onyphe, max_records, update, timestamp, project_name)
        port_flag_check(project_name)
        if (threatcrowd == True or threatminer == True or robtex == True or daloo == True or farsight == True or dnsgrep == True):
            print("[INFORMANT] Starting PDNS Enrichment")
            data_ava = pdns_grabber(scan_range, threatcrowd, threatminer, robtex, daloo, farsight, dnsgrep, ipList, update, timestamp, project_name)
            print("[INFORMANT] PDNS Enrichment Complete\n")
        else:
            print("[INFORMANT] Skipped PDNS Enrichment")

    # Successful run, update data
    if len(ipList) != 0 or data_ava == True:
        mainDB[project_name].update_one({"project_name": project_name}, {"$set": {'last_params': {'Shodan': shodan, 'Censys' : censys, 'BinaryEdge': binaryedge, 'Onyphe' : onyphe,'Threatcrowd': threatcrowd, 'Threatminer' : threatminer, 'Robtex': robtex, 'Daloo' : daloo, 'Farsight' : farsight, 'DNSgrep' : dnsgrep}}})
        save_project_stats(project_name) 
        mainDB[project_name].update_one({"project_name": project_name}, {"$set": {"last_run": datetime.utcnow().replace(second=0, microsecond=0)}})
        port_flag_check(project_name)
    else:
        print("[INFORMANT] Scan found nothing, not updating last run time.")

    # rDDoS Check
    rddos_prediction(project_name)