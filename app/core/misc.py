# !/usr/bin/env python
# Name:     misc.py
# By:       LA-Shill
# Date:     15.01.2021
# Version   0.1
# -----------------------------------------------

import tldextract
from datetime import datetime, timedelta
import pymongo
from .standardValues import StandardValues
import csv
from io import StringIO
import socket
from pymongo import UpdateMany, UpdateOne
import time
import pprint

# Setup database
client = pymongo.MongoClient(StandardValues.DB_HOST, StandardValues.DB_PORT)
mainDB = client[StandardValues.MAIN_DB_NAME]

def tld_count(tlds):
    
    tldList : list = []

    for tld in tlds:
        try:
            ext = tldextract.extract(tld)
            tld = '.'.join(ext[1:3])
            tldList.append(tld)
        except Exception as e:
            print('[INFORMANT] TLDExtraction error: ' + str(e))
    
    result = list(set(tldList))
    return (result)


def subdomain_count(tlds):
    
    subList : list = []
    for tld in tlds:
        try:
            ext = tldextract.extract(tld)
            if ext.subdomain != '':
                r = '.'.join(ext[:3])
                subList.append(r)
        except Exception as e:
            print('[INFORMANT] TLDExtraction error: ' + str(e))
    
    result = list(set(subList))
    return (result)


def overview_total_stats(project_name, schema, time_range):

    if type(time_range) is list :
        time_min = time_range[0]
        time_max = time_range[1]
        offset = 24
    else:
        # Convert times
        timeline = time_range.split(',')
        time_min = datetime.strptime(timeline[0], '%d/%m/%Y')
        time_max = datetime.strptime(timeline[1], '%d/%m/%Y')
        offset = 24

    if schema == "IWS_0": 
        # Total Assets 
        data = list(mainDB[project_name].find({"$and": [{"source": 'merged'}, {'timestamp':{'$gte':time_min, '$lt':time_max + timedelta(hours=offset)}}]}).sort("timestamp", -1))
        tmpData = []
        assets = []
        filteredAssets = []
        validAssets = []
        filteredRiskyAssets = []

        # Remove duplicate based on timestamp being closes to maxtime
        for entry in data:
            assets.append(entry['ip'])

        filteredAssets = list(set(assets))
        
        for ip in filteredAssets:
            tempRecords = []
            for entry in data:
                if entry['ip'] == ip:
                    tempRecords.append(entry)
            
            validAssets.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - time_max)))


        totalAssets = len(validAssets)

        vulAssetList = []
        defaultConfig = 0
        riskyAssets = 0 
        finalVulAssets = []


        for record in data:
            if 'risks' in record:
                for risk in record['risks']:
                    if 'ports' in risk:
                        tmpData.append(record)
                    elif 'cve' in risk:
                        tmpData.append(record)
                    elif 'rddos' in risk:
                        tmpData.append(record)
            if 'cveData' in record:
                tmpData.append(record)
                
        for entry in tmpData:
            vulAssetList.append(entry['ip'])

        filteredRiskyAssets = list(set(vulAssetList))
        

        for ip in filteredRiskyAssets:
            tempRecords = []
            for entry in tmpData:
                if entry['ip'] == ip:
                    tempRecords.append(entry)
            finalVulAssets.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - time_max)))

        secureAssets = totalAssets - len(finalVulAssets)
        riskyAssets += len(finalVulAssets)
        # Risky data
        data = list(mainDB[project_name].find({"$and": [{"flagged": True},{"type": 'pdns'}, {'timestamp':{'$gt':time_min, '$lte':time_max + timedelta(hours=offset)}}]}).sort("timestamp", -1))
        domains = []
        newData = []

        # Remove duplicate based on timestamp being closes to maxtime
        for entry in data:
            domains.append(entry['domain'])

        n_domains = list(set(domains))
        
        for domain in n_domains:
            tempRecords = []
            for entry in data:
                if entry['domain'] == domain:
                    tempRecords.append(entry)
            
            newData.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - time_max)))
        riskyAssets += len(newData)

        # Default check
        for entry in finalVulAssets:
            if 'risks' in entry:
                for risk in entry['risks']:
                    if 'default' in risk:
                        defaultConfig += 1
                        break
                

        return totalAssets, secureAssets, riskyAssets, defaultConfig

    if schema == "IWS_1": 
        risks = 0
        defaultConfig = 0
        totalAssets = 0
        secureAssets = 0

        # Total Asset Count
        data = list(mainDB[project_name].find({"$and": [{"source": 'merged'}, {'timestamp':{'$gte':time_min, '$lt':time_max + timedelta(hours=offset)}}]}).sort("timestamp", -1))
        assets = []
        done = set()
        assets_timebased = []

        for record in data:
            if record['ip'] not in done:
                done.add(record['ip'])
                assets.append(record)

        for asset in assets:
            tempRecords = []
            for record in data:
                if record['ip'] == asset['ip']:
                    tempRecords.append(record)
            assets_timebased.append(min(tempRecords, key=lambda x:abs(x.get('timestamp', time_max) - datetime.now())))

        totalAssets = len(assets_timebased)
        
        # Total Risk Count (IWS)
        riskyAssets = []
        for record in assets_timebased:
            if 'risks' in record:
                for risk in record['risks']:
                    if 'ports' in risk:
                        riskyAssets.append(record['ip'])
                    elif 'cve' in risk:
                        riskyAssets.append(record['ip'])
            if 'cveData' in record:
                riskyAssets.append(record['ip'])

        
        risks = len(list(set(riskyAssets)))
        # Secure Asset Count (IWS)
        secureAssets = (len(assets_timebased) - len(list(set(riskyAssets))))

        # Total Risk Count (PDNS)
        data = list(mainDB[project_name].find({"$and": [{"flagged": True},{"type": 'pdns'}, {'timestamp':{'$gt':time_min, '$lte':time_max + timedelta(hours=offset)}}]}).sort("timestamp", -1))
        done = set()
        pdns = []
        pdns_timebased = []
        for record in data:
            if record['domain'] not in done:
                done.add(record['domain'])
                pdns.append(record)
        for asset in pdns:
            tempRecords = []
            for record in data:
                if record['domain'] == asset['domain']:
                    tempRecords.append(record)
            pdns_timebased.append(min(tempRecords, key=lambda x:abs(x.get('timestamp', time_max) - datetime.now())))
        risks += len(pdns_timebased)        

        # Default check
        default = []
        for entry in assets_timebased:
            if 'risks' in entry:
                for risk in entry['risks']:
                    if 'default' in risk:
                        default.append(entry['ip'])
                        break
        
        defaultConfig = len(list(set(default)))


        return totalAssets, secureAssets, risks, defaultConfig


def save_last_project_stats(project_name):
    # Retrieve doc of current project stats
    project_data = list(mainDB[project_name].find({'project_name' : project_name}))
    # Grab old results
    timeline = str(project_data[0]['created_at'].date().strftime('%d/%m/%Y')) + "," + str(project_data[0]['last_run'].date().strftime('%d/%m/%Y'))
    totalAssets, secureAssets, riskyAssets, defaultConfig = overview_total_stats(project_data[0]['project_name'], 'IWS_1', timeline)
    # Save old scan results
    mainDB[project_data[0]['project_name']].update_one({"project_name": project_data[0]['project_name']}, {"$set": {'last_stats': {'totalAssets': totalAssets, 'secureAssets' : secureAssets, 'risks': riskyAssets, 'defaultConfig' : defaultConfig}}}) 


def per_change(current, previous):
    if previous == 0 or current == 0:
        return 0
    elif(previous > current ):
        try:
            return round(((abs(current - previous) / previous) * 100)*-1, 2)
        except :
            return 0
        #return round(((abs(current - previous) / previous) * 100)*-1, 2)
    else:
        try:
            return round((abs(previous - current) / current) * 100, 2)
        except :
            return 0


def latest_records(data, project_info):
    asset_list = []
    filteredAssets = []
    validAssets = []

    # Remove duplicate based on timestamp being closes to maxtime
    for entry in data:
        asset_list.append(entry['ip'])

    filteredAssets = list(set(asset_list))
    for ip in filteredAssets:
        tempRecords = []
        for entry in data:
            if entry['ip'] == ip:
                tempRecords.append(entry)
        try:
            validAssets.append(min(tempRecords, key=lambda x:abs(x['timestamp'] - project_info['last_run'])))
        except Exception as e:
            print(f'Failed to get latest records: {e}')
    
    return validAssets


def oldest_records(data, project_info):
    asset_list = []
    filteredAssets = []
    validAssets = []

    # Remove duplicate based on timestamp being closes to maxtime
    for entry in data:
        asset_list.append(entry['ip'])

    filteredAssets = list(set(asset_list))
    for ip in filteredAssets:
        tempRecords = []
        for entry in data:
            if entry['ip'] == ip:
                tempRecords.append(entry)
        try:
            validAssets.append(max(tempRecords, key=lambda x:abs(x['timestamp'] - project_info['last_run'])))
        except Exception as e:
            print(f'Failed to get oldest records: {e}')

    return validAssets


def csv_export(data):
    csv_data = ""
    # Compute all potential field names
    fieldnames = set()
    for d in data:
        fieldnames.update(d.keys())
    fieldnames = sorted(fieldnames)

    # Create CSV
    with open("tmp/export.csv", "w", newline='') as fd:
        wr = csv.DictWriter(fd, fieldnames)
        wr.writeheader()
        wr.writerows(data)
    
    # Read CSV in as string
    with open('tmp/export.csv',"rt", encoding='ascii') as f:
        for row in f:
            csv_data += row

    return csv_data


def cymru_query(bulk_query, timeout):
    # Team Cymru IP to ASN Query (netcat)
    try:
        data = ""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("whois.cymru.com", 43))
        s.sendall(bulk_query)
        reply = s.recv(4098)
        data = reply
        # Gets data until an empty line is found.
        while True:
            reply = s.recv(1024)
            data += reply
    except socket.timeout:
        if data != '':
            pass
        else:
            raise
    except Exception as e:
        raise e
    finally:
        s.close()

    return data


def pdns_enrichment(project_name, timestamp):

    pdnsIpList = []

    print("[INFORMANT] Starting Further PDNS Enrichment")
    d1 = mainDB[project_name].find({'timestamp': timestamp})
    print("[ENRICH] Pulled Records")
    for record in d1:
        if 'type' in record:
            if (not record['ip'].islower() and not record['ip'].isupper()):
                pdnsIpList.append(record['ip'])
    # Remove dupes
    pdnsIpList = list(set(pdnsIpList))
    print("[ENRICH] Sorted Records")
    i = 0
    delay = 0
        
    if len(pdnsIpList) >= 50:
        print("[INFORMANT] Using Bulk ASN & Netname Lookup - Total IPs: " + str(len(pdnsIpList)))
        # Batch up the bulk requests
        batches = [pdnsIpList[x:x+500] for x in range(0, len(pdnsIpList), 500)]
        if(len(batches) > 1):
            print("[INFORMANT] Large Data Set Detected! Total Batches: " + str(len(batches)))
            delay = 1
            
        for batch in batches:
            i += 1
            bulk_query = "begin\nverbose\n"
            for ip in batch:
                bulk_query += str(ip) + '\n'
            bulk_query += "end"
            time.sleep(delay)
            response = cymru_query(bulk_query.encode('utf_8'), 5)
            string = response.decode('utf-8')
            bulk_updates = []
            # Quick RE clean up (probs better changing into CSV format first)
            for entry in string.splitlines():
                try:
                    split_entry = entry.split("|", 6)
                    asn = split_entry[0].strip()
                    ip = split_entry[1].strip()
                    netname = split_entry[6].strip()
                    netname = netname.split(",", 1)
                    bulk_updates.append(UpdateMany({"$and": [{"ip": ip}, {'timestamp': timestamp}]}, {'$set': {'asn': asn}}))
                    bulk_updates.append(UpdateMany({"$and": [{"ip": ip}, {'timestamp': timestamp}]}, {'$set': {'netname': netname[0]}}))
                except Exception as e:
                    print(str(e))
                    continue
            try:
                mainDB[project_name].bulk_write(bulk_updates)
            except BulkWriteError as bwe:
                pprint(bwe.details)
            print("[INFORMANT] Batch " + str(i) + " of " + str(len(batches)) + " complete")

    else:
        print("[INFORMANT] Using Standard ASN & Netname Lookup")
        for record in mainDB[project_name].find({'timestamp': timestamp}):
            if 'type' in record:
                if (not record['ip'].islower() and not record['ip'].isupper()):
                    try:
                        lookup = IPWhois(record['ip']).lookup_rdap(asn_methods=['dns', 'whois', 'http']) 
                        mainDB[project_name].find_one_and_update({"_id": record['_id']},{"$set": {"asn": lookup['asn']}})
                        mainDB[project_name].find_one_and_update({"_id": record['_id']},{"$set": {"netname": lookup['network']['name']}})
                    except Exception as e:
                        print("[INFORMANT] PDNS ASN & Netname Enrichment Error (Standard method): " + str(e))
                        continue
    print("[INFORMANT] Further PDNS Enrichment Complete")