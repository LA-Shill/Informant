# !/usr/bin/env python
# Name:     vuls.py
# By:       LA-Shill
# Date:     15.01.2021
# Version   0.1
# -----------------------------------------------

import pymongo
from datetime import datetime, timedelta
from .standardValues import StandardValues
import os

# Setup database
client = pymongo.MongoClient(StandardValues.DB_HOST, StandardValues.DB_PORT)
mainDB = client[StandardValues.MAIN_DB_NAME]
vulDB = client[StandardValues.VUL_DB_NAME]


def gen_local_cpe_file(option, project_name):

    data = []
    master_list = []

    try:
        data = list(mainDB[project_name].find({"source": 'merged'}).sort("timestamp", -1))
    except Exception as e:
        print("Failed to obtain asset list from DB: " + str(e))
        return master_list, data

    if option:
        if (os.path.isfile("cpedb.txt")) :
            print("[INFORMANT] Skipping local DB file created.")
        else:
            try:
                cpeList = vulDB['cpe'].find({})
                for record in cpeList:
                    if 'cpe_2_2' in record:
                        master_list.append(record['cpe_2_2'])
                    if 'cpe_name' in record:
                        for entry in record['cpe_name']:
                            try:
                                master_list.append(entry['cpe23Uri'])
                            except Exception:
                                continue

                f = open("cpedb.txt", "w")
                for cpe in master_list:
                    f.write(cpe + '\n')
                f.close()
                print("[INFORMANT] Created local CPE list from DB")
            except Exception as e:
                print("Failed to obtain cpe list from DB: " + str(e))

        return None, data
    else:
        try:
            cpeList = vulDB['cpe'].find({})
            for record in cpeList:
                if 'cpe_2_2' in record:
                    master_list.append(record['cpe_2_2'])
                if 'cpe_name' in record:
                    for entry in record['cpe_name']:
                        try:
                            master_list.append(entry['cpe23Uri'])
                        except Exception:
                            continue
        except Exception as e:
            print("Failed to obtain cpe list from DB: " + str(e))

        return master_list, data
