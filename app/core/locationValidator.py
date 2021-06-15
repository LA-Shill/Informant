# !/usr/bin/env python
# Name:     locationValidator.py
# By:       LA-Shill
# Date:     28.11.2020
# Version   0.1
# -----------------------------------------------

# NEEDS CONVERTED TO CLASS WHEN TIME ALLOWS + MAKE PASSIVE, REPLACE LOCAL PING WITH API PING

import requests, platform, subprocess

def location_distance(origin, dest):
    """
    Function to calculate distance between orgin and host
    """
    try:
        resp = requests.get(url="https://www.distance24.org/route.json?stops=" + origin + "|" + dest)
        data = resp.json()
        distFromOrigin = 0.621371 * data['distance']
        return distFromOrigin
        if (resp.status_code == 404):
            print(f"Distance not found.")
    except:
            print(f"Distance24 connection error occured.")
            return 0

def ping_check(host):
    """
    Returns avg ping time value if host (str) responds to a ping request.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower()=='windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]
    #command = 'ping ' + param + ' 1 ' + host
    try:
        print(command)
        response = subprocess.check_output(command, stdout=subprocess.PIPE)
        print(response)
        avgPing = str(response, 'utf-8')

        if "Average = " in avgPing:
            index = avgPing.find("Average") + 10
            avgPing = avgPing[index:-4]
            return avgPing
    except:
        print("Location validation error: Please ensure the correct privileges are allowed.")
        return 0


def location_verification(distFromOrigin, avgPingTime):

    c = 124188.0
    calc = (distFromOrigin / c) * 1000

    if (calc > float(avgPingTime)):
        return False
    else:
        return True


def validate_loc(orign, dest, host):
    distFromOrigin = location_distance(orign , dest)
    if distFromOrigin > 0:
        avgPingTime = ping_check(host)
    
    # Just return funcation below after testing
    if location_verification(distFromOrigin, avgPingTime):
        print ("[INFORMANT] " + str(host) + " - Location data is accurate.")
        return True
    else:
        print ("[INFORMANT] " + str(host) + " - Location data is inaccurate.")
        return False