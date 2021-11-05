#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# enrichScan
# version 1.1
#
#  Add Check Point info to a nmap scan
# 
# Written by: Madrid Digital
# October 2021
# Updated: December 2017 for R80.10 API version
#


# A package for reading passwords without displaying them on the console.
from __future__ import print_function

import getpass,json,io,argparse
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs

## Functions
def loadScan(fichero):
    with open(fichero) as savedDataFile:
        try:
            oldScanJson = {}
            oldScanJson = json.load(savedDataFile)
            savedDataFile.close()
            return oldScanJson
        except:
            print ('Error al procesar el fichero json: ',fichero)

def saveScan(scanResult,fichero): 
    with io.open(fichero, 'w', encoding='utf8') as outfile:
        str_ = json.dumps(scanResult, indent=4, sort_keys=True, separators=(',', ': '), ensure_ascii=False)
        outfile.write(str_)
        outfile.close()


def findNoTCP(scanData):
    resultList = []
    for host in scanData.keys():
        if not ('tcp' in scanData[host].keys()):
            resultList.append(host)
    return resultList            

## Descargo todos los host de Check Point y los devuelvo
def getObjects (apikey,servers):
    client_args = APIClientArgs(server=servers)
    with APIClient(client_args) as client:
    
        # create debug file. The debug file will hold all the communication between the python script and
        # Check Point's management server.
        
        #client.debug_file = "api_calls.json"
    
        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)
    
        # login to server:
        login_res = client.login_with_api_key(apikey, domain=servers)
    
        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)
    
        # show hosts
        print("Processing Check Point Hosts. Please wait...")
        show_hosts_res = client.api_query('show-hosts', 'standard')
        if show_hosts_res.success is False:
            print("Failed to get the list of all host objects:\n{}".format(show_hosts_res.error_message))
            exit(1)
    
    # obj_dictionary - for a given IP address, get an array of hosts (name, unique-ID) that use this IP address.
    obj_dictionary = {}
     
    # Create a dict por host
    for host in show_hosts_res.data:
        ipaddr = host.get("ipv4-address")
        if ipaddr is None:
            print(host["name"] + " has no IPv4 address. Skipping...")
            continue
        #host_data = {"name": host["name"], "uid": host["uid"]}
        host_data = host
        if ipaddr in obj_dictionary:
            obj_dictionary[ipaddr] += [host_data]  # '+=' modifies the list in place
        else:
            obj_dictionary[ipaddr] = [host_data]
    
    return obj_dictionary

# Ejecuto un where-used para un UID
def getWhereUsed(apikey,servers,uid):
    client_args = APIClientArgs(server=servers)
    with APIClient(client_args) as client:
    
        # create debug file. The debug file will hold all the communication between the python script and
        # Check Point's management server.
        
        #client.debug_file = "api_calls.json"
    
        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)
    
        # login to server:
        login_res = client.login_with_api_key(apikey, domain=servers)
    
        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)
    
        # show hosts
        print("Processing Where-used. Please wait...")
        show_hosts_res = client.api_call('where-used',{ 'uid': uid, 'indirect': 'true'})
        if show_hosts_res.success is False:
            print("Failed to get the list of all host objects:\n{}".format(show_hosts_res.error_message))
            exit(1)
    return show_hosts_res.data

#Funcion operacional para recuperar los UID de reglas de acceso  de un objecto
def getAccessRulesUID(objectData):
    rulesUID = {}
    for usedType in ['used-directly', 'used-indirectly']:
        for rule in objectData[usedType]['access-control-rules']:
           #print('rule: ', rule['rule']['uid'],' ',rule['package']['name'])
           rulesUID[rule['rule']['uid']] = rule['layer']['uid']
    return rulesUID

#Recupero las reglas de acceso  donde está un objeto    
def getAccessRulesCP(apikey,servers,objectData):
    client_args = APIClientArgs(server=servers)
    rules = getAccessRulesUID(objectData)
    ruleList = []
    for uid in rules.keys():
        with APIClient(client_args) as client:        
            # create debug file. The debug file will hold all the communication between the python script and
            # Check Point's management server.
            
            #client.debug_file = "api_calls.json"
        
            # The API client, would look for the server's certificate SHA1 fingerprint in a file.
            # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
            # In case the user does not accept the fingerprint, exit the program.
            if client.check_fingerprint() is False:
                print("Could not get the server's fingerprint - Check connectivity with the server.")
                exit(1)
        
            # login to server:
            login_res = client.login_with_api_key(apikey, domain=servers)
        
            if login_res.success is False:
                print("Login failed:\n{}".format(login_res.error_message))
                exit(1)
        
            # show hosts
            print("Processing Access Rules. Please wait...")
            show_hosts_res = client.api_call('show-access-rule',{ 'uid': uid, 'layer' : rules[uid]})
            if show_hosts_res.success is False:
                print("Failed to get the list of all host objects:\n{}".format(show_hosts_res.error_message))
                exit(1)
            ruleList.append(show_hosts_res.data)
    return ruleList

#Funcion operacional para recuperar los UID de reglas de NAT de un objecto
def getNATRulesUID(objectData):
    rulesUID = {}
    for usedType in ['used-directly', 'used-indirectly']:
        for rule in objectData[usedType]['nat-rules']:
           #print('nat rule: ', rule['rule']['uid'],' ',rule['package']['name'])
           rulesUID[rule['rule']['uid']] = rule['package']['name']
    return rulesUID

#Recupero las reglas de NAT donde está un objeto 
def getNATRulesCP(apikey,servers,objectData):
    client_args = APIClientArgs(server=servers)
    rules = getNATRulesUID(objectData)
    ruleList = []
    for uid in rules.keys():
        with APIClient(client_args) as client:        
            # create debug file. The debug file will hold all the communication between the python script and
            # Check Point's management server.
            
            #client.debug_file = "api_calls.json"
        
            # The API client, would look for the server's certificate SHA1 fingerprint in a file.
            # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
            # In case the user does not accept the fingerprint, exit the program.
            if client.check_fingerprint() is False:
                print("Could not get the server's fingerprint - Check connectivity with the server.")
                exit(1)
        
            # login to server:
            login_res = client.login_with_api_key(apikey, domain=servers)
        
            if login_res.success is False:
                print("Login failed:\n{}".format(login_res.error_message))
                exit(1)
        
            # show hosts
            print("Processing NAT Rules. Please wait...")
            show_hosts_res = client.api_call('show-nat-rule',{ 'uid': uid, 'package' : rules[uid]})
            if show_hosts_res.success is False:
                print("Failed to get the list of all host objects:\n{}".format(show_hosts_res.error_message))
                exit(1)
            ruleList.append(show_hosts_res.data)
    return ruleList


# MAIN 
parser = argparse.ArgumentParser(description='Add extra data to scanned data')
parser.add_argument('scanfile',help='The scan file to Analize (Json)')
parser.add_argument('-s','--server', help='Checkpoint server to work with',default='172.25.35.122')
parser.add_argument('-o','--outfile', help='file to save the result')
parser.add_argument('-a','--apikey', help='User API Key')

args = parser.parse_args()
api_server = args.server
#Load the data
scanData = loadScan(args.scanfile)

# getting details from the user
#api_server = input("Enter server IP address or hostname:")
print ('Server and domain: ', api_server)

if not args.apikey:    
    if sys.stdin.isatty():
        apikey = getpass.getpass("Enter apikey: ")
    else:
        print("Attention! Your apikey will be shown on the screen!")
        apikey = input("Enter apikey: ")
else:
    apikey = args.apikey
    
# Load the objects list
cpHostList = getObjects(apikey,api_server)

# get the object for the IP
for ipAddress in scanData.keys():
    print('Procesing: ', ipAddress)
    if (ipAddress in cpHostList.keys()):
        #scanData = { ipAddress : {'objects' : [], 'whereused' :{}}}
        scanData[ipAddress]['objects'] = cpHostList[ipAddress]
        for cpObjects in scanData[ipAddress]['objects']:
            scanData[ipAddress]['whereused'] = {}
            scanData[ipAddress]['access-rules'] = []
            scanData[ipAddress]['nat-rules'] = []
            scanData[ipAddress]['whereused'][cpObjects['uid']] = {}
            scanData[ipAddress]['whereused'][cpObjects['uid']] = getWhereUsed(apikey,api_server,cpObjects['uid'])
            scanData[ipAddress]['access-rules'] = getAccessRulesCP(apikey,api_server,scanData[ipAddress]['whereused'][cpObjects['uid']])
            scanData[ipAddress]['nat-rules'] = getNATRulesCP(apikey,api_server,scanData[ipAddress]['whereused'][cpObjects['uid']])
    else:
        print('Not found in Check Point domain: ', api_server)    
# Test
if (args.outfile):
    saveScan(scanData,args.outfile)
    print('Result saved in: ', args.outfile)
else:
    print(json.dumps(scanData, indent=4, sort_keys=True, separators=(',', ': '), ensure_ascii=False))


