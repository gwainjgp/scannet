# -*- coding: utf-8 -*


# coding=utf-8
#

#

# Libs
from . import common

# funciones publicas
def getName ():
    return 'changemacs'

def getDescription ():
    return 'Detect IP with modified access rules fromm reference file'

def getRE ():
    return 'changem*'
    
def getReference ():
    return True

def getMade(scanData,referenceData):
    response = { 'name' : 'changemacs', 'description' : 'Detectadas nuevas direcciones MACs', 'data' : []}
    newMACs = {}
    currentMACs = {}
    for i in scanData.keys():
        for j in scanData[i]['vendor'].keys():
            currentMACs[j] = scanData[i]['vendor'][j]
    oldMACs = {}
    for i in referenceData.keys():
        for j in referenceData[i]['vendor'].keys():
            oldMACs[j] = referenceData[i]['vendor'][j]
    newKeys = set(currentMACs.keys()) - set(oldMACs.keys())
    for i in newKeys:
         response['data'].append({ 'status' : 'new', 'mac' : i , 'vendor' : currentMACs[i]})
    newKeys = set(oldMACs.keys() - currentMACs.keys())
    for i in newKeys:
         response['data'].append({ 'status' : 'miss', 'mac' :i , 'vendor' : oldMACs[i]})
    
    return response
   

## fin de get