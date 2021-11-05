# -*- coding: utf-8 -*


# coding=utf-8
#
# Obtengo una cita para el cuñao
#

# Libs
from . import common


# funciones publicas
def getName ():
    return 'listobjects'

def getDescription ():
    return 'List object and rules for each IP'

def getRE ():
    return 'listo*'
    
def getReference ():
    return False

def getMade(scanDATA):
    responseString = '# Uso de las IPs en checkpoint'
    for i in common.sortIPs(scanDATA.keys()):
        if ('objects' in scanDATA[i].keys()):
            for uid in scanDATA[i]['objects']:
                responseString += '"ip": "'+ i + '", "object": { "name": "' +  uid['name'] + '", "uid": "' + uid['uid'] + '"}\n'
        if ('access-rules' in  scanDATA[i].keys()):
            for rule in common.getAccessRulesUID(i,scanDATA):
                responseString += '"ip": "' + i + '", "access-rule": { ' + common.prettyPrintAccessRule(i,rule,scanDATA) + '}\n'
        if ('nat-rules' in  scanDATA[i].keys()):
            for rule in common.getNATRulesUID(i,scanDATA):
                 responseString += '"ip": "' + i + '", "nat-rule": { ' + common.prettyPrintNATRule(i,rule,scanDATA) + '}\n'
    return responseString
   

## fin de get