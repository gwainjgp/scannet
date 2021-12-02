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
    #responseString = '# Uso de las IPs en checkpoint'
    response = { 'name' : 'listobjects', 'description' : 'Listado de objetos y reglas por IP', 'data' : []}
    for i in common.sortIPs(scanDATA.keys()):
        ipObject = {'ip' : i, 'objects' : [], 'access-rules' : [], 'nat-rules' : []}
        if ('objects' in scanDATA[i].keys()):
            for uid in scanDATA[i]['objects']:
                ipObject['objects'].append({'name' : uid['name'], 'uid' : uid['uid']})
        if ('access-rules' in  scanDATA[i].keys()):
            for rule in scanDATA[i]['access-rules']:
                ipObject['access-rules'].append(common.getSimpleRule(rule))
        if ('nat-rules' in  scanDATA[i].keys()):
            for rule in scanDATA[i]['nat-rules']:
                 ipObject['nat-rules'].append(common.getSimpleNATRule(rule))
        response['data'].append(ipObject)
    return response
   

## fin de get