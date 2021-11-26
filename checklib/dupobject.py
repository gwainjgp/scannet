# -*- coding: utf-8 -*


# coding=utf-8
#
# Obtengo una cita para el cuñao
#

# Libs
from . import common


# funciones publicas
def getName ():
    return 'dupobject'

def getDescription ():
    return 'Detect IP with multiple objects'

def getRE ():
    return 'dupo*'
    
def getReference ():
    return False

def getMade(scanDATA):
    response = { 'name' : 'dupobject', 'description' : 'Las siguientes IPs tienen más de un objeto en el dominio Check Point', 'data' : []}
    for i in common.sortIPs(scanDATA.keys()):
      if ('objects' in scanDATA[i].keys()) and (len(scanDATA[i]['objects']) > 1):
          item = { 'ip' : i, 'cpcobject' : []}
          for j in scanDATA[i]['objects']:
            item['cpcobject'].append({'uid' : j['uid'], 'name' : j['name']})
          response['data'].append(item)
    return response
   

## fin de get