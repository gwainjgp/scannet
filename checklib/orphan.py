# -*- coding: utf-8 -*


# coding=utf-8
#
# Obtengo una cita para el cuñao
#

# Libs
from . import common

# funciones publicas
def getName ():
    return 'orphan'

def getDescription ():
    return 'Detect IP with no objects'

def getRE ():
    return 'orphan*'
    
def getReference ():
    return False

def getMade(scanDATA):
    response = { 
        'name' : 'listobjects',
        'description' : 'Las siguientes IPs no tienen objeto en el dominio Check Point',
        'data' : []
        }
    for i in common.sortIPs(scanDATA.keys()):
      if not ('objects' in scanDATA[i].keys()):
          for j in scanDATA[i]['vendor'].keys():
              if (j not in common.getDomainMACs()):
                  response['data'].append({'ip' : i, 'mac' : j, 'vendor' : scanDATA[i]['vendor'][j]})
    return response
   

## fin de get