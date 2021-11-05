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
    responseString = '# Las siguientes IPs tienen más de un objeto en el dominio Check Point\n'
    for i in common.sortIPs(scanDATA.keys()):
      if ('objects' in scanDATA[i].keys()) and (len(scanDATA[i]['objects']) > 1):
          #print(i,' ',len(scanDATA[i]['objects']))
          responseString += i
          for j in scanDATA[i]['objects']:
            responseString += '; ' + j['uid'] + '(' +j['name'] + ')'
          responseString += '\n'
    return responseString
   

## fin de get