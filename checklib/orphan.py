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
    responseString = '# Las siguientes IPs no tienen objecto en el dominio Check Point\n'
    for i in common.sortIPs(scanDATA.keys()):
      if not ('objects' in scanDATA[i].keys()):
          #print(i,' NO tiene objetos')
          for j in scanDATA[i]['vendor'].keys():
              responseString += str(i) + '; '+ j + '; '+ scanDATA[i]['vendor'][j] + '\n'
    return responseString
   

## fin de get