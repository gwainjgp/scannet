# -*- coding: utf-8 -*


# coding=utf-8
#
#

# Libs
from . import common


# funciones publicas
def getName ():
    return 'obsolete'

def getDescription ():
    return 'Detect IP to remove'

def getRE ():
    return 'obso*'
    
def getReference ():
    return False

def getMade(scanDATA):
    response = { 'name' : 'obsolete', 'description' : 'Detect IP to remove', 'data' : []}
    for i in common.sortIPs(scanDATA.keys()):
      if not ('tcp' in scanDATA[i].keys()):
          if not ('objects' in scanDATA[i].keys()):
              #print(i,' NO tiene objetos')
              for j in scanDATA[i]['vendor'].keys():
                  if ( j in common.getDomainMACs()):
                      #responseString += str(i) + '; NO Objects\n'
                      response['data'].append({'ip' : i, 'reason' : 'NoObjects'})
          else:
              # Tiene objetos
              # mirar si alguna regla limita su accesso
              if ('nat-rules' in  scanDATA[i].keys()) and (len(scanDATA[i]['nat-rules']) > 0 ):
                  if ('access-rules' in  scanDATA[i].keys()):
                      # Verificar si los objetos esta en el source
                      openRules = []
                      for rule in scanDATA[i]['access-rules']:
                          if (rule['source'][0]['name'].lower() in common.getOpenSources()) and (rule['enabled']):
                              openRules.append(common.getSimpleRule(rule))
                      if (openRules):
                          response['data'].append({
                              'ip' : i, 
                              'reason' : 'AccessfromAny', 
                              'rules' : openRules,
                              'translated-destination' : common.getDestinationNAT(scanDATA[i]['nat-rules'])
                               })
                  else:
                      response['data'].append({'ip' : i, 'reason' : 'NATandNOTAccess'})
              else:
                  # No tiene reglas de NAT
                  if ('whereused' in  scanDATA[i].keys()) and (len(scanDATA[i]['whereused']) > 0 ):
                     used = False
                     for objectUID in scanDATA[i]['whereused'].keys():
                         if (scanDATA[i]['whereused'][objectUID]['used-directly']['total'] > 0):
                              used = True
                     if not used:
                         response['data'].append({'ip' : i, 'reason' : 'NoRulesandNoused'})
    return response
   

## fin de get