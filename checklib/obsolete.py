# -*- coding: utf-8 -*


# coding=utf-8
#
# Obtengo una cita para el cuñao
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
    responseString = '# Las siguientes IPs parece que no se necesitan (Sin servicos Publicados)\n'
    for i in common.sortIPs(scanDATA.keys()):
      if not ('tcp' in scanDATA[i].keys()):
          if not ('objects' in scanDATA[i].keys()):
              #print(i,' NO tiene objetos')
              for j in scanDATA[i]['vendor'].keys():
                  if ( j in common.getDomainMACs()):
                      responseString += str(i) + '; NO Objects\n'
          else:
              # Tiene objetos
              # mirar si alguna regla limita su accesso
              if ('nat-rules' in  scanDATA[i].keys()) and (len(scanDATA[i]['nat-rules']) > 0 ):
                  if ('access-rules' in  scanDATA[i].keys()):
                      # Verificar si los objetos esta en el source
                      openRule = ''
                      for rule in scanDATA[i]['access-rules']:
                          if (rule['source'][0]['name'].lower() in common.getOpenSources()) and (rule['enabled']):
                              openRule += '"' + rule['uid'] + '" '
                      if (openRule != ''):
                          responseString += str(i) +';Access from Any; access-rulesUID: [' +\
                         openRule + ']; realobject: ' + \
                         common.prettyDestinationNAT(scanDATA[i]['nat-rules']) +'\n'
                  else:
                      responseString += str(i) + '; ' + '; NAT and NOT Access Rule \n'
              else:
                  # No tiene reglas de NAT
                  if ('whereused' in  scanDATA[i].keys()) and (len(scanDATA[i]['whereused']) > 0 ):
                     used = False
                     for objectUID in scanDATA[i]['whereused'].keys():
                         if (scanDATA[i]['whereused'][objectUID]['used-directly']['total'] > 0):
                              used = True
                     if not used:
                         responseString += str(i) + '; ' + '; NO Rules & NO used\n'
    return responseString
   

## fin de get