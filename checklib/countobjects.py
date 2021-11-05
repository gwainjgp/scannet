# -*- coding: utf-8 -*


# coding=utf-8
#
# Obtengo una cita para el cuñao
#

# Libs
from . import common


# funciones publicas
def getName ():
    return 'countobjects'

def getDescription ():
    return 'Count object and rules for each IP'

def getRE ():
    return 'counto*'
    
def getReference ():
    return False

def getMade(scanDATA):
    responseString = '# Uso de las IPs en checkpoint'
    for i in common.sortIPs(scanDATA.keys()):
        counts = {'access-control-rules': 0, 'nat-rules' : 0, 'objects' : 0, 'uid' : 0}
        if ('objects' in scanDATA[i].keys()):
            #uids
            counts['uid'] = len(scanDATA[i]['objects'])
        if ('whereused' in scanDATA[i].keys()):
            for uid in scanDATA[i]['whereused']:
                for useType in scanDATA[i]['whereused'][uid]:
                    #print ('useType', useType)
                    counts['access-control-rules'] += len(scanDATA[i]['whereused'][uid][useType]['access-control-rules'])
                    counts['nat-rules'] += len(scanDATA[i]['whereused'][uid][useType]['nat-rules'])
                    counts['objects'] += len(scanDATA[i]['whereused'][uid][useType]['objects'])     
        responseString += i + ', ' + str(counts) + '\n'   
    return responseString
   

## fin de get