# -*- coding: utf-8 -*


# coding=utf-8
#

#

# Libs
from . import common

# funciones publicas
def getName ():
    return 'changerules'

def getDescription ():
    return 'Detect IP with modified access rules from reference file'

def getRE ():
    return 'changer*'
    
def getReference ():
    return True

def getMade(scanData,referenceData):
    response = { 'name' : 'changerules', 'description' : 'Direcciones IP cuyas reglas de acceso han cambiado', 'data' : []}
    for i in common.sortIPs(scanData.keys()):
        if i in referenceData.keys():
            if ('access-rules' in scanData[i].keys()) and (len(scanData[i]['access-rules']) > 0):
                #print(i, ' tiene reglas')
                if ('access-rules' in referenceData[i].keys()) and (len(referenceData[i]['access-rules']) > 0):
                    #print(i, ' tenia reglas')
                    rulesCurrent = set(common.getAccessRulesUID(i,scanData))
                    rulesOld = set(common.getAccessRulesUID(i,referenceData))
                    for rule in (rulesCurrent - rulesOld):
                        #print('  Rule create: ', common.prettyPrintAccessRule(i,rule,scanData))
                        newFullRule = common.getFullAccessRule(rule,scanData[i]['access-rules'])
                        response['data'].append({'ip' : i, 'reason' : 'new', 'uid' : rule, 'rule' : newFullRule})
                    for rule in (rulesOld - rulesCurrent):
                        #print('  Rule delete: ', common.prettyPrintAccessRule(i,rule,referenceData))
                        oldFullRule = common.getFullAccessRule(rule,referenceData[i]['access-rules'])
                        response['data'].append({'ip' : i, 'reason' : 'delete', 'uid' : rule, 'rule' : oldFullRule})
                    for rule in (rulesCurrent & rulesOld):
                        oldFullRule = common.getFullAccessRule(rule,referenceData[i]['access-rules'])
                        newFullRule = common.getFullAccessRule(rule,scanData[i]['access-rules'])
                        if (oldFullRule != newFullRule):
                            #print('  Rule original: ', common.prettyPrintAccessRule(i,rule,referenceData))
                            response['data'].append({'ip' : i, 'reason' : 'original', 'uid' : rule, 'rule' : oldFullRule})
                            #print('  Rule modified: ',common.prettyPrintAccessRule(i,rule,scanData))
                            response['data'].append({'ip' : i, 'reason' : 'modified', 'uid' : rule, 'rule' : newFullRule})
                else:
                    #print (i, ' NO TENIA reglas')
                    for rule in common.getAccessRulesUID(i,scanData):
                        #print('  Rule new: ', common.prettyPrintAccessRule(i,rule,scanData))
                        newFullRule = common.getFullAccessRule(rule,scanData[i]['access-rules'])
                        response['data'].append({'ip' : i, 'reason' : 'new', 'uid' : rule, 'rule' : newFullRule})
            else:
                #print(i, ' NO tiene reglas')
                if ('access-rules' in referenceData[i].keys()) and (len(referenceData[i]['access-rules']) > 0):
                    for rule in common.getAccessRulesUID(i,referenceData):
                        #print('  Rule delete: ', common.prettyPrintAccessRule(i,rule,referenceData))
                        oldFullRule = common.getFullAccessRule(rule,referenceData[i]['access-rules'])
                        response['data'].append({'ip' : i, 'reason' : 'delete', 'uid' : rule, 'rule' : oldFullRule})
        else:
            #print(i, ' Nueva')
            for rule in common.getAccessRulesUID(i,scanData):
                #print('  Rule new: ', common.prettyPrintAccessRule(i,rule,scanData))
                newFullRule = common.getFullAccessRule(rule,scanData[i]['access-rules'])
                response['data'].append({'ip' : i, 'reason' : 'new', 'uid' : rule, 'rule' : newFullRule})
    return response
   

## fin de get