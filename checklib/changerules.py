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
    return 'Detect IP with modified access rules fromm reference file'

def getRE ():
    return 'changer*'
    
def getReference ():
    return True

def getMade(scanData,referenceData):
    responseString = '# Las siguientes IPs  están en reglas diferentes\n'
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
                        responseString += i + ', rule create: ' + common.prettyPrintAccessRule(i,rule,scanData) + '\n'
                    for rule in (rulesOld - rulesCurrent):
                        #print('  Rule delete: ', common.prettyPrintAccessRule(i,rule,referenceData))
                        responseString += i + ',  rule delete: ' + common.prettyPrintAccessRule(i,rule,referenceData) + '\n'
                    for rule in (rulesCurrent & rulesOld):
                        oldFullRule = common.getFullAccessRule(rule,referenceData[i]['access-rules'])
                        newFullRule = common.getFullAccessRule(rule,scanData[i]['access-rules'])
                        if (oldFullRule != newFullRule):
                            #print('  Rule original: ', common.prettyPrintAccessRule(i,rule,referenceData))
                            responseString += i + ', rule original: ' + common.prettyPrintAccessRule(i,rule,referenceData) + '\n'
                            #print('  Rule modified: ',common.prettyPrintAccessRule(i,rule,scanData))
                            responseString += i + ', rule modified: ' + common.prettyPrintAccessRule(i,rule,scanData) + '\n'
                else:
                    #print (i, ' NO TENIA reglas')
                    for rule in common.getAccessRulesUID(i,scanData):
                        #print('  Rule new: ', common.prettyPrintAccessRule(i,rule,scanData))
                        responseString += i + ', rule new: ' + common.prettyPrintAccessRule(i,rule,scanData) + '\n'
            else:
                #print(i, ' NO tiene reglas')
                if ('access-rules' in referenceData[i].keys()) and (len(referenceData[i]['access-rules']) > 0):
                    for rule in common.getAccessRulesUID(i,referenceData):
                        #print('  Rule delete: ', common.prettyPrintAccessRule(i,rule,referenceData))
                        responseString += i + ', rule delete: '  +  common.prettyPrintAccessRule(i,rule,referenceData) + '\n'
        else:
            #print(i, ' Nueva')
            for rule in common.getAccessRulesUID(i,scanData):
                #print('  Rule new: ', common.prettyPrintAccessRule(i,rule,scanData))
                responseString += i + ', rule new: ' + common.prettyPrintAccessRule(i,rule,scanData) + '\n'
    return responseString
   

## fin de get