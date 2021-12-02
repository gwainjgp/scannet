# -*- coding: utf-8 -*
#
# Funciones comunes para todos
import __main__

def getDomainMACs():
    #listMAC = ['00:12:C1:0E:50:06','00:12:C1:C2:D0:04']
    return __main__.conf.config['knowMACs']

def getDomainFirewalls():
    #ist = ['195.77.129.20','213.0.53.131']
    return __main__.conf.config['domainFirewalls']
    
def getOpenSources():
    return __main__.conf.config['openSources']

def sortIPs(ips):
    import ipaddress
    return sorted(ips, key = ipaddress.IPv4Address)

def prettyCell(cellContent):
    cellString = '["' + str(cellContent.pop(0)['name']) + '"'
    for object in cellContent:
        cellString += ', "' + str(object['name'] ) + '"'
    return cellString + ']'
    
def getAccessRulesUID(ipAddress,scanData):
    UIDList = []
    for rule in scanData[ipAddress]['access-rules']:
       UIDList.append(rule['uid'])
    return UIDList

def getFullAccessRule(UID, ruleList):
    ruleUID = {}
    for rule in ruleList:
      if (UID == rule['uid']):
          ruleUID = rule
    return ruleUID
    
def prettyPrintAccessRules(ipAddress,scanData):
    ruleString = ''
    for rule in scanData[ipAddress]['access-rules']:
       print(rule['uid'])
    return ruleString

def prettyPrintAccessRule(ipAddress,ruleUID,scanData):
    ruleString = ''
    for rule in scanData[ipAddress]['access-rules']:
       if (rule['uid'] == ruleUID):
           if not (rule['enabled']):
               ruleString += 'DISABLED '         
           if ('name' in rule.keys()):
               ruleString += ' "name": "' + rule['name'] + '"'
           else:
               ruleString += ' "name": ""'       
           ruleString += ', "source": '
           if rule['source-negate']:
               ruleString += 'NOT '
           ruleString += prettyCell(rule['source'])
           ruleString += ', "destination": '
           if rule['destination-negate']:
               ruleString += 'NOT '
           ruleString += prettyCell(rule['destination'])
           ruleString += ', "services": '
           if rule['service-negate']:
               ruleString += 'NOT '
           ruleString += prettyCell(rule['service'])
           ruleString += ', "action": "' + rule['action']['name']+ '"'
           ruleString += ', "uid": "' + rule['uid'] + '"'
    return ruleString

def getSimpleRule(rule):
    simpleRule = { 
        'uid' : rule['uid'], 
        'enabled' : rule['enabled'],
        'source-negate': rule['source-negate'],
        'destination-negate' : rule['destination-negate'],
        'source' : rule['source'],
        'destination' : rule['destination'],
        'service-negate' : rule['service-negate'],
        'service' : rule['service'],
        'action' : rule['action']['name'],
        }
    if 'name' in rule.keys():
        simpleRule['name'] = rule['name']
    else:
        simpleRule['name'] = ''
    for cell in ['source','destination','service']:
        nameList = []
        for objectEntry in rule[cell]:
            nameList.append({'name' : objectEntry['name'], 'uid' : objectEntry['uid']})
        simpleRule[cell] = nameList
    return simpleRule

def getSimpleNATRule(rule):
    simpleRule = {
         'original-source' : { 'name' : rule['original-source']['name'], 'uid' : rule['original-source']['uid'] },
         'original-destination' :  { 'name' :  rule['original-destination']['name'], 'uid' : rule['original-destination']['uid'] },
         'original-service' :  { 'name' : rule['original-service']['name'], 'uid' : rule['original-service']['uid'] },
         'translated-source' :  { 'name' : rule['translated-source']['name'], 'uid' : rule['translated-source']['uid'] },
         'translated-destination' :  { 'name' : rule['translated-destination']['name'], 'uid' : rule['translated-destination']['uid'] },
         'translated-service' :  { 'name' : rule['translated-service']['name'], 'uid' : rule['translated-service']['uid'] },
         'uid' : rule['uid']
        }
    return simpleRule


def getNATRulesUID(ipAddress,scanData):
    UIDList = []
    for rule in scanData[ipAddress]['nat-rules']:
       UIDList.append(rule['uid'])
    return UIDList

def prettyPrintNATRule(ipAddress,ruleUID,scanData):
    ruleString = ''
    for rule in scanData[ipAddress]['nat-rules']:
       if (rule['uid'] == ruleUID):
           if not (rule['enabled']):
               ruleString += 'DISABLED ' 
           ruleString += '"original-source": "' + rule['original-source']['name'] + '"'
           ruleString += ', "original-destination": "' + rule['original-destination']['name'] + '"'
           ruleString += ', "original-service": "' + rule['original-service']['name'] + '"'
           ruleString += ', "translated-source": "' + rule['translated-source']['name'] + '"'
           ruleString += ', "translated-destination": "' + rule['translated-destination']['name'] + '"'
           ruleString += ', "translated-service": "' + rule['translated-service']['name'] + '"'
           ruleString += ', "uid": "' + rule['uid'] + '"'
    return ruleString

def prettyDestinationNAT(natRules):
    responseList = '["' + str(natRules.pop(0)['translated-destination']['name']) + '"'
    for rule in natRules:
        responseList += ', "' + str(rule['translated-destination']['name'] ) + '"'
    return responseList + ']'

def getDestinationNAT(natRules):
    response = []
    for rule in natRules:
       response.append(rule['translated-destination']['name'])
    return response

    
