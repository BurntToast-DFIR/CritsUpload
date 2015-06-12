from base64 import b64decode 
import pycrits 
import datetime
import re 

HOST = 'http://192.168.0.128:8080'
API_KEY = '72c6550ca9a83b1c502acca999356ae02763e2a2' # 72c6550ca9a83b1c502acca999356ae02763e2a2
USER_NAME = 'adove' 
SOURCE = 'CSIRT FR'
FILENAME = 'D:\\db_2014_08_20.csv'
BUCKET_LIST='Malware DB'
CAMPAIGNS = ['Terminator', 'Kuluoz', 'Taidoor', 'xAPTCode','PlugX','Hidden Lynx','Protux','Banking Trojan', 'Zeus','Citadel','IXESHE',
                 'Grand Theft Auto (GTA) Panda)','PaoHuiKing','Lurid','PcShare','Poison Ivy','Ghost Rat','APT.Mongol','NetTraveler']

class DataEntry(object):
    def __init__(self, entry):
        self.hash = entry[0]
        self.timestamp = entry[1] 
        self.sampleType = entry[2]
        self.sampleSize = entry[3]
        self.exploits = [e.strip(' \'\t') for e in entry[4].strip('[]').split(',')]
        self.netIdents = [e.strip(' \'\t') for e in entry[5].strip('[]').split(',')]
        self.mutexes = [e.strip(' \'\t') for e in entry[6].strip('[]').split(',')]
        self.userAgents = [b64decode(e) for e in entry[7].strip('[]').split(',')]
        self.comment = b64decode(entry[8].strip('[]'))

    def PostToCrits(self, host, user, apiKey, source):
        print('Adding ' + self.hash )
        crits = pycrits.pycrits(host, user, apiKey)
        fname = self.hash + '.'  + self.sampleType
        campaign = ''
        if self.comment != '':
            for c in CAMPAIGNS:
                if c in self.comment:
                    campResp = crits.add_campaign(c,params={'bucket_list':BUCKET_LIST, 'description': self.comment})
                    campaign = c 
        apiParams = {'md5': self.hash, 'bucket_list':BUCKET_LIST}
        if campaign != '':
            apiParams['campaign'] = campaign
        sampleResponse = crits.add_sample('metadata',source,filename=fname, params = apiParams)
        for e in self.exploits:
            if e != '':
                apiParams = {'bucket_list':BUCKET_LIST}
                if campaign != '':
                    apiParams['campaign'] = campaign
                resp = crits.add_exploit(e, e, source, params=apiParams)
                crits.add_relationship(sampleResponse['type'],sampleResponse['id'],resp['type'],resp['id'],'Created',params = {'rel_confidence':'high','rel_date':datetime.datetime.now()})
        for m in self.mutexes:
            if m != '':
                apiParams = {'bucket_list':BUCKET_LIST}
                if campaign != '':
                    apiParams['campaign'] = campaign
                resp = crits.add_indicator('mutex' ,m, source, params=apiParams)
                crits.add_relationship(sampleResponse['type'],sampleResponse['id'],resp['type'],resp['id'],'Created',params = {'rel_confidence':'high','rel_date':datetime.datetime.now()})
        for n in self.netIdents:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",n): # identifier is an IP
                apiParams = {'bucket_list':BUCKET_LIST, 'add_indicator':'True'}
                if campaign != '':
                    apiParams['campaign'] = campaign
                resp = crits.add_ip(n, 'Address - ipv4-addr', source, params=apiParams )
                crits.add_relationship(sampleResponse['type'],sampleResponse['id'],resp['type'],resp['id'],'Connected_To',params = {'rel_confidence':'high','rel_date':datetime.datetime.now()})
            elif n != '':
                apiParams = {'bucket_list':BUCKET_LIST, 'add_indicator':'True'}
                if campaign != '':
                    apiParams['campaign'] = campaign
                resp = crits.add_domain(n, source, params=apiParams)
                crits.add_relationship(sampleResponse['type'],sampleResponse['id'],resp['type'],resp['id'],'Connected_To',params = {'rel_confidence':'high','rel_date':datetime.datetime.now()})
        for ua in self.userAgents:
            if ua != '':
                apiParams = {'bucket_list':BUCKET_LIST}
                if campaign != '':
                    apiParams['campaign'] = campaign
                resp = crits.add_indicator('HTTP Request Header Fields - User-Agent' ,ua, source, params=apiParams)
                crits.add_relationship(sampleResponse['type'],sampleResponse['id'],resp['type'],resp['id'],'Sent',params = {'rel_confidence':'high','rel_date':datetime.datetime.now()})
        




		
if __name__ == '__main__':
    entries = []
    
    inputFile = open(FILENAME)
    for line in inputFile.readlines():
        entry = line.split('|')
        entries.append(DataEntry(entry))

    for e in entries:
        e.PostToCrits(HOST,USER_NAME,API_KEY, SOURCE)


		

	
