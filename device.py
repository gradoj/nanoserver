import os
import config
if os.__name__ == 'os':
    from json import loads, dumps
else:
    from ujson import loads, dumps

try:
    f = open('devinfo.json', 'r')
    devinfo = loads(f.read())
except:
    devinfo={}

try:
    f = open('joininfo.json', 'r')
    joininfo = loads(f.read())
except:
    joininfo = {}

def getDevAddr(deveui):
    global joininfo
    try:
        devaddr = int(joininfo[str(deveui)]['devaddr'])
    except KeyError:
        # deveui not found so generate a new devaddr and add to joinInfo
        for devaddr in range(config.DEV_EUI, config.DEV_EUI+0x100):
            if devaddr not in joininfo.keys():
                # found a new useable devaddr
                joininfo[str(deveui)] = {'devaddr':devaddr}
                break
    return devaddr

def getDevEui(devaddr):
    global joininfo
    for de, da in joininfo.items():
        if da == devaddr:
            return de
    return 0

def commitNV():
    global joininfo, devinfo
    f=open('devinfo.json', 'w')
    f.write(dumps(devinfo))
    f.close()    
    f=open('joininfo.json', 'w')
    f.write(dumps(joininfo))
    f.close()
    
class Device():
    def __init__(self, devaddr):
        global devinfo
        self.devaddr = str(devaddr)
        try:
            d = devinfo[self.devaddr]
        except KeyError:
            # add a new device
            devinfo[str(devaddr)] = {'deveui':getDevEui(devaddr),
                                        'appkey':config.APP_KEY,
                                        'appeui':0x0,
                                        'netid':0,
                                        'appskey':0,
                                        'nwkskey':0,
                                        'appnonce':0,
                                        'fcntup':0,
                                        'fcntdown':0,
                                        'devnonce':0}
            d = devinfo[str(devaddr)]
       
        self.appkey = (d['appkey'])
        self.appeui = (d['appeui'])
        self.netid = (d['netid'])
        self.deveui = (d['deveui'])
        self.appskey = (d['appskey'])
        self.nwkskey = (d['nwkskey'])
        self.appnonce = (d['appnonce'])
        self.fcntup = (d['fcntup'])
        self.fcntdown = (d['fcntdown'])
        self.devnonce = (d['devnonce'])
    def commit(self):
        global devinfo
        devaddr = str(self.devaddr)
        devinfo[(devaddr)]['appkey'] = int(self.appkey)
        devinfo[devaddr]['appeui'] = (self.appeui)
        devinfo[devaddr]['netid'] = (self.netid)
        devinfo[devaddr]['deveui'] = (self.deveui)
        devinfo[devaddr]['appskey'] = int(self.appskey)
        devinfo[devaddr]['nwkskey'] = int(self.nwkskey)
        devinfo[devaddr]['appnonce'] = int(self.appnonce)
        devinfo[devaddr]['fcntup'] = int(self.fcntup)
        devinfo[devaddr]['fcntdown'] = int(self.fcntdown)
        devinfo[devaddr]['devnonce'] = int(self.devnonce)
