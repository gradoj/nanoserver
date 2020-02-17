import os
import time
if os.__name__ == 'os':
    import socket

if os.__name__ == 'os':
    from struct import pack,unpack
else:
    from ustruct import pack,unpack
    
if os.__name__ == 'os':
    from json import loads, dumps
else:
    from ujson import loads, dumps
    
from base64 import b64encode, b64decode

if os.__name__ == 'os':
    from Crypto.Cipher import AES
    #from Crypto.Hash import CMAC
else:
    from crypto import AES
from cmac import CMAC


try:
    from ubinascii import hexlify, unhexlify
except:
    from binascii import hexlify, unhexlify

from math import ceil
import device

if os.__name__ == 'os':
    def const(num):
        return num

"""GWMP Identifiers"""
PUSH_DATA = const(0)
PUSH_ACK = const(1)
PULL_DATA = const(2)
PULL_RESP = const(3)
PULL_ACK = const(4)
TX_ACK = const(5)
"""MAC Message Types"""
JOIN_REQUEST = const(0)
JOIN_ACCEPT = const(1)
UN_DATA_UP = const(2)
UN_DATA_DOWN = const(3)
CO_DATA_UP = const(4)
CO_DATA_DOWN = const(5)
PROPRIETARY = const(7)

"""MAC Commands"""
LINKCHECKREQ = const(2)
LINKCHECKANS = const(2)
LINKADRREQ = const(3)
LINKADRANS = const(3)
DUTYCYCLEREQ = const(4)
DUTYCYCLEANS = const(4)
RXPARAMSETUPREQ = const(5)
RXPARAMSETUPANS = const(5)
DEVSTATUSREQ = const(6)
DEVSTATUSANS = const(6)
NEWCHANNELREQ = const(7)
NEWCHANNELANS = const(7)
RXTIMINGSETUPREQ = const(8)
RXTIMINGSETUPANS = const(8)

"""Major version of data message (Major bit field)"""
LORAWAN_R1 = const(0)

msg_out = 0
remote = ()        
tmst = 0


def localPush(packet):
    '''Function to be called from nanoserver to bypass the udp
        and push upstream data
    '''
    #print('packet', packet.encode('utf8'))
    #now = time.ticks_ms()
    datagramReceived(packet, 0,0)    
    #print('process datagram received time in ms', time.ticks_ms()-now)
def localPull():
    '''Function to be called to pull downstream messages
    '''
    global msg_out
    msg = msg_out
    msg_out = ''
    #print('msg type', type(msg))
    return msg

def commitNV():
    device.commitNV()

def inboundAppMessage(devaddr, appdata, token, acknowledge=False):
    """Sends inbound data from the application interface to the device
    
    Args:
        devaddr (int): 32 bit device address (DevAddr)
        appdata (str): packed application data
        acknowledge (bool): Acknowledged message
    """

    # Retrieve the active device
    #device = yield self._getActiveDevice(devaddr)
    #if device is None:
    #    log.error("Cannot send to unregistered device address {devaddr}",
    #             devaddr=devaddrString(devaddr))
    #    returnValue(None)

    # Check the device is enabled
    #if not device.enabled:
    #    log.error("Inbound application message for disabled device "
    #             "{deveui}", deveui=euiString(device.deveui))
    #    returnValue(None)
        
    # Get the associated application
    #app = yield Application.find(where=['appeui = ?', device.appeui], limit=1)
    #if app is None:
    #    log.error("Inbound application message for {deveui} - "
    #        "AppEUI {appeui} does not match any configured applications.",
    #        deveui=euiString(device.deveui), appeui=device.appeui)
    #    returnValue(None)
    
    # Find the gateway
    #gateway = self.lora.gateway(device.gw_addr)
    #if gateway is None:
    #    log.error("Could not find gateway for inbound message to "
    #             "{devaddr}.", devaddr=devaddrString(device.devaddr))
    #    returnValue(None)


    #fcntdown = device.fcntdown + 1
            
    # Piggyback any queued MAC messages in fopts 
    #fopts = ''
    #device.rx = self.band.rxparams((device.tx_chan, device.tx_datr), join=False)
    #if self.config.macqueueing:
        # Get all of this device's queued commands: this returns a list of tuples (index, command)
    #    commands = [(i,c[2]) for i,c in enumerate(self.commands) if device.deveui == c[1]]
    #    for (index, command) in commands:
            # Check if we can accommodate the command. If so, encode and remove from the queue
    #        if self.band.checkAppPayloadLen(device.rx[1]['datr'], len(fopts) + len(appdata)):
    #            fopts += command.encode()
    #            del self.commands[index]
    #        else:
    #            break
    
    
    #global nwkskey
    #global appskey
    # Increment fcntdown
    #global fcntdown
    global remote
    global tmst

    #now = time.ticks_ms()
    dev = device.Device(str(devaddr))
    
    dev.fcntdown = dev.fcntdown + 1
    dev.commit()
    adrenable = False
    fopts = ''
    fport = ''#1
    #print('lookup device info time in ms', time.ticks_ms()-now)

    #print('appdata', appdata)
    #print('devaddr',hexlify(int.to_bytes(devaddr,4,'big')))
    #print('fcntdown',fcntdown)
    
    # Create the downlink message, encrypt with AppSKey and encode
    #now = time.ticks_ms()
    response = MACDataDownlinkMessage(devaddr,
                                      dev.nwkskey,
                                      dev.fcntdown,
                                      adrenable,
                                      fopts, '',appdata,#int(fport), appdata,
                                      acknowledge=acknowledge)
    response.encrypt(dev.appskey)
    data = response.encode()

    #print('create mac downlink message time in ms', time.ticks_ms()-now)
    #now =time.ticks_ms()
    #print('dataout',hexlify(data))
    # Create Txpk objects
    txpk = txpkResponse(data, itmst=int(tmst),
                              join=False,
                              immediate=False)
    request = GatewayMessage(gatewayEUI=0x0, token=token,remote=remote)
                                        
    #print('create gateway message time in ms', time.ticks_ms()-now)
    # Save the frame count down
    #device.update(fcntdown=fcntdown)
    #print('Data Out', txpk[1])


    '''for m, v in txpk[1].__dict__.items():
            try:
                for attr, value in v.__dict__.items():
                    print('    '+attr, value)
            except:
                print(m, v)
                continue
    '''
    
    # Send RX1 window message
    sendPullResponse(remote,request, txpk[1])
    # If Class A, send the RX2 window message
    #sendPullResponse(remote,request, txpk[2])


def scheduleDownlinkTime(tmst, offset):
    """Calculate the timestamp for downlink transmission
    
    Args:
        tmst (int): Gateway time counter of the received frame
        offset (int): Number of seconds to add to tmst
    
    Returns:
        int: scheduled value of gateway time counter
    """
    #print('tmst offset', tmst, offset)
    sts = tmst + int(offset * 1000000)
    # Check we have not wrapped around the 2^32 counter
    if sts > 4294967295:
        sts -= 4294967295
    #print('sts', sts)
    return sts


def sendPullResponse(remote, request, txpk):
    """"Send a PULL_RESP message to a gateway.
    
    The PULL_RESP message transports its payload, a JSON object,
    from the LoRa network server to the LoRa gateway. The length
    of a PULL_RESP message shall not exceed 1000 octets.
    
    Args:
        request (GatewayMessage): The decoded Pull Request
        txpk (Txpk): The txpk to be transported
    """
    # Create a new PULL_RESP message. We must send to the
    # gateway's PULL_DATA port.
    host = request.remote[0]
    #gateway = self.gateway(host)
    #if gateway is None:
    #    log.error("Pull Reponse - no known gateway for {host}",
    #              host=host)
    #    return
    #if gateway.port == None:
    #    log.error("Pull Reponse - no known port for gateway {host}",
    #              host=host)
    #    return
    
    remote = (remote[0], remote[1])
    #print('tmstN', txpk.tmst)
    #print('token', request.token)
    m = GatewayMessage(version=request.version, token=request.token,
                identifier=PULL_RESP, gatewayEUI=0x0,
                remote=remote, ptype='txpk', txpk=txpk)
    #print("Sending PULL_RESP message to %s:%d" % remote)
    #mstring=str(m.encode()).encode()
    #print('MSTRING',hexlify(mstring),mstring)
    #print('PACKET',m.encode())

    # need to get this data back to nanoserver

    if os.__name__ == 'os':
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_socket.sendto(m.encode(), remote)
    else:
        global msg_out
        msg_out = m.encode()
        #localPull()
    
    
def zfill(s, width):
    return '{:0>{w}}'.format(s, w=width)


    
def intPackBytes(n, length, endian='big'):
    """Convert an integer to a packed binary string representation.
    
    Args:
        n (int: Integer to convert
        length (int): converted string length
        endian (st)r): endian type: 'big' or 'little'
    
    Returns:
        A packed binary string.
    """
    
    if length == 0:
        return ''
    h = '%x' % n
    #s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    #s = bytearray.fromhex(('0'*(len(h) % 2) + h).zfill(length*2))
    #s = unhexlify(('0'*(len(h) % 2) + h).zfill(length*2))
    s = unhexlify(zfill(('0'*(len(h) % 2) + h), length*2))
    if endian == 'big':
        return s
    else:
        #return s[::-1]
        
        return int.to_bytes(n, length, 'little')
    return n

def intUnpackBytes(data, endian='big'):
    """Convert an packed binary string representation to an integer.
    
    Args:
        data (str): packed binary data
        endian (str): endian type: 'big' or 'little'
    
    Returns:
        An integer.
    """
    if isinstance(data, str):
        data = bytearray(data)
    if endian == 'big':
        data = reversed(data)
    num = 0
    for offset, byte in enumerate(data):
        num += byte << (offset * 8)
    return num


class Txpk(object):
    """A Gateway Txpk (downstream) JSON object.
    
    The root JSON object shall contain zero or more txpk
    objects. See Gateway to Server Interface Definition
    Section 6.2.4.
    
    Attributes:
        imme (bool): If true, the gateway is commanded to
                     transmit the frame immediately 
        tmst (int): If "imme" is not true and "tmst" is present,
                    the gateway is commanded to transmit the frame
                    when its internal timestamp counter equals the
                    value of "tmst".
        time (str): UTC time. The precision is one microsecond. The
                    format is ISO 8601 compact format. If "imme" is
                    false or not present and "tmst" is not present,
                    the gateway is commanded to transmit the frame at
                    this time.
        freq (float): The centre frequency on when the frame is to
                    be transmitted in units of MHz.
        rfch (int): The antenna on which the gateway is commanded
                    to transmit the frame.
        powe (int): The output power which what the gateway is
                    commanded to transmit the frame.
        modu (str): Modulation technique - "LORA" or "FSK".
        datr (str): Datarate identifier. For Lora, comprised of
                    "SFnBWm where n is the spreading factor and
                    m is the frame's bandwidth in kHz.
        codr (str): ECC code rate as "k/n" where k is carried
                    bits and n is total bits received.
        ipol (bool): If true, commands gateway to invert the
                    polarity of the transmitted bits. LoRa Server sets
                    value to true when "modu" equals "LORA", otherwise
                    the value is omitted.
        size (int): Number of octets in the received frame.
        data (str): Frame payload encoded in Base64. Padding characters
                    shall not be not added
        ncrc (bool): If not false, disable physical layer CRC generation
                    by the transmitter.
    """
    
    def __init__(self, imme=False, tmst=None, time=None, freq=None,
                 rfch=None, powe=None, modu=None, datr=None, codr=None,
                 ipol=None, size=None, data=None, ncrc=None):
        """Txpk initialisation method.
        
        """
        self.imme = imme
        self.tmst = tmst 
        self.time = time
        self.freq = freq
        self.rfch = rfch
        self.powe = powe
        self.modu = modu
        self.datr = datr
        self.codr = codr
        self.ipol = ipol  
        self.size = size
        self.data = data
        self.ncrc = ncrc
        self.keys = ['imme', 'tmst', 'time', 'freq', 'rfch',
                    'powe', 'modu', 'datr', 'codr', 'ipol',
                    'size', 'data', 'ncrc']
        # Base64 encode data, no padding
        if self.data is not None:
            self.size = len(self.data)
            self.data = b64encode(self.data)
            # Remove padding
            if self.data[-2:] == '==':
                self.data = self.data[:-2]
            elif self.data[-1:] == '=':
                self.data = self.data[:-1]
        else:
            self.size = 0
    
    def encode(self):
        """Create a JSON string from Txpk object
        
        """
        # Create dict from attributes. Maintain added order
        #jd = {'txpk': collections.OrderedDict()}
        jd = {'txpk': {}}
        #jd = collections.OrderedDict()
        #jd['txpk']=collections.OrderedDict()
        for key in self.keys:
            val = getattr(self, key)

            if val is not None:
                if key == 'data':
                    jd['txpk'][key] = val.decode('utf-8')
                else:
                    jd['txpk'][key] = val
            #print('key',key)
            #print('valtype',type(val),val)                
        
        #print(jd)
        
        #return dumps(jd, separator(',', ':'))
        return dumps(jd)

def txpkResponse(data, itmst=0, join=False, immediate=False):
    """Create Txpk object
    
    Args:
        device (Device): Target device
        data (str): Data payload
        gateway (Gateway): Target gateway
        itmst (int): Gateway time counter of the received frame
        immediate (bool): Immediate transmission if true, otherwise
                          scheduled
    
    Returns:
        Dict of txpk objects indexed as txpk[1], txpk[2]
    """
    if join:
        rxdelay = 4.98
    else:
        rxdelay = 0.98
    
    txpk = {}
    for i in range(0,2):
        if immediate:
            txpk[i+1] = Txpk(imme=True, freq=923.3,
                           rfch=0, powe=20,
                           modu="LORA", datr='SF10BW500',
                           codr="4/5", ipol=True, ncrc=True, data=data)
        else:
            #print('TimeStamp:', itmst)
            tmst = scheduleDownlinkTime(itmst, rxdelay+i)
            #print('Scheduled TimeStamp', tmst)
            txpk[i+1] = Txpk(tmst=tmst, freq=923.3,
                           rfch=0, powe=20,
                           modu="LORA", datr="SF10BW500",
                           codr="4/5", ipol=True, ncrc=True, data=data)
    return txpk



def intUnpackBytes(data, endian='big'):
    """Convert an packed binary string representation to an integer.
    
    Args:
        data (str): packed binary data
        endian (str): endian type: 'big' or 'little'
    
    Returns:
        An integer.
    """
    if isinstance(data, str):
        data = bytearray(data)
    if endian == 'big':
        data = reversed(data)
    num = 0
    for offset, byte in enumerate(data):
        num += byte << (offset * 8)
    return num

def createSessionKey(pre, appkey, appnonce, netid, msg):
    """Create a NwkSKey or AppSKey
    
    Creates the session keys NwkSKey and AppSKey specific for
    an end-device to encrypt and verify network communication
    and application data.
    
    Args:
        pre (int): 0x01 ofr NwkSKey, 0x02 for AppSKey
        app (Application): The applicaiton object.
        msg (JoinRequestMessage): The MAC Join Request message.
    
    Returns:
        int: 128 bit session key
    """
    # Session key data: 0x0n | appnonce | netid | devnonce | pad (16)
    data = pack('B', pre) + \
           intPackBytes(appnonce, 3, endian='little') + \
           intPackBytes(netid, 3, endian='little') + \
           pack('<H', msg.devnonce) + intPackBytes(0, 7)
    aesdata = aesEncrypt(intPackBytes(appkey, 16), data)
    key = intUnpackBytes(aesdata)
    return key



def processJoinRequest(message):
    """Process an OTA Join Request message from a LoraWAN device
    
    This method checks the message devnonce and integrity code (MIC).
    If the devnonce has not been seen before, and the MIC is valid,
    we have a valid join request, and we can create the session
    keys and assign an OTA device address.
    
    Args:
        message (JoinRequestMessage): The join request message object
        app (Application): The requested application object
        device (Device): The requesting device object
        
    Returns:
        True on success, False otherwise.
    """
    # Perform devnonce check
    #if not device.checkDevNonce(message):
    #    log.info("Join request message from {deveui} failed message "
    #            "devnonce check.", deveui=euiString(message.deveui))
    #    returnValue(False)
        
    # Perform message integrity check.

    # Given deveui lookup or generate the devaddr
    devaddr = device.getDevAddr(message.deveui)

    dev = device.Device(devaddr)
    appkey = dev.appkey

    if not message.checkMIC(appkey):
        print("Failed message integrity check deviceeui", message.deveui)
        return(False)
    
    dev.netid = 0x000000 # not sure where this originates
    dev.devaddr = 0x60000000 # need to generate
    dev.appnonce = 0x000013 # need to generate
    dev.appeui = message.appeui
    dev.deveui = message.deveui
    dev.netid = message.devnonce
    
    
    # Assign DevEUI, NwkSkey and AppSKey.
    # def createSessionKey(pre, appkey, appnonce, netid, msg):
    #appeui = app.appeui
    
    dev.nwkskey = createSessionKey(1, dev.appkey, dev.appnonce, dev.netid, message)
    dev.appskey = createSessionKey(2, dev.appkey, dev.appnonce, dev.netid, message)
    #nwkskey = devinfo.nwkskey
    #appskey = devinfo.appskey

    print('Network Session Key:', hexlify(intPackBytes(dev.nwkskey,16)))
    print('App Session Key:', hexlify(intPackBytes(dev.appskey,16)))

    dev.commit()
    #devaddr = 
    # If required, obtain a OTA devaddr for the device
    #if device.devaddr is None:
    #    device.devaddr = yield self._getFreeOTAAddress()
        
    return True

def sendJoinResponse(request, rxpk, gateway, deveui):
    """Send a join response message
    
    Called if a join response message is to be sent.
    
    Args:
        request: request (GatewayMessage): Received gateway message object
        app (Application): The requested application object
        device (Device): The requesting device object
    """

    #appkey = 0xCD0D7B3BCB116F5B6A05E48E78CC949B
    tx_chan = 0
    tx_datr = 'SF10BW500'
    rx1droffset = 0

    # Given deveui lookup or generate the devaddr
    devaddr = device.getDevAddr(deveui)
    dev = device.Device(devaddr)
    
    
    # Get receive window parameters and
    # set dlsettings field
    #rx =  {1: 5, 2: 6} #self.band.rxparams((tx_chan, tx_datr))
    dlsettings = 8#0 | rx1droffset << 4 | 0 #rx[2]['index']
    
    # Create the Join Response message
    #log.info("Sending join response for devaddr {devaddr}",
    #         devaddr=devaddrString(device.devaddr))
    response = JoinAcceptMessage(dev.appkey, dev.appnonce,
                                 dev.netid, devaddr,
                                 dlsettings, 1)#rx[1]['delay'])
    data = response.encode()
    
    txpk = txpkResponse(data, rxpk.tmst, join=True)
    #print('txpk[1]',txpk[1].tmst)
    #print('txpk[2]',txpk[2].tmst)
    #print('gateway',gateway)
    #txpk[1].tmst=int(txpk[1].tmst)
    #txpk[1].freq=float(txpk[1].freq)
    #txpk[2].tmst=int(txpk[2].tmst)
    # Send the RX1 window messages
    sendPullResponse(gateway, request, txpk[1])
    # Send the RX2 window message
    #sendPullResponse(gateway, request, txpk[2])



def aesEncrypt(key, data, mode=None):
    """AES encryption function
    
    Args:
        key (str): packed 128 bit key
        data (str): packed plain text data
        mode (str): Optional mode specification (CMAC)
        
    Returns:
        Packed encrypted data string
    """
    dataorder='big'
    keyorder='big'
    
    if mode == 'CMAC':
        cipher = CMAC()
        
        key=(int.from_bytes(key[0:4], 'big'),
             int.from_bytes(key[4:8], 'big'),
             int.from_bytes(key[8:12], 'big'),
             int.from_bytes(key[12:16], 'big'))
        #print(hexlify(key[0].to_bytes(4,byteorder='little')))
        #print(hexlify(key[1].to_bytes(4,byteorder='little')))
        #print(hexlify(key[2].to_bytes(4,byteorder='little')))
        #print(hexlify(key[3].to_bytes(4,byteorder='little')))
        if len(data) <= 16:
            length=len(data)*8
            data=data+bytearray((16-len(data)))
            data=[(int.from_bytes(data[0:4], 'big'),
                   int.from_bytes(data[4:8], 'big'),
                   int.from_bytes(data[8:12], 'big'),
                   int.from_bytes(data[12:16], 'big'))]
                  
        elif len(data) > 16:
            length = (len(data)-16)*8
            data=data+bytearray((32-len(data)))
            data=[(int.from_bytes(data[0:4], 'big'),
                   int.from_bytes(data[4:8], 'big'),
                   int.from_bytes(data[8:12], 'big'),
                   int.from_bytes(data[12:16], 'big')),
                  (int.from_bytes(data[16:20], 'big'),
                   int.from_bytes(data[20:24], 'big'),
                   int.from_bytes(data[24:28], 'big'),
                   int.from_bytes(data[28:32], 'big'))]          
        else:
            print('Data greater than 32 bytes')

        #print('Length', length)
        mic=cipher.cmac(key, data, length)
        
        # Create AES cipher using key argument, and encrypt data
        '''cipher = CMAC.new(key, ciphermod=AES)
        cipher.update(data)
        mic=cipher.hexdigest()
        '''
        #print('MIC',hexlify(bytearray.fromhex(mic)))

        #print(hexlify(mic[0].to_bytes(4,byteorder='little')))
        #print(hexlify(mic[1].to_bytes(4,byteorder='little')))
        #print(hexlify(mic[2].to_bytes(4,byteorder='little')))
        #print(hexlify(mic[3].to_bytes(4,byteorder='little')))
        
        mic = mic[0].to_bytes(4, 'big')
        return mic# bytearray.fromhex(mic[0])
        #return bytearray.fromhex(mic)
    else: #if mode == None:
        try: 
            cipher = AES.new(key,AES.MODE_ECB)
        except:
            cipher = AES(key,AES.MODE_ECB)
        return cipher.encrypt(data)
    
def aesDecrypt(key, data):
    """AES decryption fucnction
    
    Args:
        key (str): packed 128 bit key
        data (str): packed encrypted data
        
    Returns:
        Packed decrypted data string
    """
    if os.__name__ == 'os':
        cipher = AES.new(key,AES.MODE_ECB)
    else:
        cipher = AES(key,AES.MODE_ECB)
    return cipher.decrypt(data)


class MACMessage(object):
    """A LoRa MAC message.
    
    """        
    @classmethod
    def decode(cls, data):
        """Decode the message type.
        
        Args:
            data (str): UDP packet data.
        
        Returns:
            MACJoinMessage or MACDataMessage on success, None otherwise.
            
        """
        # Message (PHYPayload) must be at least 1 byte
        if len(data) < 1:
            raise DecodeError()
        # Decode the MAC Header
        mhdr = MACHeader.decode(data[0])
        # Decode the Message
        if mhdr.mtype == JOIN_REQUEST:
            return JoinRequestMessage.decode(mhdr, data)
        elif mhdr.mtype == UN_DATA_UP or mhdr.mtype == CO_DATA_UP:
            return MACDataUplinkMessage.decode(mhdr, data)
        else:
            return None

    def isJoinRequest(self):
        """Check if message is a Join Request.
        
        Returns:
            True on match, otherwise False.
        
        """
        return self.mhdr.mtype == JOIN_REQUEST
    
    def isMACCommand(self):
        """Check if message is a MAC Command.
        
        Returns:
            True on match, otherwise False.
        
        """
        return self.payload.fport == 0

    def hasMACCommands(self):
        """Check if the message has piggybacked MAC commands.
        
        Returns:
            True on match, otherwise False.
        """
        return hasattr(self, 'commands') and len(self.commands) > 0
    
    def isUnconfirmedDataUp(self):
        """Check if message is Unconfirmed Data Up.
        
        Returns:
            True on match, otherwise False.
        
        """
        return self.mhdr.mtype == UN_DATA_UP
    
    def isConfirmedDataUp(self):
        """Check if message is Confirmed Data Up.
        
        Returns:
            True on match, otherwise False.
        
        """
        return self.mhdr.mtype == CO_DATA_UP


class JoinRequestMessage(MACMessage):
    """A LoRa Join Request message.
    
    The join request message contains the AppEUI
    and DevEUI of the end device, followed by a
    Nonce of 2 octets (devnonce).
    
    Attributes:
        mhdr (MACHeader): MAC header object.
        appeui (int): Application identifer.
        deveui (int): Global end device EUI.
        devnonce (int): Device nonce.
        mic (int): Message integrity code.
    
    """
        
    def __init__(self, mhdr, appeui, deveui, devnonce, mic):
        """JoinRequestMessage initialisation method.
        
        """
        self.mhdr = mhdr
        self.appeui = appeui
        self.deveui = deveui
        self.devnonce = devnonce
        self.mic = mic

    @classmethod
    def decode(cls, mhdr, data):
        """Create a MACJoinRequestMessage object from binary representation.
        
        Args:
            mhdr (MACHeader): MAC header object.
            data (str): UDP packet data.
        
        Returns:
            JoinRequestMessage object on success, None otherwise.
            
        """
        # Message (PHYPayload) must be 23 bytes
        if len(data) != 23:
            raise DecodeError()
        (appeui, deveui, devnonce, mic) = unpack('<QQHL', data[1:])
        m = JoinRequestMessage(mhdr, appeui, deveui, devnonce, mic)

        '''for attr, value in m.__dict__.items():
            print(attr, value)
        '''
        return m
    
    def checkMIC(self, appkey):
        """Verify the message integrity code (MIC).
        
        The MIC is calculated over the binary join request message
        excluding the MIC. Use the first four bytes of AES CMAC
        encrypted data, convert from little endian data to int.
        
        Args:
            appkey (int): The application key.
            
        Returns:
            True on success, False otherwise.
        """
        data = self.mhdr.encode() + pack('<QQH', self.appeui,
                                                self.deveui, self.devnonce)
        aesdata = aesEncrypt(intPackBytes(appkey, 16), data, mode='CMAC')
        mic = unpack('<L', aesdata[:4])[0]
        print('Message MIC', hexlify(self.mic.to_bytes(4,'little')))
        print('Calculated MIC', hexlify(mic.to_bytes(4,'little')))
        return mic == self.mic

class JoinAcceptMessage(MACMessage):
    """A LoRa Join Accept message.
    
    The join accept message contains an
    application nonce of 3 octets (appnonce),
    3 octet a network identifier (netid), a 4
    octet device address (devaddr), a 1 octet
    delay between tx and rx (rxdelay) and
    an optional list of channel frequencies
    (cflist).
    
    Attributes:
        mhdr (MACHeader): MAC header
        appkey (int): Application key
        appnonce (int): Application nonce
        netid (int): Network identifer
        devaddr (int): Device address
        dlsettings (int): DLsettings field
        rxdelay (int): Delay between tx and rx
        cflist (list): List of channel frequencies
        mic (int): Message integrity code
    """
        
    def __init__(self, appkey, appnonce, netid, devaddr, dlsettings,
                 rxdelay, cflist=[]):
        """JoinAcceptMessage initialisation method.
        
        """
        self.mhdr = MACHeader(JOIN_ACCEPT, LORAWAN_R1)
        self.appkey = appkey
        self.appnonce = appnonce
        self.netid = netid
        self.devaddr = devaddr
        self.dlsettings = dlsettings
        self.rxdelay = rxdelay
        self.cflist = cflist
        self.mic = None

    def encode(self):
        """Create a binary representation of JoinAcceptMessage object.
        
        Returns:
            Packed JoinAccept message.
        """
        # Encoding Join-accept:
        # MAC Header
        # 3 bytes appnonce
        # 3 bytes netid 
        # 4 bytes devaddr
        # 1 byte dlsettings
        # 1 byte rxdelay
        # Optional cflist
        
        # Create the message
        header = self.mhdr.encode()
        msg =  intPackBytes(self.appnonce, 3, endian='little') + \
               intPackBytes(self.netid, 3, endian='little') + \
               pack('<L', self.devaddr) + \
               pack('B', self.dlsettings) + \
               pack('B', self.rxdelay) #+ \
               #intPackBytes(0xFFFFFFFFFFFFFFFFFF,9) + \
               #intPackBytes(0x00000000000001,7)
        # CFList is not used in a Join Accept message for US/AU bands
        #if self.cflist:
        #    pass
        # Create the MIC over the entire message
        self.mic = aesEncrypt(intPackBytes(self.appkey, 16), header + msg,
                              mode='CMAC')[0:4]

        #print('msg',msg)
        #print('mic',self.mic)
        msg += self.mic

        #print('****', hexlify(header+msg))
        # Add the header and encrypt the message using AES-128 decrypt
        # this is done so endpoint only needs to implement Encrypt
        data = header + aesDecrypt(intPackBytes(self.appkey, 16), msg)
        #data = header + aesEncrypt(intPackBytes(self.appkey, 16), msg)
        return data


class FrameHeader(object):
    """MAC Payload Frame Header.
    
    The frame header contains the short device address
    of the end device (devaddr), and frame control octet
    (fctrl), 2 octet frame counter (fcnt) and up to 15
    octets used to transport MAC commands (fopts).
    
    Attributes:
        devaddr (str): Device address.
        adr (int): ADR bit
        adrackreq (int): ADR acknowledgment request bit
        ack (int): Acknowledgment bit.
        foptslen (int): Frame options length field: Length of the 
                        fopts field included in the frame.
        fcnt (int): Frame counter.
        fopts (list): Frame options.
        fdir (str): Frame direction (uplink or downlink).
        length (int): Length of the frameheader
        
    """
    
    def __init__(self, devaddr, adr, adrackreq, ack,
                 foptslen, fcnt, fopts, fpending=0, fdir='up'):
        """FrameHeader initialisation method.
        
        """
        self.devaddr = devaddr
        self.adr = adr
        self.adrackreq = adrackreq
        self.ack = ack
        self.fpending = fpending
        self.foptslen = foptslen
        self.fcnt = fcnt
        self.fopts = fopts
        self.fdir = fdir
        self.length = self.foptslen + 7

    @classmethod
    def decode(cls, data):
        """Create a FrameHeader object from binary representation.
        
        Args:
            data (str): MACPayload packet data
        
        Returns:
            FrameHeader object on success, None otherwise.
            
        """
        # FrameHeader must be at least 7 bytes
        if len(data) < 7:
            raise DecodeError()
        (devaddr, fctrl, fcnt) = unpack('<LBH', data[:7])
        # Decode fctrl field
        # ADR is bit 7
        adr = (fctrl & 128) >> 7
        # ADRackreq is bit 6
        adrackreq = (fctrl & 64) >> 6
        # ACK is bit 5
        ack = (fctrl & 32) >> 5
        # Foptslen = bits [3:0]
        foptslen = fctrl & 15
        fopts = data[7:7+foptslen]
        
        fheader = FrameHeader(devaddr, adr, adrackreq, ack,
                 foptslen, fcnt, fopts)
        return fheader
    
    def encode(self):
        """Create a binary representation of FrameHeader object.
        
        Returns:
            String of packed data.
        
        """
        fctrl = 0 | (self.adr << 7) | (self.adrackreq << 6) \
                  | (self.ack << 5) | (self.fpending << 4) \
                  | (self.foptslen & 15)

        #print('fopts',type(self.fopts))
        if self.fopts == '':
            data = pack('<LBH', self.devaddr, fctrl, self.fcnt)
        else:
            data = pack('<LBH', self.devaddr, fctrl, self.fcnt) + bytes(self.fopts)
        return data

class MACPayload(object):
    """LoRa MAC payload.
    
    Contains the frame header (fhdr), followed by an
    optional port field (fport) and an optional frame
    payload field (frmpayload).
    
    Attributes:
        fhdr (FrameHeader): Frame header.
        fport (int): Frame port
        frmpayload (str): Frame payload.
    """
    
    def __init__(self, fhdr, fport, frmpayload):
        """MACPayload initialisation method.
        
        """
        self.fhdr = fhdr
        self.fport = fport
        self.frmpayload = frmpayload

    @classmethod
    def decode(cls, data):
        """Create a MACPayload object from binary representation.
        
        Args:
            data (str): MACPayload packet data.
        
        Returns:
            MACPayload object on success, None otherwise.
        """
        # Payload must be at a minimum 1 byte, + 7 byte fhdr
        dlen = len(data)
        # TODO: check region specific length
        if dlen < 8:
            raise DecodeError()
        # Decode the frame header
        fhdr = FrameHeader.decode(data)
        # Check and decode fport
        fport = None
        frmpayload = None
        if dlen > fhdr.length:
            fport = unpack('B', bytes([data[fhdr.length]]))[0]
        # Decode frmpayload
        if dlen > fhdr.length + 1:
            frmpayload = data[fhdr.length+1:]
        p = MACPayload(fhdr, fport, frmpayload)
        return p

    def encode(self):
        """Create a binary representation of MACPayload object.
        
        Returns:
            String of packed data.
        
        """
        #print('fhdrt',type(self.fhdr.encode()))
        #print('frmpayloadt',type(self.frmpayload),self.frmpayload)
        

        
        if self.frmpayload == '':
            data = self.fhdr.encode() #+ pack('B', self.fport)
        else:
            data = self.fhdr.encode() + pack('B', self.fport) + \
                self.frmpayload
        return data


class MACDataMessage(MACMessage):
    """A LoRa MAC Data Message base class.
    
    LoRa uplink and downlink data messages carry a PHY
    payload consiting of a single octet header (mhdr),
    a MAC payload (macpayload) and a 4-octet message
    integrity code (mic).
    
    Attributes:
        mhdr (MACHeader): MAC header.
        payload (MACPayload): MAC payload
        mic (str): Message integrity code.
    
    """
    def __init__(self):
        self.mhdr = None
        self.payload = None
        self.mic = None
        
    def encrypt(self, key, dir):
        """Encrypt FRMPayload
        
        The algorithm defines a sequence of Blocks Ai for i = 1..k with k =
        ceil(len(pld) / 16):
        Ai: [0x01 | 4 x 0x00 | dir | devaddr | Fcntup or FcntDown | 0x00 | i]
        
        dir is 0 for uplink and 1 for downlink
        
        The blocks Ai are encrypted to get a sequence S of blocks Si:
          Si = aes128_encrypt(K, Ai) for i = 1..k
          
        Encryption and decryption of the payload is done by
        truncating (pld | pad16) xor S to the first len(pld) octets.
        i.e. pad pld to a 16 byte boundary, then xor with S, and
        truncate to the original length.
        
        Args:
            key (int): AES encryption key - device NwkSKey or AppSkey
            dir (int): Direction - 0 for uplink and 1 for downlink
        
        """
        print('LORA MAC PAYLOAD')
        if self.payload.frmpayload == None:
            return
        plen = len(self.payload.frmpayload)
        if plen == 0:
            return
        k = int(ceil(plen/16.0))
        # Create the concatenated block S
        S = bytearray()#''
        for i in range(k):
            # Ai: [0x01 | 4 x 0x00 | dir | devaddr | Fcntup or FcntDown | 0x00 | i]
            Ai = pack('<BLBLLBB', 1, 0, dir, self.payload.fhdr.devaddr,
                             self.payload.fhdr.fcnt, 0, i+1)
            # Si = aes128_encrypt(K, Ai) 
            S += aesEncrypt(intPackBytes(key, 16), Ai)

        # Pad frmpayload to a byte multiple of 16
        padlen = k * 16 - plen
        padded = self.payload.frmpayload + intPackBytes(0, padlen)
        
        # Unpack S and padded payload into arrays of long long ints
        ufmt = '{}Q'.format(k*2)
        s = unpack(ufmt, S)
        p = unpack(ufmt, padded)
        
        # Perform the XOR function over the data, and pack
        pld = bytearray()#''
        for i in range (len(s)):
            pld += pack('Q', s[i] ^ p[i])
            
        # Truncate the result to the original length
        self.payload.frmpayload = pld[:plen]
        
    def decrypt(self, key, dir):
        """Decrypt FRMPayload
        
        encrypt() is a symmetric function - we simply call encrypt() here
        to decrypt.
        
        """
        self.encrypt(key, dir)

class MACDataDownlinkMessage(MACDataMessage):
    """A LoRa MAC Data Uplink Message.
    
    LoRa uplink data messages carry a PHY payload
    consiting of a single octet header (mhdr),
    a MAC payload (macpayload) and a 4-octet message
    integrity code (mic).
    
    Attributes:
        confirmed (bool): True if Confirmed Data Down
        devaddr (int): Device address (DevAddr)
        key (int): Encryption key (NwkSkey or AppSKey)
        
    """
    def __init__(self, devaddr, key, fcnt, adrenable, fopts,
                 fport, frmpayload, acknowledge=False):
        """MACDataDownlinkMessage initialisation method.
        
        """
        self.devaddr = devaddr
        self.key = key
        self.mhdr = MACHeader(UN_DATA_DOWN, LORAWAN_R1)
        ack = 1 if acknowledge is True else 0
        adr = 1 if adrenable is True else 0
        try:
            foptslen = len(fopts)
        except:
            foptslen = 0
        fhdr = FrameHeader(devaddr, adr, 0, ack, foptslen, fcnt,
                           fopts, fpending=0, fdir='down')
        self.payload = MACPayload(fhdr, fport, frmpayload)
        self.mic = None
        
    def encode(self):
        """Create a binary representation of MACMessage object.
        
        Returns:
            String of packed data.
        
        """
        # Calculate the MIC.
        # The MIC is calculated as cmac = aes128_cmac(NwkSKey, B0 | msg)
        # MIC = cmac[0:3]
        # msg is defined as: MHDR | FHDR | FPort | FRMPayload
        # B0 is defined as:
        # 1 byte 0x49 | 4 bytes 0x00 | 1 byte dir=0 for uplink, 1 for downlink
        # 4 bytes devaddr | 4 bytes fcntup or fcntdown
        # 1 byte 0x00 | 1 bytes len
        msg = self.mhdr.encode() + self.payload.encode()
        B0 = pack('<BLBLLBB', int('0x49', 16), 0, 1,
                         self.devaddr, self.payload.fhdr.fcnt, 0, len(msg))
        data = B0 + msg
        # Create the MIC over the entire message
        self.mic = aesEncrypt(intPackBytes(self.key, 16), data,
                              mode='CMAC')[0:4]
        msg += self.mic

        #print('datamsg',hexlify(msg))
        return msg

    def encrypt(self, key):
        #super(MACDataDownlinkMessage, self).encrypt(key, dir=1)
        super().encrypt(key,dir=1)
        



class MACDataUplinkMessage(MACDataMessage):
    """A LoRa MAC Data Uplink Message.
    
    Subclass of MACDataMessage.
    LoRa uplink data messages carry a PHY payload
    consiting of a single octet header (mhdr),
    a MAC payload (payload) and a 4-octet message
    integrity code (mic). May optionally carry
    piggybacked MAC commands.
    
    Attributes:
        mhdr (MACHeader): MAC header
        payload (MACPayload): MAC payload object
        commands (list): List of piggybacked MAC commands
        mic (int): Message integrity code
        confirmed (bool): True if Confirmed Data Up
    
    """
    def __init__(self, mhdr, payload, commands, mic):
        self.mhdr = mhdr
        self.payload = payload
        self.commands = commands
        self.mic = mic
        self.confirmed = self.mhdr.mtype == CO_DATA_UP
    
    @classmethod
    def decode(cls, mhdr, data):
        """Create a MACMessage object from binary representation.
        
        Args:
            mhdr (MACHeader): MAC header object.
            data (str): UDP packet data.
        
        Returns:
            A MACDataUplinkMessage object.
        """
        # Message (PHYPayload) must be at least 6 bytes
        if len(data) < 6:
            raise DecodeError()
        # Decode message payload
        payload = MACPayload.decode(data[1:len(data)-4])
        
        # Decode fopts MAC Commands
        commands = []
        p = 0
        while p < payload.fhdr.foptslen:
            #ke c = MACCommand.decode(payload.fhdr.fopts[p:])
            # We have no option except to break here if we fail to decode 
            # a MAC command, as we have no way of advancing the pointer
            #if c is None:
            #    break
            #commands.append(c)
            #p += c.length
            pass
            
        # Slice the MIC
        mic = unpack('<L', data[len(data)-4:])[0]
        
        m = MACDataUplinkMessage(mhdr, payload, commands, mic)
        return m
    
    def decrypt(self, key):
        """Decrypt the MAC Data Uplink Message
        
        Args:
            key (int): AES encryption key - device NwkSKey or AppSkey
        """
        super(MACDataUplinkMessage, self).decrypt(key, dir=0)
    
    def checkMIC(self, key):
        """Check the message integrity code
        
        Args:
            key (int): NwkSkey
        
        Returns:
            True on success, False otherwise
        """

        # Calculate the MIC for this message using key
        msg = self.mhdr.encode() + self.payload.encode()
        B0 = pack('<BLBLLBB',
                         int('0x49', 16), 0, 0, self.payload.fhdr.devaddr,
                         self.payload.fhdr.fcnt, 0, len(msg))
        data = B0 + msg
        aesdata = aesEncrypt(intPackBytes(key, 16), data, mode='CMAC')
        mic = unpack('<L', aesdata[:4])[0]
        # Compare to message MIC
        return mic == self.mic

class MACHeader(object):
    """LoRa Message MAC Header.
    
    The MAC header specifies the message type (mtype)
    and according to which major version (major) of the
    frame format of the LoRaWAN layer specification used
    for encoding.
    
    Attributes:
        mtype (int): Message type.
        major (int): Major version.
        
    """

    def __init__(self, mtype, major):
        """MACHeader initialisation method.
        
        Args:
            mtype (int): Message type.
            major (int): Major version.
        
        """
        self.mtype = mtype
        self.major = major
        
    @classmethod
    def decode(cls, data):
        """Create a MACHeader object from binary representation.
        
        Args:
            data (str): UDP packet data.
        
        Returns:
            MACHeader object on success, None otherwise.
            
        """
       
        #h = unpack('B', data)[0]
        
        h = unpack('B', bytes([data]))[0]
        # Bits 7-5 define the message type
        mtype = (h & 224) >> 5
        # Bits 1-0 define the major version
        major = h & 3
        m = MACHeader(mtype, major)
        return m
    
    def encode(self):
        """Create a binary representation of MACHeader object.
        
        Returns:
            One character of data.
        
        """
        b = 0 | self.mtype << 5 | self.major
        data = pack('B', b)
        return data
    

class MACMessage(object):
    """A LoRa MAC message.
    
    """        
    @classmethod
    def decode(cls, data):
        """Decode the message type.
        
        Args:
            data (str): UDP packet data.
        
        Returns:
            MACJoinMessage or MACDataMessage on success, None otherwise.
            
        """
        # Message (PHYPayload) must be at least 1 byte
        if len(data) < 1:
            raise DecodeError()
        # Decode the MAC Header
        mhdr = MACHeader.decode(data[0])
        # Decode the Message
        if mhdr.mtype == JOIN_REQUEST:
            return JoinRequestMessage.decode(mhdr, data)
        elif mhdr.mtype == UN_DATA_UP or mhdr.mtype == CO_DATA_UP:
            return MACDataUplinkMessage.decode(mhdr, data)
        else:
            return None

    def isJoinRequest(self):
        """Check if message is a Join Request.
        
        Returns:
            True on match, otherwise False.
        
        """
        return self.mhdr.mtype == JOIN_REQUEST
    
    def isMACCommand(self):
        """Check if message is a MAC Command.
        
        Returns:
            True on match, otherwise False.
        
        """
        return self.payload.fport == 0

    def hasMACCommands(self):
        """Check if the message has piggybacked MAC commands.
        
        Returns:
            True on match, otherwise False.
        """
        return hasattr(self, 'commands') and len(self.commands) > 0
    
    def isUnconfirmedDataUp(self):
        """Check if message is Unconfirmed Data Up.
        
        Returns:
            True on match, otherwise False.
        
        """
        return self.mhdr.mtype == UN_DATA_UP
    
    def isConfirmedDataUp(self):
        """Check if message is Confirmed Data Up.
        
        Returns:
            True on match, otherwise False.
        
        """
        return self.mhdr.mtype == CO_DATA_UP

def processPushDataMessage(request, gateway):
    global tmst
    
    for rxpk in request.rxpk:
        message = MACMessage.decode(rxpk.data)
        tmst=rxpk.tmst
        
        
        if message is None:
            print('MAC message decode error')
            #print("MAC message decode error for gateway {gateway}: message "                        
            #        "timestamp {timestamp}", gateway=gateway.host,
            #        timestamp=str(rxpk.time))
            returnValue(False)
        
            # Check if thisis a duplicate message
            #if self._checkDuplicateMessage(message):
            #    returnValue(False)
        
            # Join Request
        if message.isJoinRequest():
            print('Received Join Request message')


                # Process join request
            joined=processJoinRequest(message)
            sendJoinResponse(request, rxpk, gateway, message.deveui)
            
                #joined = yield self._processJoinRequest(message, app, device)
                # Send the join response
                #self._sendJoinResponse(request, rxpk, gateway, app, device)
        elif message.isMACCommand():
            print('Received MAC Command message')
            #message.decrypt(device.nwkskey)
            #commands = [MACCommand.decode(message.payload.frmpayload)]
        # Contains piggybacked MAC command(s)
        if message.hasMACCommands():
            print('Message has MAC Commands')
            #commands = message.commands
            
            #for command in commands:
            #    if command.isLinkCheckReq():
            #        pass
                    #self._processLinkCheckReq(device, command, request, rxpk.lsnr)
            #    elif command.isLinkADRAns():
            #        pass
                #self._processLinkADRAns(device, command)
                # TODO: add other MAC commands
            
        # Process application data message
        if message.isUnconfirmedDataUp() or message.isConfirmedDataUp():
            if message.isConfirmedDataUp():
                print('Confirmed Data Uplink')
            else:
                print('Unconfirmed Data Uplink')
            # Find the app
            #app = yield Application.find(where=['appeui = ?', device.appeui], limit=1)
            #if app is None:
                #print("Message from {devaddr} - AppEUI {appeui} "
                #    "does not match any configued applications.",
                #    devaddr=euiString(device.devaddr), appeui=device.appeui)
            #    returnValue(False)
                
            # Decrypt frmpayload
            #global appskey
            #global devaddr
            #devaddr = 0x06000002
            
            devaddr = message.payload.fhdr.devaddr
            dev = device.Device(devaddr)
            print('Encrypted App Msg', hexlify(message.payload.frmpayload))
            message.decrypt(dev.appskey)
            print('AppsKey',hex(dev.appskey))
            appdata = message.payload.frmpayload
            try:
                print('Decrypted App Msg**************',appdata.decode('ascii'))
            except:
                print('Decrypted App Msg**************',hexlify(appdata))
            port = message.payload.fport
            print('port',port)
                                
            # Route the data to an application server via the configured interface
            #print("Outbound message from devaddr {devaddr}",
            #         devaddr=devaddrString(device.devaddr))
            #interface = interfaceManager.getInterface(app.appinterface_id)
            #if interface is None:
            #    pass
            #    log.error("No outbound interface found for application "
            #              "{app}", app=app.name)
            #elif not interface.started:
            #    pass
            #    log.error("Outbound interface for application "
            #              "{app} is not started", app=app.name)
            #else:
            #    pass
                #self._outboundAppMessage(interface, device, app, port, appdata)
            
            # Send an ACK if required
            if message.isConfirmedDataUp():
                appdata=''
                #now = time.ticks_ms()
                inboundAppMessage(devaddr, appdata, request.token, acknowledge=True)
                #print('process inboundappmessage time in ms', time.ticks_ms()-now)

class Stat(object):
    """A Gateway Stat (upstream) JSON object.
    
    The root JSON object shall contain zero or one stat
    objects. See Gateway to Server Interface Definition
    Section 6.2.1.
    
    Attributes:
        time (str): UTC time of the LoRa frame (us precision).
        lati (float): Gateway latitude in degress north of the equator.
        long (float): Gateway longitude in degress north of the equator.
        alti (int): Altitude of the gateway's position in metres above sea
                    level
        rxnb (int): Number of radio frames received since gateway start.
        rxok (int): Number of radio frames received with correct CRC since
                    gateway start.
        rwfw (int): Number of radio frames forwarded to the network server
                    since gateway start.
        ackr (int): Percentage of radio frames forwarded to the network
                    server, and acknowledged by the server since gateway
                    start.
        dwnb (int): Number of radio frames received from the network server
                    since gateway start.
        txnb (int): Number of radio frames transmitted since gateway start.
    
    """
    
    def __init__(self):
        """Stat initialisation method.
        
        """
        self.time = None
        self.lati = None
        self.long = None
        self.alti = None
        self.rxnb = None
        self.rxok = None
        self.rwfw = None
        self.ackr = None
        self.dwnb = None
        self.txnb = None
    
    @classmethod
    def decode(cls, stp):
        """Decode Stat JSON dictionary.
        
        Args:
            stp (dict): Dict representation of stat JSON object.
        
        Returns:
            Stat object.
            
        """
        
        skeys = stp['stat'].keys()
        s = Stat()
        
        # Set the attributes
        s.time = stp['stat']['time'] if 'time' in skeys else None
        s.lati = float(stp['stat']['lati']) if 'lati' in skeys else None
        s.long = float(stp['stat']['long']) if 'long' in skeys else None
        s.alti = int(stp['stat']['alti']) if 'alti' in skeys else None
        s.rxnb = int(stp['stat']['rxnb']) if 'rxnb' in skeys else None
        s.rxok = int(stp['stat']['rxok']) if 'rxok' in skeys else None
        s.rwfw = int(stp['stat']['rwfw']) if 'rwfw' in skeys else None
        s.ackr = int(stp['stat']['ackr']) if 'ackr' in skeys else None
        s.dwnb = int(stp['stat']['dwnb']) if 'dwnb' in skeys else None
        s.txnb = int(stp['stat']['txnb']) if 'txnb' in skeys else None

        print('STAT PACKET')
        #for attr, value in s.__dict__.items():
        #    print(attr, value)
        return s

class Rxpk(object):
    """A Gateway Rxpk (upstream) JSON object.
    
    The root JSON object shall contain zero or more rxpk
    objects. See Gateway to Server Interface Definition
    Section 6.2.2.
    
    Attributes:
        tmst (int): value of the gateway time counter when the
                    frame was received (us precision).
        freq (float): Centre frequency of recieved signal (MHz).
        chan (int): Concentrator IF channel on which the frame
                    was received.
        rfch (int): Concentrator RF chain on which the frame
                    was received.
        stat (int): The result of the gateway's CRC test on the
                    frame - 1 = correct, -1 = incorrect, 0 = no test.
        modu (str): Modulation technique - "LORA" or "FSK".
        datr (str): Datarate identifier. For Lora, comprised of
                    "SFnBWm where n is the spreading factor and
                    m is the frame's bandwidth in kHz.
        codr (str): ECC code rate as "k/n" where k is carried
                    bits and n is total bits received.
        rssi (int): The measured received signal strength (dBm).
        lsnr (float): Measured signal to noise ratio (dB).
        data (str): Frame payload encoded in Base64.
        time (str): UTC time of the LoRa frame (us precision).
        size (int): Number of octects in the received frame.
    
    """
    
    def __init__(self, tmst=None, freq=None, chan=None, rfch=None,
                 stat=None, modu=None, datr=None, codr=None, rssi=None,
                 lsnr=None, data=None, time=None, size=None):
        """Rxpk initialisation method.
        
        """
        self.tmst = tmst
        self.freq = freq
        self.chan = chan
        self.rfch = rfch
        self.stat = stat
        self.modu = modu
        self.datr = datr
        self.codr = codr
        self.rssi = rssi
        self.lsnr = lsnr
        self.data = data
        self.time = time        
        self.size = size
                
    @classmethod
    def decode(cls, rxp):
        """Decode Rxpk JSON dictionary.
            
        Args:
            rxp (dict): Dict representation of rxpk JSON object.
        
        Returns:
            Rxpk object if successful, None otherwise.
            
        """
        
        rkeys = rxp.keys()
        # Check mandatory fields exist
        mandatory = ('tmst', 'freq', 'chan', 'rfch',
                     'stat', 'modu', 'datr', 'codr',
                     'rssi', 'lsnr', 'data')
        if not all (rkeys for k in mandatory):
            return None
        # Mandatory attributes
        tmst = int(rxp['tmst'])
        freq = float(rxp['freq'])        
        chan = int(rxp['chan'])
        rfch = int(rxp['rfch'])
        stat = int(rxp['stat'])
        modu = rxp['modu']
        datr = rxp['datr']
        codr = rxp['codr']
        rssi = int(rxp['rssi'])
        lsnr = float(rxp['lsnr'])
        data = b64decode(rxp['data'])
        # Optional attributes
        time = rxp['time'] if 'time' in rkeys else None
        size = int(rxp['size']) if 'size' in rkeys else None        
        a = Rxpk(tmst=tmst, freq=freq, chan=chan, rfch=rfch, stat=stat,
                    modu=modu, datr=datr, codr=codr, rssi=rssi, lsnr=lsnr,
                    data=data, time=time, size=size)


        '''for m, v in a.__dict__.items():
            try:
                for attr, value in v.__dict__.items():
                    print('    '+attr, value)
            except:
                print(m, v)
                continue
        '''
        return a
class GatewayMessage():
    """A Gateway Message.
    
    Messages sent between the LoRa gateway and the LoRa network
    server. The gateway message protocol operates over UDP and
    occupies the data area of a UDP packet. See Gateway to Server
    Interface Definition.
    
    Attributes:
        version (int): Protocol version - 0x01 or 0x02
        token (str): Arbitrary tracking value set by the gateway.
        id (int): Identifier - see GWMP Identifiers above.
        gatewayEUI (str): Gateway device identifier.
        payload (str): GWMP payload.
        remote (tuple): Gateway IP address and port.
        ptype (str): JSON protocol top-level object type.

    """

    def __init__(self, version=2, token=0, identifier=None,
                 gatewayEUI=None, txpk=None, remote=None,
                 ptype=None):
        """GatewayMessage initialisation method.
        
        Args:
            version (int): GWMP version.
            token (str): Message token.
            id: GWMP identifier.
            gatewayEUI: gateway device identifier.
            payload: GWMP payload.
            ptype (str): payload type
            remote: (host, port)
            
        Raises:
            TypeError: If payload argument is set to None.
        
        """
        self.version = version
        self.token = token
        self.id = identifier
        self.gatewayEUI = gatewayEUI
        self.payload = ''
        self.ptype = ptype
        self.remote = remote
        
        self.rxpk = None
        self.txpk = txpk
        self.stat = None
    
    @classmethod
    def decode(cls, data, remote):
        """Create a Message object from binary representation.
        
        Args:
            data (str): UDP packet data.
            remote (tuple): Gateway address and port.
        
        Returns:
            GatewayMessage object on success.
            
        """
        # Check length
        if len(data) < 4:
            raise DecodeError("Message too short.")
        # Decode header
        (version, token, identifer) = unpack('<BHB', data[:4])
        #print('Received Token', token)
        m = GatewayMessage(version=version, token=token, identifier=identifer)
        m.remote = remote
        # Test versions (1 or 2) and supported message types
        if ( m.version not in (1, 2) or 
             m.version == 1 and m.id not in (PUSH_DATA, PULL_DATA) or 
             m.version == 2 and m.id not in (PUSH_DATA, PULL_DATA, TX_ACK)
             ):
                print('Version',m.version,'ID',m.id)
                pass
                #raise UnsupportedMethod()

        # Decode gateway EUI and payload
        if m.id == PUSH_DATA:
            if len(data) < 12:
                raise DecodeError("PUSH_DATA message too short.")
            m.gatewayEUI = unpack('<Q', data[4:12])[0]
            m.payload = data[12:]
        elif m.id == PULL_DATA:
            if len(data) < 12:
                raise DecodeError("PULL_DATA message too short.")
            m.gatewayEUI = unpack('<Q', data[4:12])[0]
        elif m.id == TX_ACK:
            m.payload = data[4:]
            
        # Decode PUSH_DATA payload
        if m.id == PUSH_DATA:
            try:
                jdata = loads(m.payload)
            except ValueError:
                raise DecodeError("JSON payload decode error")
            m.ptype = list(jdata.keys())[0]
            # Rxpk payload - one or more.
            if  m.ptype == 'rxpk':
                m.rxpk = []
                for r in jdata['rxpk']:
                    rx = Rxpk.decode(r)
                    if rx is not None:
                        m.rxpk.append(rx)
                if not m.rxpk:
                    raise DecodeError("Rxpk payload decode error")
            # Stat payload
            elif m.ptype == 'stat':
                m.stat = Stat.decode(jdata)
                if m.stat is None:
                    raise DecodeError("Stat payload decode error")
            # Unknown payload type
            else:
                raise DecodeError("Unknown payload type")



        

        '''for a, v in m.__dict__.items():
            try:
                for attr, value in v.__dict__.items():
                    print('    '+attr,value)
            except:
                print(a, v)
                continue
        ''' 
        return m

    def encode(self):
        """Create a binary representation of message from Message object.
        
        Returns:
            String of packed data.
        
        """
        data = ''
        if self.id == PUSH_ACK:
            data = pack('<BHB', self.version, self.token, self.id)
        elif self.id == PULL_ACK:
            data = pack('<BHBQ', self.version, self.token, self.id,
                               self.gatewayEUI)
        elif self.id == PULL_RESP:
            if self.version == 1:
                self.token = 0
            self.payload = self.txpk.encode()
            data = pack('<BHB', self.version, self.token, self.id) + \
                    bytearray(self.payload)
                    #bytearray(self.payload,'utf-8')
            #print('Gatewayencode',hexlify(data))
        return data

def datagramReceived(datapacket, host, port):
    """Handle an inbound LoraWAN datagram.

    This method dispatches the inbound GWMP types PULL_DATA and PUSH_DATA.
    
    Args:
        data (str): UDP packet data.
        (host, port) (tuple): Gateway IP address and port.
    
    """
    #print('Received %s bytes from %s:%s' % (len(datapacket), host,port))
    #print(repr(datapacket))
    global remote
    remote = (host, port)
    gateway = (host,port)
    #print("Received"+ repr(datapacket)+"from"+host+":"+"port") 
    #gateway = self.gateway(host)
    #if gateway is None:
    #    log.error("Gateway message from unknown gateway {host}", host=host)
    #    return
    #if not gateway.enabled:
    #    log.error("Gateway message from disabled gateway {host}", host=host)
    #    return
    #try:
    #now = time.ticks_ms()
    gm=GatewayMessage()
    message = gm.decode(datapacket, (host, port))
    #print('Process Gateway msg in ms', time.ticks_ms()-now)
    #except (UnsupportedMethod, DecodeError) as e:
    #    if isinstance(e, UnsupportedMethod):
    #        log.error("Gateway message unsupported method error "
    #                "{errstr}", errstr=str(e))
    #    elif isinstance(e, DecodeError):
    #        log.error("Gateway message decode error "
    #                "{errstr}", errstr=str(e))
    #    return

    #gateway.eui = message.gatewayEUI
    if message.id == PULL_DATA:
        #pass
        print('PULL_DATA')
        #for attr, value in message.__dict__.items():
            #print(attr, value)
        #print("Received PULL_DATA from %s:%d" % (host, port))
        #gateway.port = port
        #self._acknowledgePullData(message)
    elif message.id == PUSH_DATA:
        #print('PUSH_DATA')
        #print("Received PUSH_DATA from %s:%d" % (host, port))
        #self._acknowledgePushData(message)

        #print('MESSAGE')
        #for attr, value in message.__dict__.items():
        #    print(attr, value)
        #print()
        #print('RXPacket')
        #if message.rxpk == None:
        #    pass
        #else:
        #    for rxpk in message.rxpk:
        #        for attr, value in rxpk.__dict__.items():
        #            print(attr, value)

        if(message.ptype=='stat'):
            pass
            #print('STAT MESSAGE')
            #for attr, value in message.stat.__dict__.items():
            #    print(attr, value)
            
        else:
            #now = time.ticks_ms()
            processPushDataMessage(message,gateway)
            #print('Process Push Data message in ms', time.ticks_ms()-now)
            #processPushDataMessage(message,'asf')#message, gateway)
        
    elif message.id == TX_ACK:
        # TODO: Version 2 only
        pass


def main():

    # Create a TCP/IP socket
    if os.__name__ == 'os':
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind the socket to the port
        server_address = ('', 1700)
        print('Starting up on%s port %s' % server_address)
        sock.bind(server_address)

        while True:
            print('\n===================================================================')
            data, address = sock.recvfrom(4096)
            print(data)
            #print('received %s bytes from %s' % (len(data), address))
            datagramReceived(data, address[0],address[1])


if __name__=='__main__':
    main()    

    
