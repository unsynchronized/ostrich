#!/usr/bin/env python

import struct
import logging
import threading

from scapy.config import *
conf.use_pcap = True        # XXX: a hack to make bpf filters work on linux
from scapy.all import *
logging.getLogger("scapy").setLevel(1)

conf.use_pcap = True
SEND_VERSION  = 0x0
SET_FILTER    = 0x1
SEND_CHANNELS = 0x3
SET_CHANNEL   = 0x4
DEL_CHANNEL   = 0x5
SEND_M        = 0x6
SET_M         = 0x7
SAVE_M        = 0x8
SET_FLAG      = 0x9
SEND_FLAGS    = 0xA
SET_COOKIE    = 0xB
SET_CMDIP     = 0xC
SET_CMDPORT   = 0xD
CLEAR_M       = 0xE
DELETE_M      = 0xF

OCTRL_SEND_CHANNEL = 0
OCTRL_SEND_UDPIP4  = 1

OCTRL_CHANNEL_UDP4 = 0

class OCtrlCommand(Packet):
    fields_desc = [
        ByteEnumField("command", SEND_VERSION,
            { SEND_VERSION: "SEND_VERSION", SET_FILTER: "SET_FILTER",
              SEND_CHANNELS: "SEND_CHANNELS", SET_CHANNEL: "SET_CHANNEL",
              DEL_CHANNEL: "DEL_CHANNEL", SEND_M: "SEND_M", SET_M: "SET_M",
              SAVE_M: "SAVE_M", SET_FLAG: "SET_FLAG", SEND_FLAGS: "SEND_FLAGS",
              SET_COOKIE: "SET_COOKIE", SET_CMDIP: "SET_CMDIP", SET_CMDPORT: "SET_CMDPORT",
              CLEAR_M: "CLEAR_M", DELETE_M: "DELETE_M" }),
          ]

class DestinationField(Field):
    def i2m(self, pkt, x):
        if isinstance(x, str): 
            ip,port = x.split(":")
        elif isinstance(x, tuple):
            ip,port = x
        else:
            return struct.pack("!BB", OCTRL_SEND_CHANNEL, int(x))
        return struct.pack("!B", OCTRL_SEND_UDPIP4)+inet_aton(ip)+struct.pack("!H", int(port))

    def addfield(self,pkt, s, val):
        return s+self.i2m(pkt, val)
            
    def __init__(self, name, default):
        Field.__init__(self, name, default)

class SEND_M_RESPONSE(Packet):
    fields_desc = [
        ByteEnumField("result", 0, {0: "m_clear", 1:"success", 2:"invalid_range"}),
        XIntField("mlen", 0),
        FieldLenField("datalen", None, length_of="data"),
        StrLenField("data", None, length_from=lambda pkt: pkt.datalen)
        ]

class SET_CHANNEL(Packet):
    fields_desc = [
        XByteField("command", SET_CHANNEL),
        XByteField("id", 0),
        IntEnumField("type", OCTRL_CHANNEL_UDP4, {OCTRL_CHANNEL_UDP4: "OCTRL_CHANNEL_UDP4"}),
        StrFixedLenField("addr", '', 16),
        IntEnum("port", 0)
        ]

class SET_FILTER(Packet):
    fields_desc = [
        XByteField("command", SET_FILTER),
        FieldLenField("filterlen", None, length_of="filter"),
        StrLenField("filter", None, length_from=lambda pkt: pkt.filterlen)
        ]

class SEND_M(Packet):
    fields_desc = [
        XByteField("command", SEND_M),
        XIntField("maddr", 0),
        ShortField("len", 0),
        DestinationField("dst", 0)
        ]

class SEND_FLAGS(Packet):
    fields_desc = [
        XByteField("command", SEND_CHANNELS),
        DestinationField("dst", 0)
        ]

class SEND_CHANNELS(Packet):
    fields_desc = [
        XByteField("command", SEND_CHANNELS),
        DestinationField("dst", 0)
        ]

class SEND_VERSION(Packet):
    fields_desc = [ 
        XByteField("command", SEND_VERSION), 
        DestinationField("dst", 0)
        ]

class OCtrl(Packet):
    name = "OCtrl "
    fields_desc = [ 
        StrField("cookie", ''),
        ShortField("len", None),
    ]
    def post_build(self, p, pay):
        if self.len is None and pay:
            return p[:len(self.cookie)]+struct.pack("!H", len(pay))+pay
        return p+pay

GLOBAL_TIMEOUT = 1.5

def ocreceive(timeout, verbose, filter, outarr, cond):
    print "sniffing"
    cond.acquire()
    cond.notify()
    cond.release()
    res = sniff(filter=filter, timeout=timeout, count=1)
    cond.acquire()
    outarr[0] = res
    cond.notify()
    return res

def ocsr(pkt, timeout=GLOBAL_TIMEOUT, verbose=2, filter=None):
    if __name__ == '__main__':
        outarr = [None]
        cond = threading.Condition()
        p = threading.Thread(target=ocreceive, args=(timeout, verbose, filter, outarr, cond))
        p.start()
        cond.acquire()
        cond.wait()
        cond.release()
        send(pkt)
        p.join()
        return outarr[0]


def getversion(dstip, cookie, cmdip, cmdport, localip, port=4445):
    res = ocsr(IP(src=cmdip,dst=dstip)/UDP(sport=port,dport=cmdport)/OCtrl(cookie)/SEND_VERSION(dst=(localip,port)), verbose=2, timeout=GLOBAL_TIMEOUT, filter="udp and dst port %u" % port)
    if isinstance(res, tuple):
        res = reduce(lambda x,y: x+y, res)
    if res is None or len(res) == 0:
        return None
    return str(res[0][Raw])

def getchannels(dstip, cookie, cmdip, cmdport, localip, port=4445):
    res = ocsr(IP(src=cmdip,dst=dstip)/UDP(sport=port,dport=cmdport)/OCtrl(cookie)/SEND_CHANNELS(dst=(localip,port)), verbose=2, timeout=GLOBAL_TIMEOUT, filter="udp and dst port %u" % port)
    if isinstance(res, tuple):
        res = reduce(lambda x,y: x+y, res)
    if res is None or len(res) == 0:
        return None
    return str(res[0][Raw])

def getflags(dstip, cookie, cmdip, cmdport, localip, port=4445):
    res = ocsr(IP(src=cmdip,dst=dstip)/UDP(sport=port,dport=cmdport)/OCtrl(cookie)/SEND_FLAGS(dst=(localip,port)), verbose=2, timeout=GLOBAL_TIMEOUT, filter="udp and dst port %u" % port)
    if isinstance(res, tuple):
        res = reduce(lambda x,y: x+y, res)
    if res is None or len(res) == 0:
        return None
    return str(res[0][Raw])

def getm(dstip, cookie, cmdip, cmdport, localip, maddr, mlen, port=4445):
    res = ocsr(IP(src=cmdip,dst=dstip)/UDP(sport=port,dport=cmdport)/OCtrl(cookie)/SEND_M(maddr=maddr, len=mlen, dst=(localip,port)), verbose=2, timeout=GLOBAL_TIMEOUT, filter="udp and dst port %u" % port)
    if isinstance(res, tuple):
        res = reduce(lambda x,y: x+y, res)
    if res is None or len(res) == 0:
        return None
    return str(res[0][Raw])

def setchan(dstip, cookie, cmdip, cmdport, localip, chanid, chantype, chanip, chanport, port=4445):
    res = ocsr(IP(src=cmdip,dst=dstip)/UDP(sport=port,dport=cmdport)/OCtrl(cookie)/SEND_M(maddr=maddr, len=mlen, dst=(localip,port)), verbose=2, timeout=GLOBAL_TIMEOUT, filter="udp and dst port %u" % port)
    if isinstance(res, tuple):
        res = reduce(lambda x,y: x+y, res)
    if res is None or len(res) == 0:
        return None
    return str(res[0][Raw])


def setfilter(dstip, cookie, cmdip, cmdport, localip, filter, port=4445):
    p = IP(src=cmdip,dst=dstip)/UDP(sport=port,dport=cmdport)/OCtrl(cookie)/SET_FILTER(filter=filter)
    send(p)


setfilter("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1", "\xFF\xFF\xFF\xFF\xFF\xFF")


ver = getversion("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1")
print "version: " + str(ver)

m = getm("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1", 0, 4)
if m is not None:
    print "m[0:15]: " 
    hexdump(m)
    mp = SEND_M_RESPONSE(m)
    mp.display()
else:
    print "(no response)"

flags = getflags("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1")
print "flags: " 
hexdump(flags)

chans = getchannels("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1")
print "chans: " 
hexdump(chans)


#  IP(src="192.168.0.5",dst="192.168.1.1")/UDP(sport=4445,dport=4142)/OCtrl("cookie")/SEND_M(maddr=0x11223344, len=0x5566, dst=("192.168.1.1",4142))


#send(IP(src="192.168.0.4",dst="192.168.1.1")/UDP(dport=4142)/"cookie\x00\x17\x06\x00\x00\x00\x00\x00\x10\x01\xC0\xA8\x01\x01\x22\x23\x00\x01\xC0\xA8\x01\x01\x22\x23\x00\x01\xC0\xA8\x01\x01\x22\x23")
