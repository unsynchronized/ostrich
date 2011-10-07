#!/usr/bin/env python

import struct
import logging
import threading

from scapy.config import *
conf.use_pcap = True        # XXX: a hack to make bpf filters work on linux
from scapy.all import *
logging.getLogger("scapy").setLevel(1)

# These variables select 


conf.use_pcap = True
# OCTRL top-level commands.
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

# Destination type enum values.
OCTRL_SEND_CHANNEL = 0
OCTRL_SEND_UDPIP4  = 1

# Channel types.
OCTRL_CHANNEL_UDP4 = 0

# Currently-defined flags.
OCTRL_FLAG_ENABLE_COOKIE = 0
OCTRL_FLAG_ENABLE_PMLVM  = 1
OCTRL_FLAG_MAX_INSNS     = 2

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

class CLEAR_M(Packet):
    name = "CLEAR_M"
    fields_desc = [
        XByteField("command", CLEAR_M)
    ]

class DELETE_M(Packet):
    name = "DELETE_M"
    fields_desc = [
        XByteField("command", DELETE_M),
        IntField("maddr", 0),
        IntField("len", 0)
    ]

class SET_CMDPORT(Packet):
    name = "SET_CMDPORT"
    fields_desc = [
        XByteField("command", SET_CMDPORT),
        ShortField("port", 0),
    ]

class SET_CMDIP(Packet):
    name = "SET_CMDIP"
    fields_desc = [
        XByteField("command", SET_CMDIP),
        FieldLenField("iplen", 0, fmt="H", length_of="ip"),
        StrLenField("ip", "", "iple")
    ]

class SET_COOKIE(Packet):
    name = "SET_COOKIE"
    fields_desc = [
        XByteField("command", SET_COOKIE),
        FieldLenField("cookielen", 0, fmt="H", length_of="cookie"),
        StrLenField("cookie", "", "cookielen")
    ]

class SET_FLAG(Packet):
    name = "SET_FLAG"
    fields_desc = [
        XByteField("command", SET_FLAG),
        ShortEnumField("flag", OCTRL_FLAG_ENABLE_COOKIE, 
            { OCTRL_FLAG_ENABLE_COOKIE: "OCTRL_FLAG_ENABLE_COOKIE",
              OCTRL_FLAG_ENABLE_PMLVM: "OCTRL_FLAG_ENABLE_PMLVM"
            }),
        FieldLenField("datalen", 0, fmt="H", length_of="data"),
        StrLenField("data", "", "datalen")
    ]

class DEL_CHANNEL(Packet):
    name = "DEL_CHANNEL"
    fields_desc = [
        XByteField("command", DEL_CHANNEL),
        XByteField("id", 0),
        ]

class SAVE_M(Packet):
    name = "SAVE_M"
    fields_desc = [
        XByteField("command", SAVE_M),
        IntField("maddr", 0),
        IntField("len", 0)
    ]

class SET_M(Packet):
    name = "SET_M"
    fields_desc = [
        XByteField("command", SET_M),
        XIntField("maddr", 0),
        FieldLenField("datalen", 0, fmt="H", length_of="data"),
        StrLenField("data", "", "datalen")
        ]

class SEND_M_RESPONSE(Packet):
    name = "SEND_M_RESPONSE"
    fields_desc = [
        ByteEnumField("result", 0, {0: "m_clear", 1:"success", 2:"invalid_range"}),
        XIntField("mlen", 0),
        FieldLenField("datalen", None, length_of="data"),
        StrLenField("data", None, length_from=lambda pkt: pkt.datalen)
        ]

class OCtrlChannel(Packet):
    fields_desc = [
        XByteField("id", 0),
        IntEnumField("type", OCTRL_CHANNEL_UDP4, {OCTRL_CHANNEL_UDP4: "OCTRL_CHANNEL_UDP4"}),
        StrFixedLenField("addr", '', 16),
        IntField("port", 0)
    ]
    def extract_padding(self, p):
        return "",p

class SEND_CHANNELS_RESPONSE(Packet):
    fields_desc = [
        FieldLenField("chancount", None, count_of="channels", fmt="B"),
        PacketListField("channels", None, OCtrlChannel, count_from=lambda pkt:pkt.chancount)
        ]

class SET_CHANNEL(Packet):
    fields_desc = [
        XByteField("command", SET_CHANNEL),
        XByteField("id", 0),
        IntEnumField("type", OCTRL_CHANNEL_UDP4, {OCTRL_CHANNEL_UDP4: "OCTRL_CHANNEL_UDP4"}),
        StrFixedLenField("addr", '', 16),
        IntField("port", 0)
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

class OCReq(Packet):
    name = "OCReq "
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

def myocsr(pkt, timeout=GLOBAL_TIMEOUT, verbose=2, filter=None):
    return [sr1(pkt, timeout=timeout, filter=filter, verbose=verbose, iface="en0")]

def tocsr(pkt, timeout=GLOBAL_TIMEOUT, verbose=2, filter=None):
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
        if isinstance(res, tuple):
            res = reduce(lambda x,y: x+y, res)

ocsr = myocsr

class octrl(object):
    dstip = "10.10.1.1"
    cookie = "cookie"
    cmdip = "10.10.1.2"
    cmdport = 4142
    dst = ("10.10.1.2", 4445)
    srcport = 4445

    def getbase(self):
        return IP(src=self.cmdip,dst=self.dstip)/UDP(sport=self.srcport,dport=self.cmdport)/OCReq(self.cookie)

    def getversion(self):
        res = ocsr(IP(src=self.cmdip,dst=self.dstip)/UDP(sport=self.srcport,dport=self.cmdport)/OCReq(self.cookie)/SEND_VERSION(dst=self.dst), verbose=2, timeout=GLOBAL_TIMEOUT, filter="udp and dst port %u" % self.srcport)
        if res is None:
            return None
        return res[0][Raw].load

    def getchannels(self):
        res = ocsr(IP(src=self.cmdip,dst=self.dstip)/UDP(sport=self.srcport,dport=self.cmdport)/OCReq(self.cookie)/SEND_CHANNELS(dst=self.dst), verbose=2, timeout=GLOBAL_TIMEOUT, filter="udp and dst port %u" % self.srcport)
        if res is None or len(res) == 0:
            return None
        return SEND_CHANNELS_RESPONSE(str(res[0][Raw]))

    def getflags(self):
        res = ocsr(IP(src=self.cmdip,dst=self.dstip)/UDP(sport=self.srcport,dport=self.cmdport)/OCReq(self.cookie)/SEND_FLAGS(dst=self.dst), verbose=2, timeout=GLOBAL_TIMEOUT, filter="udp and dst port %u" % self.srcport)
        if res is None or len(res) == 0:
            return None
        return str(res[0][Raw])

    def get_m(self, maddr, mlen):
        res = ocsr(IP(src=self.cmdip,dst=self.dstip)/UDP(sport=self.srcport,dport=self.cmdport)/OCReq(self.cookie)/SEND_M(maddr=maddr, len=mlen, dst=self.dst), verbose=2, timeout=GLOBAL_TIMEOUT, filter="udp and dst port %u" % self.srcport)
        if res is None or len(res) == 0:
            return None
        return SEND_M_RESPONSE(str(res[0][Raw]))


    def setchannel(self, chanid, chantype, chanip, chanport):
        p = self.getbase()/SET_CHANNEL(id=chanid, type=chantype, addr=inet_aton(chanip), port=chanport)
        send(p)

    def delchannel(self, chanid):
        p = self.getbase()/DEL_CHANNEL(id=chanid)
        send(p)

    def set_m(self, maddr, m):
        p = self.getbase()/SET_M(maddr=maddr, data=m, datalen=len(m))
        send(p)

    def save_m(self, maddr, mlen):
        p = self.getbase()/SAVE_M(maddr=maddr, len=mlen)
        send(p)

    def delete_m(self, maddr, mlen):
        p = self.getbase()/DELETE_M(maddr=maddr, len=mlen)
        send(p)

    def set_flag(self, flag, flagval):
        p = self.getbase()/SET_FLAG(flag=flag, data=flagval, datalen=len(flagval))
        send(p)

    def set_cookie(self, ncookie):
        p = self.getbase()/SET_COOKIE(cookie=ncookie, cookielen=len(ncookie))
        send(p)

    def setcmdip(self, ncmdip):
        p = self.getbase()/SET_CMDIP(ip=ncmdip, iplen=len(ncmdip))
        send(p)

    def setcmdport(self, nport):
        p = self.getbase()/SET_CMDPORT(port=nport)
        send(p)

    def clear_m(self):
        p = self.getbase()/CLEAR_M()
        send(p)

# XXX
#ver = getversion("10.10.1.1", "cookie", "10.10.1.2", 4142, dst=("10.10.1.2",4445))
#print "version: " + str(ver)

def demo():
    set_flag("192.168.1.1", "cookie", "192.168.0.5", 4142, OCTRL_FLAG_MAX_INSNS, struct.pack("!I", 1000))
    exit(1)

    clear_m("192.168.1.1", "cookie", "192.168.0.5", 4142)

    set_m("192.168.1.1", "cookie", "192.168.0.5", 4142, 0, "abcdefg")
    save_m("192.168.1.1", "cookie", "192.168.0.5", 4142, 0, 16)
    m = get_m("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1", 0, 16)
    if m is not None:
        print "m[0:15]: " 
        hexdump(m)
        mp = SEND_M_RESPONSE(m)
        mp.display()
    else:
        print "(no response)"
    delete_m("192.168.1.1", "cookie", "192.168.0.5", 4142, 0, 4)
    m = get_m("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1", 0, 16)
    if m is not None:
        print "m[0:15]: " 
        hexdump(m)
        mp = SEND_M_RESPONSE(m)
        mp.display()
    else:
        print "(no response)"
    exit(1)


    exit(1)


    setcmdport("192.168.1.1", "cookie", "192.168.0.5", 4142, 4143)
    setcmdport("192.168.1.1", "cookie", "192.168.0.5", 4143, 4142)

    setcmdip("192.168.1.1", "cookie", "192.168.0.5", 4142, inet_aton("192.168.0.8"))
    setcmdip("192.168.1.1", "cookie", "192.168.0.8", 4142, inet_aton("192.168.0.5"))

    ver = getversion("192.168.1.1", "cookie", "192.168.0.5", 4142, dst=("192.168.1.1",4445))
    print "version: " + str(ver)
    set_cookie("192.168.1.1", "cookie", "192.168.0.5", 4142, "aaabbb")
    ver = getversion("192.168.1.1", "aaabbb", "192.168.0.5", 4142, dst=("192.168.1.1",4445))
    print "version: " + str(ver)
    set_cookie("192.168.1.1", "aaabbb", "192.168.0.5", 4142, "cookie")

    set_flag("192.168.1.1", "cookie", "192.168.0.5", 4142, OCTRL_FLAG_ENABLE_PMLVM, "\x01")

    m = get_m("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1", 0, 16)
    if m is not None:
        print "m[0:15]: " 
        hexdump(m)
        mp = SEND_M_RESPONSE(m)
        mp.display()
    else:
        print "(no response)"

    set_m("192.168.1.1", "cookie", "192.168.0.5", 4142, 0, "abcdefg")
    save_m("192.168.1.1", "cookie", "192.168.0.5", 4142, 0, 16)
    m = get_m("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1", 0, 16)
    if m is not None:
        print "m[0:15]: " 
        hexdump(m)
        mp = SEND_M_RESPONSE(m)
        mp.display()
    else:
        print "(no response)"
    exit(1)



    setchannel("192.168.1.1", "cookie", "192.168.0.5", 4142, 1, OCTRL_CHANNEL_UDP4, "192.168.1.1", 4446)
    setchannel("192.168.1.1", "cookie", "192.168.0.5", 4142, 4, OCTRL_CHANNEL_UDP4, "192.168.1.1", 4447)

    ver = getversion("192.168.1.1", "cookie", "192.168.0.5", 4142, 1, port=4446)
    print "version: " + str(ver)

    chans = getchannels("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1")
    print "chans: " 
    ch = SEND_CHANNELS_RESPONSE(chans)
    ch.display()

    delchannel("192.168.1.1", "cookie", "192.168.0.5", 4142, 1)

    chans = getchannels("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1")
    print "chans: " 
    ch = SEND_CHANNELS_RESPONSE(chans)
    ch.display()

    setfilter("192.168.1.1", "cookie", "192.168.0.5", 4142, "\xFF\xFF\xFF\xFF\xFF\xFF")


    m = get_m("192.168.1.1", "cookie", "192.168.0.5", 4142, "192.168.1.1", 0, 4)
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

#  IP(src="192.168.0.5",dst="192.168.1.1")/UDP(sport=4445,dport=4142)/OCReq("cookie")/SEND_M(maddr=0x11223344, len=0x5566, dst=("192.168.1.1",4142))


#send(IP(src="192.168.0.4",dst="192.168.1.1")/UDP(dport=4142)/"cookie\x00\x17\x06\x00\x00\x00\x00\x00\x10\x01\xC0\xA8\x01\x01\x22\x23\x00\x01\xC0\xA8\x01\x01\x22\x23\x00\x01\xC0\xA8\x01\x01\x22\x23")
