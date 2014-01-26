NBT-NS/LLMNR Responder
Laurent Gaffie <lgaffie@trustwave.com>
http://www.spiderlabs.com

INTRODUCTION
============

This tool is first an LLMNR and NBT-NS responder, it will answer to 
*specific* NBT-NS (NetBIOS Name Service) queries based on their name 
suffix (see: http://support.microsoft.com/kb/163409). By default, the
tool will only answers to File Server Service request, which is for SMB.
The concept behind this, is to target our answers, and be stealthier on
the network. This also helps to ensure that we don't break legitimate
NBT-NS behavior. You can set the -r option to "On" via command line if 
you want this tool to answer to the Workstation Service request name
suffix.

FEATURES
========

- Built-in SMB Auth server.
  Supports NTLMv1, NTLMv2 hashes with Extended Security NTLMSSP by default.
  Successfully tested from Windows 95 to Server 2012 RC, Samba and Mac OSX Lion.
  Clear text password is supported for NT4, and LM hashing downgrade when the 
  --lm option is set to On. This functionality is enabled by default when the
  tool is launched.

- Built-in MSSQL Auth server.
  In order to redirect SQL Authentication to this tool, you will need to
  set the option -r to On(NBT-NS queries for SQL Server lookup are using
  the Workstation Service name suffix) for systems older than windows 
  Vista (LLMNR will be used for Vista and higher). This server supports
  NTLMv1, LMv2 hashes. This functionality was successfully tested on 
  Windows SQL Server 2005 & 2008.

- Built-in HTTP Auth server.
  In order to redirect HTTP Authentication to this tool, you will need
  to set the option -r to On for Windows version older than Vista (NBT-NS
  queries for HTTP server lookup are sent using the Workstation Service
  name suffix). For Vista and higher, LLMNR will be used. This server 
  supports NTLMv1, NTLMv2 hashes *and* Basic Authentication. This server
  was successfully tested on IE 6 to IE 10, Firefox, Chrome, Safari.
  Note: This module also works for WebDav NTLM authentication issued from
  Windows WebDav clients (WebClient). You can now send your custom files to a victim.

- Built-in HTTPS Auth server.
  In order to redirect HTTPS Authentication to this tool, you will need
  to set the -r option to On for Windows versions older than Vista (NBT-NS
  queries for HTTP server lookups are sent using the Workstation Service
  name suffix). For Vista and higher, LLMNR will be used. This server 
  supports NTLMv1, NTLMv2, *and* Basic Authentication. This server
  was successfully tested on IE 6 to IE 10, Firefox, Chrome, and Safari.
  The folder Cert/ was added and contain 2 default keys, including a dummy
  private key. This is *intentional*, the purpose is to have Responder 
  working out of the box. A script was added in case you need to generate
  your own self signed key pair.

- Built-in LDAP Auth server.
  In order to redirect LDAP Authentication to this tool, you will need
  to set the option -r to On for Windows version older than Vista (NBT-NS
  queries for HTTP server lookup are sent using the Workstation Service
  name suffix). For Vista and higher, LLMNR will be used. This server 
  supports NTLMSSP hashes and Simple Authentication (clear text authentication).
  This server was successfully tested on Windows Support tool "ldp" and LdapAdmin.

- Built-in FTP Auth server.
  This module will collect FTP clear text credentials.

- Built-in small DNS server. This server will answer type A queries. This
  is really handy when it's combined with ARP spoofing. 

- All hashes are printed to stdout and dumped in an unique file John
  Jumbo compliant, using this format:
  (SMB or MSSQL or HTTP)-(ntlm-v1 or v2 or clear-text)-Client_IP.txt
  The file will be located in the current folder.

- Responder will logs all its activity to a file Responder-Session.log.

- When the option -f is set to "On", Responder will fingerprint every host who issued
  an LLMNR/NBT-NS query. All capture modules still work while in fingerprint mode. 

- Browser Listener finds the PDC in stealth mode.

- Icmp Redirect for MITM on Windows XP/2003 and earlier Domain members. This attack combined with
  the DNS module is pretty effective.

- WPAD rogue transparent proxy server. This module will capture all HTTP requests from anyone launching Internet Explorer on the network. This module is higly effective. You can now send your custom Pac script to a victim and inject HTML into the server's responses. See Responder.conf. This module is now enabled by default.

- Responder is now using a configuration file. See Responder.conf.

- Built-in POP3 auth server. This module will collect POP3 plaintext credentials

- Built-in SMTP auth server. This module will collect PLAIN/LOGIN clear text credentials.

CONSIDERATIONS
==============

- This tool listen on several port: UDP 137, UDP 138, UDP 53, UDP/TCP 389,TCP 1433,
  TCP 80, TCP 139, TCP 445, TCP 21, TCP 3141,TCP 25, TCP 110, TCP 587 and Multicast UDP 5553.
  If you run Samba on your system, stop smbd and nmbd and all other 
  services listening on these ports.
  For Ubuntu users: 
  Edit this file /etc/NetworkManager/NetworkManager.conf and comment the line : "dns=dnsmasq".
  Then kill dnsmasq with this command (as root): killall dnsmasq -9

- Any rogue server can be turn off in Responder.conf.

- You can set a network interface via command line switch -I. Default is all. 

- This tool is not meant to work on Windows.


USAGE
=====

First of all, please take a look at Responder.conf and set it for your needs.
Running this tool:

- python Responder.py [options]

Usage Example:

python Responder.py -i 10.20.30.40 -r On -I eth0

Options List:

-h, --help                           show this help message and exit.

-i 10.20.30.40, --ip=10.20.30.40     The ip address to redirect the traffic to.
                                     (usually yours)

-I eth0, --interface=eth0            Network interface to use

-b Off, --basic=Off                  Set this to On if you want to return a 
                                     Basic HTTP authentication. Off will return 
                                     an NTLM authentication.

-r Off, --wredir=Off                 Set this to On to enable answers for netbios 
                                     wredir suffix queries. Answering to wredir
                                     will likely break stuff on the network 
                                     (like classics 'nbns spoofer' will).
                                     Default value is therefore set to Off.

-f Off, --fingerprint=Off            This option allows you to fingerprint a 
                                     host that issued an NBT-NS or LLMNR query.

-w On, --wpad=On                   Set this to On or Off to start/stop the WPAD rogue
                                     proxy server. Default value is On

--lm=Off                             Set this to On if you want to force LM hashing
                                     downgrade for Windows XP/2003 and earlier. Default value is Off


For more information read these posts: 
http://blog.spiderlabs.com/2012/10/introducing-responder-10.html
http://blog.spiderlabs.com/2013/01/owning-windows-networks-with-responder-17.html
http://blog.spiderlabs.com/2013/02/owning-windows-network-with-responder-part-2.html

Follow our latest updates on twitter:
https://twitter.com/PythonResponder

COPYRIGHT
=========

NBT-NS/LLMNR Responder
Created by Laurent Gaffie
Copyright (C) 2013 Trustwave Holdings, Inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
