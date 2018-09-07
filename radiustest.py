#! /usr/bin/python
# Author: Michal Garcarz at cisco.com
# Date: 15.10.2013
# Update: 26.10.2013

import re
import array
import string
import random
import argparse
import logging
#disable ipv6 warning before importing scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from struct import *
from scapy.all import *
from radiusattr import RadiusAttr
from radiusext import RadiusExt
from hashlib import *
from threading import Thread
from Queue import Queue, Empty

#set a conf verb not to disaply packets sent by scapy
conf.verb = 0


################################ GENERIC FUNCTIONS #############################

################################ RADIUS FUNCTIONS ##############################

def Radius_Send_Request_PAP(host,dst_port,src_port,password, username, authenticator, secret, radius_id, \
    nasipaddr, service_type, nas_port_type, calling_station_id, called_station_id, vsa_id, vsa_type, vsa_value, vsa_coding, vsa_trim, \
    framed_ip):
    avp1 = RadiusAttr(type="User-Name",value=username)
    avp2 = RadiusAttr(type="User-Password",value=RadiusAttr.Encrypt_Pass(password,authenticator,secret))
    avp3 = RadiusAttr(type="NAS-IP-Address",value=nasipaddr)
    avp = str(avp1)+str(avp2)+str(avp3)
    if len(framed_ip) >2:
	avp4 = RadiusAttr(type="Framed-IP-Address",value=framed_ip)
	avp = avp + str(avp4)

    if service_type == "framed":
	avp4 = RadiusAttr(type="Service-Type",value=socket.inet_aton("2")) #Framed
	avp += str(avp4)
    elif service_type == "login":
	avp4 = RadiusAttr(type="Service-Type",value=socket.inet_aton("1")) #Login
	avp += str(avp4)
    elif service_type == "outbound":
	avp4 = RadiusAttr(type="Service-Type",value=socket.inet_aton("5")) #Outbound
	avp += str(avp4)
    elif service_type == "call-check":
	avp4 = RadiusAttr(type="Service-Type",value=socket.inet_aton("10")) #Call-check
	avp += str(avp4)
    if nas_port_type == "ethernet":
	avp4 = RadiusAttr(type="NAS-Port-Type",value=socket.inet_aton("15")) #Ethernet
	avp += str(avp4)
    elif nas_port_type == "wireless":
	avp4 = RadiusAttr(type="NAS-Port-Type",value=socket.inet_aton("19")) #Wireless
	avp += str(avp4)
    elif nas_port_type == "virtual":
	avp4 = RadiusAttr(type="NAS-Port-Type",value=socket.inet_aton("5")) #Virtual
	avp += str(avp4)
    if called_station_id != "":
	avp4 = RadiusAttr(type="Called-Station-Id",value=called_station_id) 
	avp += str(avp4)	
    if calling_station_id != "":
	avp4 = RadiusAttr(type="Calling-Station-Id",value=calling_station_id) 
	avp += str(avp4)	
    if vsa_id != "" and vsa_type != "" and vsa_value != "":
	if vsa_coding == "string":
	    avp3 = RadiusAttr(type=vsa_type,value=vsa_value) 
    	    avp4 = RadiusAttr(type="Vendor-Specific",value=socket.inet_aton(str(vsa_id))+str(avp3)) 
    	    avp += str(avp4)	
    	elif vsa_coding == "hex":
    	    if vsa_trim == "":
    		#No trimming, send hex value as 32 unsigned int as per RFC 2865
    	        avp3 = RadiusAttr(type=vsa_type,value=socket.inet_aton(vsa_value))     	        	        	    
    		avp4 = RadiusAttr(type="Vendor-Specific",value=socket.inet_aton(str(vsa_id))+str(avp3)) 
    		avp += str(avp4)	
    	    else:
    		#Trimming the attribute, violates RFC 2865
    	        avp3 = RadiusAttr(type=vsa_type,value=vsa_value)     	    
    		avp4 = RadiusAttr(type="Vendor-Specific",value=socket.inet_aton(str(vsa_id))+str(avp3)) 
    		avp += str(avp4)	

    
    RadiusPacket = RadiusExt(code="Access-Request",authenticator=authenticator,id=radius_id)    
    Packet=IP(dst=host)/UDP(sport=src_port,dport=dst_port)/RadiusPacket/(avp)
    send(Packet)
    
    print "Sending Radius Packet......."
    RadiusPacket.Display_Packet(Packet)
    #print Packet.summary()
    #Packet.show()

def Radius_Packet_Counter(Packet,port):
    global r_accept
    global r_reject 
    global r_other 
    if IP in Packet and UDP in Packet:
	if Packet[UDP].sport == port:
	    Packet[UDP].decode_payload_as(Radius)
	    RadiusPacket = RadiusExt(code=Packet[Radius].code,authenticator=Packet[Radius].authenticator,id=Packet[Radius].id)
	    print "Received Radius Packet......"
	    RadiusPacket.Display_Packet(Packet)
		
	    if Packet[Radius].code == 2:
		r_accept += 1
	    elif Packet[Radius].code == 3:
		r_reject += 1
	    else:
		r_other += 1
   
########################### SNIFFING ###########################################

m_iface = "eth0"
m_finished = False
m_main = False
r_accept = 0
r_reject = 0
r_other = 0
    
#listening for a response from the server/port on which we have send Radius-Requests
def threaded_sniff_target(q,host,timeout,port):
    global m_finished

    #determine interface used to sniff (determined by routing)
    p = subprocess.Popen(["ip", "route", "get", host], stdout=subprocess.PIPE)
    x = str(p.stdout.read())
    y = x[x.find("dev"):x.find("src")]
    m_iface = y[y.find(" ")+1:len(y)-2]

    print "Choosen %s interface for sniffing" % m_iface
    fff = "udp and src {0} and port {1}".format(host,port)
    print "Sniffing traffic from %s" % fff
    sniff(iface = m_iface, timeout = timeout, filter = "udp and src {0} and port {1}".format(host,port), prn = lambda x : q.put(x))
    m_finished = True

def threaded_sniff(host,timeout,port):
    q = Queue()
    sniffer = Thread(target = threaded_sniff_target, args = (q,host,timeout,port,))
    sniffer.daemon = True
    sniffer.start()
    while (not m_finished):
	try:
	    pkt = q.get(timeout = 1)
	    Radius_Packet_Counter(pkt,port)
	    #print pkt.summary()
	except Empty:
	    pass
    print "Finishing sniffing thread"
    global m_main
    m_main = True
     
################################## MAIN ########################################
 
#defaults
src_port = random.randrange(1024,65535)
dst_port = 1812
timeout = 5
packet_num = 1
service_type = ""
nas_port_type = ""
called_station_id = ""
calling_station_id = ""
vsa_id=""
vsa_type=""
vsa_value=""
vsa_coding="string"
vsa_trim=""
framed_ip=""

parser = argparse.ArgumentParser("Send & Receive Radius Packets by Michal Garcarz at cisco.com")
parser.add_argument('-d', '--host', help='Destination host', required=True)
parser.add_argument('-s', '--secret', default="cisco", help='Radius secret, default: cisco')
parser.add_argument('-u', '--username', default="cisco", help='Radius username, default: cisco')
parser.add_argument('-p', '--password', default="cisco", help='Radius password, default: cisco')
parser.add_argument('-sp', '--src_port', help='Source port, default: random')
parser.add_argument('-dp', '--dst_port', default="1812", help='Destination port, default: 1812')
parser.add_argument('-t', '--timeout', default="5", help='Timeout, default: 5s')
parser.add_argument('-n', '--packet_num', default="1", help='Number of packets to send, default: 1')
parser.add_argument('-an', '--nas_ip_addr', help='AVP NAS-IP-Address, default: source ip from udp packet')
parser.add_argument('-ap', '--nas_port_type', help='AVP NAS-Port-Type, default: none', choices=["ethernet","wireless", "virtual"])
parser.add_argument('-as', '--service_type', help='AVP Service-Type, default: none', choices=["framed","login", "outbound", "call-check"])
parser.add_argument('-ac', '--called_station_id', help='AVP Called-Station-Id format: [xx-xx-xx-xx-xx-xx]", default: none')
parser.add_argument('-ai', '--calling_station_id', help='AVP Calling-Station-Id format: [xx-xx-xx-xx-xx-xx], default: none')
parser.add_argument('-fi', '--framed_ip_addr', help='AVP Framed-Ip-Address format: [xx.xx.xx.xx], default: none')
parser.add_argument('-avi', '--vendor_specific_id', help='AVP with vendor specific attribute: vendor id, default: none')
parser.add_argument('-avt', '--vendor_specific_type', help='AVP with vendor specific attribute: attribute id, default: none')
parser.add_argument('-avv', '--vendor_specific_value', help='AVP with vendor specific attribute: attribute value, default: none')
parser.add_argument('-avx', '--vendor_specific_value_coding', help='AVP with vendor specific attribute: attribute value encoding, default: string', choices=["string","hex"])
parser.add_argument('-avc', '--vendor_specific_value_trim', help='AVP with vendor specific attribute: trim hex attribute to X bytes default: none')
args = parser.parse_args()
args = vars(parser.parse_args())
if (args['host']):
    host = args['host']
src_host = socket.inet_aton(IP(dst=host).src)
nasipaddr = src_host
if (args['src_port']):
    src_port = int(args['src_port'])
if (args['dst_port']):
    dst_port = int(args['dst_port'])
if (args['timeout']):
    timeout = int(args['timeout'])
if (args['packet_num']):
    packet_num = int(args['packet_num'])
if (args['secret']):
    secret = args['secret']
if (args['username']):
    username = args['username']
if (args['password']):
    password = args['password']
if (args['nas_ip_addr']):
    nasipaddr = socket.inet_aton(args['nas_ip_addr'])
if (args['service_type']):
    service_type = args['service_type']
if (args['nas_port_type']):
    nas_port_type = args['nas_port_type']
if (args['calling_station_id']):
    calling_station_id = args['calling_station_id']
if (args['called_station_id']):
    called_station_id = args['called_station_id']
if (args['framed_ip_addr']):
    framed_ip = socket.inet_aton(args['framed_ip_addr'])
if (args['vendor_specific_id']):
    vsa_id = int(args['vendor_specific_id'])
if (args['vendor_specific_type']):
    vsa_type = int(args['vendor_specific_type'])
if (args['vendor_specific_value']):
    vsa_value = args['vendor_specific_value']
if (args['vendor_specific_value_coding']):
    vsa_coding = args['vendor_specific_value_coding']
if (args['vendor_specific_value_trim']):
    vsa_trim = args['vendor_specific_value_trim']


print "Starting sniffing daemon"
thread = Thread(target = threaded_sniff, args = (host,timeout,dst_port,))
thread.daemon = True
thread.start()
time.sleep(1)

print "Sending Radius Access-Requests"
for x in range(0, packet_num):
    Radius_Send_Request_PAP(host, dst_port, src_port, password, username, RadiusExt.Generate_Authenticator(), \
    secret, RadiusExt.Generate_id(), nasipaddr, service_type, nas_port_type, calling_station_id, called_station_id, \
    vsa_id, vsa_type, vsa_value, vsa_coding, vsa_trim, framed_ip )

print "Waiting %d seconds for the responses" % timeout

while (not m_main):
    try:
	time.sleep(1)
    except Empty:
	pass

print "Results:"
print "Radius-Request sent: %d" % packet_num
print "Radius-Accept received: %d" % r_accept
print "Radius-Reject received: %d" % r_reject
print "Other Radius messages received: %d" % r_other
print "Finishing main thread"
