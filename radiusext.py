## Author: Michal Garcarz (mgarcarz@cisco.com)
## Date: 15.10.2013
## Update: 25.10.2013

"""
RADIUS (Remote Authentication Dial In User Service)
"""

import struct
from scapy.packet import *
from scapy.fields import *
from scapy.all import *

import re
import array
import string
import random

from radiusattr import RadiusAttr
from hashlib import *

class RadiusExt(Packet):
    name = "RadiusExt"
    fields_desc = [ ByteEnumField("code", 1, {1: "Access-Request",
                                              2: "Access-Accept",
                                              3: "Access-Reject",
                                              4: "Accounting-Request",
                                              5: "Accounting-Accept",
                                              6: "Accounting-Status",
                                              7: "Password-Request",
                                              8: "Password-Ack",
                                              9: "Password-Reject",
                                              10: "Accounting-Message",
                                              11: "Access-Challenge",
                                              12: "Status-Server",
                                              13: "Status-Client",
                                              21: "Resource-Free-Request",
                                              22: "Resource-Free-Response",
                                              23: "Resource-Query-Request",
                                              24: "Resource-Query-Response",
                                              25: "Alternate-Resource-Reclaim-Request",
                                              26: "NAS-Reboot-Request",
                                              27: "NAS-Reboot-Response",
                                              29: "Next-Passcode",
                                              30: "New-Pin",
                                              31: "Terminate-Session",
                                              32: "Password-Expired",
                                              33: "Event-Request",
                                              34: "Event-Response",
                                              40: "Disconnect-Request",
                                              41: "Disconnect-ACK",
                                              42: "Disconnect-NAK",
                                              43: "CoA-Request",
                                              44: "CoA-ACK",
                                              45: "CoA-NAK",
                                              50: "IP-Address-Allocate",
                                              51: "IP-Address-Release",
                                              253: "Experimental-use",
                                              254: "Reserved",
                                              255: "Reserved"} ),
                    ByteField("id", 0),
                    ShortField("len", None),
                    StrFixedLenField("authenticator","",16) ]
    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            l = len(p)
            p = p[:2]+struct.pack("!H",l)+p[4:]
        return p
    
    ################################ GENERIC FUNCTIONS #############################
    def display_str_as_hex(src):
	return ":".join(x.encode('hex') for x in src)

    def hexxor(a, b):    # xor two hex strings of the same length
	return "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(a, b)])
    
    def xor_strings(xs, ys):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

    @staticmethod
    def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for x in range(size))
	
    @staticmethod 
    def array_to_int(array):
	reduce(lambda x, y: (x<<8) + y, array)

    ################################ RADIUS FUNCTIONS ##############################

    def Get_AVPList(self,D):
	#input: radius packet payload
	#output: list of AVPs
	Data = str(D)
	data_len = len(Data)
	curr_len =0
	AVP_list = []
	while (curr_len + 2 <= data_len):
	    try:	    
		result = array.array('B',Data)
		avp_type = result[curr_len+0]
		avp_len = result[curr_len+1]
		avp_value = result[curr_len+2:curr_len+avp_len]
		AVP_list.append(RadiusAttr(type=avp_type,value=avp_value))
		curr_len += avp_len
	    except:
		print "Exception"
		pass 
	return AVP_list

    def Print_AVP(self,AVP_List):
	#input: tables of AVPs, value is the array of bytes
	for i in range(len(AVP_List)):
	    avp = AVP_List[i]
	    if avp.type == 1:
		print "AVP[%d] Type: %d (User-Name) Value: %s" % (i, avp.type, "".join(map(chr,avp.value)))	    
	    elif avp.type == 2:
		print "AVP[%d] Type: %d (User-Password) Value: *" % (i, avp.type)
	    elif avp.type == 4:
		print "AVP[%d] Type: %d (NAS-IP-Address) Value: %s" % (i, avp.type,socket.inet_ntoa(avp.value))
	    elif avp.type == 5:
		print "AVP[%d] Type: %d (NAS-Port) Value: %s" % (i, avp.type,socket.inet_ntoa(avp.value))
	    elif avp.type == 6:
		val = reduce(lambda x, y: (x<<8) + y, avp.value)
		if val == 1:
		    print "AVP[%d] Type: %d (Service-Type) Value: %d (Login)" % (i, avp.type,val)
		elif val == 2:
		    print "AVP[%d] Type: %d (Service-Type) Value: %d (Framed)" % (i, avp.type,val)
		elif val == 5:
		    print "AVP[%d] Type: %d (Service-Type) Value: %d (Outbound)" % (i, avp.type,val)
		elif val == 10:
		    print "AVP[%d] Type: %d (Service-Type) Value: %d (Call-check)" % (i, avp.type,val)
		else:
		    print "AVP[%d] Type: %d (Service-Type) Value: %d" % (i, avp.type,val)
	    elif avp.type == 7:
		val = reduce(lambda x, y: (x<<8) + y, avp.value)
		if val == 1:
		    print "AVP[%d] Type: %d (Framed-Protocol) Value: %d (PPP)" % (i, avp.type,val)
		else:
		    print "AVP[%d] Type: %d (Framed-Protocol) Value: %d" % (i, avp.type,val)
	    elif avp.type == 8:
		print "AVP[%d] Type: %d (Framed-IP-Address) Value: %s" % (i, avp.type,socket.inet_ntoa(avp.value))
	    elif avp.type == 9:
		print "AVP[%d] Type: %d (Framed-IP-Netmask) Value: %s" % (i, avp.type,socket.inet_ntoa(avp.value))
	    elif avp.type == 11:
		print "AVP[%d] Type: %d (Filter-Id) Value: %s" % (i, avp.type,"".join(map(chr,avp.value)))
	    elif avp.type == 12:
		val = reduce(lambda x, y: (x<<8) + y, avp.value)
		print "AVP[%d] Type: %d (Framed-MTU) Value: %d" % (i, avp.type,val)
	    elif avp.type == 13:
		val = reduce(lambda x, y: (x<<8) + y, avp.value)
		if val == 1:
		    print "AVP[%d] Type: %d (Framed-Compression) Value: %d (Van-Jacobsen-TCP-IP)" % (i, avp.type,val)
		else:
		    print "AVP[%d] Type: %d (Framed-Compression) Value: %d" % (i, avp.type,val)
	    elif avp.type == 24:
		print "AVP[%d] Type: %d (State) Value: %s" % (i, avp.type,"".join(map(chr,avp.value)))
	    elif avp.type == 25:
		print "AVP[%d] Type: %d (Class) Value: %s" % (i, avp.type,"".join(map(chr,avp.value)))
	    elif avp.type == 26:
		vendor_id = int(avp.value[0])*256*256*256+256*256*int(avp.value[1])+256*int(avp.value[2])+int(avp.value[3])
		internal_avp_type = avp.value[4]
		internal_avp_val = "".join(map(chr,avp.value[6:]))
		if vendor_id == 9:
		    if internal_avp_type == 1:
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco) Type: %d (Cisco-AV-Pair) Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)		
		    elif internal_avp_type == 21:
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco) Type: %d (Cisco-Abort-Cause) Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)		
		    elif internal_avp_type == 244:
			internal_avp_val_int = struct.unpack('>I',avp.value[6:])[0]
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco) Type: %d (Cisco-Idle-Limit) Value: %d" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val_int)		
		    else:
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco) Type: %d Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)		
		elif vendor_id == 388:
		    if internal_avp_type == 2:			
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Motorola) Type: %d (Symbol-Current-ESSID) Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)				    
		    elif internal_avp_type == 4:
			internal_avp_val_int = 0
			try:
			    internal_avp_val_int = struct.unpack('>I',avp.value[6:])[0]
			except:
			    #violates RFC 2865 (value is not 32bit usigned)
			    pass
			#internal_avp_val_int = struct.unpack('>B',avp.value[6:7])[0]
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Motorola) Type: %d (Symbol-WLAN-Index) Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val_int)				    
		    else:
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Motorola) Type: %d Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)				    
		elif vendor_id == 3076:
		    if internal_avp_type == 15:
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-IPSec-Banner1) Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)				    
		    elif internal_avp_type == 28:
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-IPSec-Default-Domain) Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)				    
		    elif internal_avp_type == 61:
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-DHCP-Network-Scope) Value: %s" % (i, avp.type,vendor_id,internal_avp_type,socket.inet_ntoa(internal_avp_val))				    
		    elif internal_avp_type == 85:
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-Tunnel-Group-Lock) Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)				    
		    elif internal_avp_type == 220:
			internal_avp_val_int = struct.unpack('>I',avp.value[6:])[0]
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-Privilege-Level) Value: %d" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val_int)				    
		    else:
			print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)				    
		else:
		    print "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d Type: %d Value: %s" % (i, avp.type,vendor_id,internal_avp_type,internal_avp_val)		
	    elif avp.type == 30:
		print "AVP[%d] Type: %d (Called-Station-Id) Value: %s" % (i, avp.type,"".join(map(chr,avp.value)))
	    elif avp.type == 31:
		print "AVP[%d] Type: %d (Calling-Station-Id) Value: %s" % (i, avp.type,"".join(map(chr,avp.value)))
	    elif avp.type == 40:
		val = reduce(lambda x, y: (x<<8) + y, avp.value)
		if val == 1:
		    print "AVP[%d] Type: %d (Acct-Status-Type) Value: %d (Start)" % (i, avp.type,val)
		elif val == 2:
		    print "AVP[%d] Type: %d (Acct-Status-Type) Value: %d (Stop)" % (i, avp.type,val)
		elif val == 3:
		    print "AVP[%d] Type: %d (Acct-Status-Type) Value: %d (Interim)" % (i, avp.type,val)
		else:    
		    print "AVP[%d] Type: %d (Acct-Status-Type) Value: %s" % (i, avp.type,val)
	    elif avp.type == 44:
		print "AVP[%d] Type: %d (Acct-Session-Id) Value: %s" % (i, avp.type,"".join(map(chr,avp.value)))
	    elif avp.type == 61:
	    	val = reduce(lambda x, y: (x<<8) + y, avp.value)
		if val == 5:
		    print "AVP[%d] Type: %d (NAS-Port-Type) Value: %d (Virtual)" % (i, avp.type,val)
		elif val == 15:
		    print "AVP[%d] Type: %d (NAS-Port-Type) Value: %d (Ethernet)" % (i, avp.type,val)
		elif val == 19:
		    print "AVP[%d] Type: %d (NAS-Port-Type) Value: %d (Wireless-802.11)" % (i, avp.type,val)
		else:
		    print "AVP[%d] Type: %d (NAS-Port-Type) Value: %d (Virtual)" % (i, avp.type,val)
	    elif avp.type == 79:
		print "AVP[%d] Type: %d (EAP-Message) Value: %s" % (i, avp.type,"".join(map(chr,avp.value)))
	    elif avp.type == 80:
		print "AVP[%d] Type: %d (Message-Authenticator) Value: %s" % (i, avp.type,"".join(map(chr,avp.value)))
	    elif avp.type == 87:
		print "AVP[%d] Type: %d (Nas-Port-Id) Value: %s" % (i, avp.type,"".join(map(chr,avp.value)))
	    else:
		#by default convert value to ascii string
		print "AVP[%d] Type: %d Value: %s" % (i, avp.type, "".join(map(chr,avp.value)))
    
    def Display_Packet(self, Packet):
	Packet[UDP].decode_payload_as(Radius)
	
	print "Radius packet details: %s:%d -> %s:%d" % (Packet[IP].src,Packet[UDP].sport,Packet[IP].dst,Packet[UDP].dport) 
	if Packet[Radius].code == 1:
	    print "Radius Code: 1 (Access-Request)"
	elif Packet[Radius].code == 2:
	    print "Radius Code: 2 (Access-Accept)"
	elif Packet[Radius].code == 3:
	    print "Radius Code: 3 (Access-Reject)"
	elif Packet[Radius].code == 4:
	    print "Radius Code: 4 (Accounting-Request)"
	elif Packet[Radius].code == 5:
	    print "Radius Code: 5 (Accounting-Response)"
	else:
	    print "Radius Code: %d" % Packet[Radius].code
	print "Radius Id: %d" % Packet[Radius].id
	self.Print_AVP(self.Get_AVPList(Packet[Radius].payload))
	print ""
    
    @staticmethod
    def Generate_id():
	return random.randrange(255)
    
    @staticmethod
    def Generate_Authenticator():
	chars=string.ascii_uppercase + string.digits
	return ''.join(random.choice(chars) for x in range(16))

    @staticmethod
    def Generate_AcctAuthenticator(): #FIX IT AS PER RFC 2866
	chars=string.ascii_uppercase + string.digits
	return ''.join(random.choice(chars) for x in range(16))
   
