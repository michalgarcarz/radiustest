## Author: Michal Garcarz (mgarcarz@cisco.com)
## Date: 15.10.2013
## Update: 25.10.2013

"""
RADIUS payload of AVP for VSA (Vendor Specific Attributes)
"""

import struct
import re
import array
import string

from scapy.packet import *
from scapy.fields import *
from hashlib import *

class RadiusAttrVSA(Packet):
    name = "RadiusAttrVSA"
    fields_desc = [ ByteEnumField("type", 1, {1: "User-Name",
                                              2: "User-Password",
                                              4: "NAS-IP-Address",
                                              5: "NAS-Port",
                                              6: "Service-Type",
                                              7: "Framed-Protocol",
                                              8: "Framed-IP-Address",
                                              9: "Framed-IP-Netmask", 
                                              11: "Filter-id",
                                              12: "Framed-MTU",
                                              13: "Framed-Compression",
                                              24: "State",
                                              26: "Vendor-Specific",
                                              30: "Called-Station-Id",
                                              31: "Calling-Station-Id",
                                              61: "NAS-Port-Type",
                                              79: "EAP-Message",
                                              80: "Message-Authenticator",
                                              87: "NAS-Port-Id",
                                              255: "Reserved"} ),                    
                    ByteField("len", None),
                    StrLenField("value",""),
                    ByteField("vsa_id",None),
                    ByteField("vsa_type",None), 
                    StrLenField("vsa_value","") ]
    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
    	    l = len(p)
#            l = len(pay)
            p = p[:1]+struct.pack("!B",l)+p[2:]
#            p = p[:1]+p[2:]
        return p

    def xor_strings(self,xs, ys):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))
    
    @staticmethod
    def Encrypt_Pass(password, authenticator, secret):
	m = md5()
        m.update(secret+authenticator)
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(password.ljust(16,'\0')[:16], m.digest()[:16]))

