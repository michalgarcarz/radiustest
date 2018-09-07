# radiustest
Radius client in python

I. Introduction

This is a flexible radius client. The main idea is to have a client which could be easily used to test different Radius servers.
Client supports:
- Radius PAP authentication
- Multi thread (sniffing separated from sending)
- Several Attribute Value Pairs (AVP) supported (nas-ip-address, service-type, nas-port-type, calling-station-id, called-station-id)
- We can add new AVP easily
- Support for flooding mode (performance/stress testing)

Client uses scapy library to send/receive packets. It consists of two python classes:
- RadiusExt: Radius class supporting AVP, authentication, packet manipulation (derived from Scapy Packet class)
- RadiusAttr: Class for AVP (derived from Scapy Packet class)

I use this client to:
- test basic PAP authentication
- send different AVP to test if Radius server is behaving correctly (RFC compliance)
- display and validate returned AVP
- flood Radius server with multiple packets (performance testing, Cisco ACS support ~200 Authentications per second per node)
- find memory leaks in Radius server (it's easier when server is stress tested)

Disclaimer:
This client is not fully RFC compliant. There are many corner case scenarios which has not been programmed.

Author: Michal Garcarz AT cisco.com
License: Open Software License

II. Requirements
- Python 2.x (tested on python 2.7.5)
- Scapy 2.2 (tested on scanpy 2.2.0)

III. Installation
No need. Just run ./radiustest.py. 

IV. Examples

1. Sending 1 Access-Request for username/password cisco/cisco, secret=cisco, source port = 666, waiting 4 seconds for reply.
Attaching AVP: NAS-IP-Address, Service-Type, NAS-Port-Type, Called-Station-Id, Calling-Station-Id

   ./radiustest.py -d 192.168.10.120 -t 4 -s cisco -u cisco -p cisco -an 1.1.1.1 -sp 666 -n 1 -as framed -ap ethernet -ac 11:22:33:44:55:66 -ai 55:55:55:55:55:55 
   Starting sniffing daemon
   Choosen tap1 interface for sniffing
   Sending Radius Access-Requests
Sending Radius Packet.......
Radius packet details: 192.168.10.1:666 -> 192.168.10.120:1812
Radius Code: 1 (Access-Request)
Radius Id: 46
AVP[0] Type: 1 (User-Name) Value: cisco
AVP[1] Type: 2 (User-Password) Value: *
AVP[2] Type: 4 (NAS-IP-Address) Value: 1.1.1.1
AVP[3] Type: 6 (Service-Type) Value: 2 (Framed)
AVP[4] Type: 61 (NAS-Port-Type) Value: 15 (Ethernet)
AVP[5] Type: 30 (Called-Station-Id) Value: 11:22:33:44:55:66
AVP[6] Type: 31 (Calling-Station-Id) Value: 55:55:55:55:55:55

Waiting 4 seconds for the responses
Received Radius Packet......
Radius packet details: 192.168.10.120:1812 -> 192.168.10.1:666
Radius Code: 2 (Access-Accept)
Radius Id: 46
AVP[0] Type: 6 (Service-Type) Value: 2 (Framed)
AVP[1] Type: 7 (Framed-Protocol) Value: 1 (PPP)
AVP[2] Type: 8 (Framed-IP-Address) Value: 172.16.3.33
AVP[3] Type: 9 (Framed-IP-Netmask) Value: 255.255.255.0
AVP[4] Type: 11 (Filter-Id) Value: ACLin
AVP[5] Type: 12 (Framed-MTU) Value: 1500
AVP[6] Type: 13 (Framed-Compression) Value: 1 (Van-Jacobsen-TCP-IP)

Finishing sniffing thread
Results:
Radius-Request sent: 1
Radius-Accept received: 1
Radius-Reject received: 0
Other Radius messages received: 0
Finishing main thread

2. Sending Motorola VSA pair: vendor id = 388, attribute number = 2 (Symbol-Current-ESSID 
), attribute value = "WLAN_SSID", attribute type = string

./radiustest.py -d 10.48.66.185 -avi 388 -avt 2 -avv "Wlan essid" -avx string
Starting sniffing daemon
Choosen eth0 interface for sniffing
Sniffing traffic from udp and src 10.48.66.185 and port 1812
Sending Radius Access-Requests
Sending Radius Packet.......
Radius packet details: 10.147.24.84:60220 -> 10.48.66.185:1812
Radius Code: 1 (Access-Request)
Radius Id: 182
AVP[0] Type: 1 (User-Name) Value: cisco
AVP[1] Type: 2 (User-Password) Value: *
AVP[2] Type: 4 (NAS-IP-Address) Value: 10.147.24.84
AVP[3] Type: 26 (Vendor Specific Attribute) Vendor: 388 (Motorola) Type: 2 (Symbol-Current-ESSID) Value: Wlan essid

Waiting 5 seconds for the responses
Finishing sniffing thread
Results:
Radius-Request sent: 1
Radius-Accept received: 0
Radius-Reject received: 0
Other Radius messages received: 0
Finishing main thread


3. Sending Cisco VSA pair: vendor id = 9, attribute number = 21 (Cisco-Abort-Cause), attribute value = Client, attribute type = string

./radiustest.py -d 10.48.66.185 -avi 9 -avt 21 -avv "Client Abort" -avx string
Starting sniffing daemon
Choosen eth0 interface for sniffing
Sniffing traffic from udp and src 10.48.66.185 and port 1812
Sending Radius Access-Requests
Sending Radius Packet.......
Radius packet details: 10.147.24.84:18728 -> 10.48.66.185:1812
Radius Code: 1 (Access-Request)
Radius Id: 144
AVP[0] Type: 1 (User-Name) Value: cisco
AVP[1] Type: 2 (User-Password) Value: *
AVP[2] Type: 4 (NAS-IP-Address) Value: 10.147.24.84
AVP[3] Type: 26 (Vendor Specific Attribute) Vendor: 9 (Cisco) Type: 21 Value: Client Abort

Waiting 5 seconds for the responses
Received Radius Packet......
Radius packet details: 10.48.66.185:1812 -> 10.147.24.84:18728
Radius Code: 3 (Access-Reject)
Radius Id: 144

Finishing sniffing thread
Results:
Radius-Request sent: 1
Radius-Accept received: 0
Radius-Reject received: 1
Other Radius messages received: 0
Finishing main thread

4. Sending Cisco VSA pair: vendor id = 9, attribute number = 244 (Cisco-Idle-Limit), attribute value = 100, attribute type = hex

./radiustest.py -d 10.48.66.185 -avi 9 -avt 244 -avv 100 -avx hex
Starting sniffing daemon
Choosen eth0 interface for sniffing
Sniffing traffic from udp and src 10.48.66.185 and port 1812
Sending Radius Access-Requests
Sending Radius Packet.......
Radius packet details: 10.147.24.84:45842 -> 10.48.66.185:1812
Radius Code: 1 (Access-Request)
Radius Id: 219
AVP[0] Type: 1 (User-Name) Value: cisco
AVP[1] Type: 2 (User-Password) Value: *
AVP[2] Type: 4 (NAS-IP-Address) Value: 10.147.24.84
AVP[3] Type: 26 (Vendor Specific Attribute) Vendor: 9 (Cisco) Type: 244 (Cisco-Idle-Limit) Value: 100

Waiting 5 seconds for the responses
Received Radius Packet......
Radius packet details: 10.48.66.185:1812 -> 10.147.24.84:45842
Radius Code: 3 (Access-Reject)
Radius Id: 219

Finishing sniffing thread
Results:
Radius-Request sent: 1
Radius-Accept received: 0
Radius-Reject received: 1
Other Radius messages received: 0
Finishing main thread

5. Sending Cisco-AV-Pair (vendor_id 9, attribute number = 1). That AVP is commonly used for all custom Cisco attributes.
This example is for Cisco-AV-Pair which contains audit-session-id value. 

./radiustest.py -d 10.48.66.185 -avi 9 -avt 1 -avv "audit-session-id=0A30276F00001225751086B2" -avx string
Starting sniffing daemon
Choosen tun0 interface for sniffing
Sniffing traffic from udp and src 10.48.66.185 and port 1812
Sending Radius Access-Requests
Sending Radius Packet.......
Radius packet details: 10.0.0.104:21714 -> 10.48.66.185:1812
Radius Code: 1 (Access-Request)
Radius Id: 99
AVP[0] Type: 1 (User-Name) Value: cisco
AVP[1] Type: 2 (User-Password) Value: *
AVP[2] Type: 4 (NAS-IP-Address) Value: 10.0.0.104
AVP[3] Type: 26 (Vendor Specific Attribute) Vendor: 9 (Cisco) Type: 1 (Cisco-AV-Pair) Value: audit-session-id=0A30276F00001225751086B2

Waiting 5 seconds for the responses
Finishing sniffing thread
Results:
Radius-Request sent: 1
Radius-Accept received: 0
Radius-Reject received: 0
Other Radius messages received: 0
Finishing main thread

6. Send request and receive multiple Cisco IPSec attributes for VPN access

./radiustest.py -u test -p test -d 10.48.66.185 
Starting sniffing daemon
Choosen eth0 interface for sniffing
Sniffing traffic from udp and src 10.48.66.185 and port 1812
Sending Radius Access-Requests
Sending Radius Packet.......
Radius packet details: 10.147.24.84:31444 -> 10.48.66.185:1812
Radius Code: 1 (Access-Request)
Radius Id: 152
AVP[0] Type: 1 (User-Name) Value: test
AVP[1] Type: 2 (User-Password) Value: *
AVP[2] Type: 4 (NAS-IP-Address) Value: 10.147.24.84

Waiting 5 seconds for the responses
Received Radius Packet......
Radius packet details: 10.48.66.185:1812 -> 10.147.24.84:31444
Radius Code: 2 (Access-Accept)
Radius Id: 152
AVP[0] Type: 1 (User-Name) Value: test
AVP[1] Type: 25 (Class) Value: CACS:acs54/172239296/1862
AVP[2] Type: 26 (Vendor Specific Attribute) Vendor: 3076 (Cisco VPN 3000) Type: 15 (CVPN3000-IPSec-Banner1) Value: VPNBanner
AVP[3] Type: 26 (Vendor Specific Attribute) Vendor: 3076 (Cisco VPN 3000) Type: 28 (CVPN3000-IPSec-Default-Domain) Value: example.com
AVP[4] Type: 26 (Vendor Specific Attribute) Vendor: 3076 (Cisco VPN 3000) Type: 61 (CVPN3000-DHCP-Network-Scope) Value: 10.0.0.0
AVP[5] Type: 26 (Vendor Specific Attribute) Vendor: 3076 (Cisco VPN 3000) Type: 85 (CVPN3000-Tunnel-Group-Lock) Value: TunnelGroup
AVP[6] Type: 26 (Vendor Specific Attribute) Vendor: 3076 (Cisco VPN 3000) Type: 220 (CVPN3000-Privilege-Level) Value: 15

7. Send request and receive multiple Cisco-AV-Pairs for auth proxy and 802.1x:

./radiustest.py -u test -p test -d 10.48.66.185 
Starting sniffing daemon
Choosen eth0 interface for sniffing
Sniffing traffic from udp and src 10.48.66.185 and port 1812
Sending Radius Access-Requests
Sending Radius Packet.......
Radius packet details: 10.147.24.84:31444 -> 10.48.66.185:1812
Radius Code: 1 (Access-Request)
Radius Id: 152
AVP[0] Type: 1 (User-Name) Value: test
AVP[1] Type: 2 (User-Password) Value: *
AVP[2] Type: 4 (NAS-IP-Address) Value: 10.147.24.84

Waiting 5 seconds for the responses
Received Radius Packet......
Radius packet details: 10.48.66.185:1812 -> 10.147.24.84:31444
Radius Code: 2 (Access-Accept)
Radius Id: 152
AVP[0] Type: 1 (User-Name) Value: test
AVP[1] Type: 25 (Class) Value: CACS:acs54/172239296/1862
AVP[2] Type: 26 (Vendor Specific Attribute) Vendor: 9 (Cisco) Type: 1 (Cisco-AV-Pair) Value: ip:inacl#1=deny ip 10.155.10.0 0.0.0.255  10.159.2.0 0.0.0.255 log
AVP[3] Type: 26 (Vendor Specific Attribute) Vendor: 9 (Cisco) Type: 1 (Cisco-AV-Pair) Value: auth-proxy:priv-lvl=15
AVP[4] Type: 26 (Vendor Specific Attribute) Vendor: 9 (Cisco) Type: 1 (Cisco-AV-Pair) Value: auth-proxy:proxyacl#1=permit icmp any any


8. Sending 10 packets, waiting 5 seconds for all responses,  using default settings

./radiustest.py -d 192.168.10.120 -t 5 -n 10

Starting sniffing daemon
Choosen tap1 interface for sniffing
Sending Radius Access-Requests
Sending Radius Packet.......
Radius packet details: 192.168.10.1:38041 -> 192.168.10.120:1812
Radius Code: 1 (Access-Request)
Radius Id: 134
AVP[0] Type: 1 (User-Name) Value: cisco
AVP[1] Type: 2 (User-Password) Value: *
AVP[2] Type: 4 (NAS-IP-Address) Value: 192.168.10.1

<.....output ommitted for clarity.....>

Finishing sniffing thread
Results:
Radius-Request sent: 10
Radius-Accept received: 10
Radius-Reject received: 0
Other Radius messages received: 0
Finishing main thread

9. Sending Motorola VSA attribute type integer with value trimmed to 1 Byte (violating RFC 2865 which is expecting 4 byte value)

./radiustest.py -d 10.48.66.185 -avi 388 -avt 4 -avv 3 -avx hex -avc 1
Starting sniffing daemon
Choosen eth0 interface for sniffing
Sniffing traffic from udp and src 10.48.66.185 and port 1812
Sending Radius Access-Requests
Sending Radius Packet.......
Radius packet details: 10.147.24.84:2414 -> 10.48.66.185:1812
Radius Code: 1 (Access-Request)
Radius Id: 40
AVP[0] Type: 1 (User-Name) Value: cisco
AVP[1] Type: 2 (User-Password) Value: *
AVP[2] Type: 4 (NAS-IP-Address) Value: 10.147.24.84
AVP[3] Type: 26 (Vendor Specific Attribute) Vendor: 388 (Motorola) Type: 4 (Symbol-WLAN-Index) Value: 0

Waiting 5 seconds for the responses
Finishing sniffing thread
Results:
Radius-Request sent: 1
Radius-Accept received: 0
Radius-Reject received: 0
Other Radius messages received: 0
Finishing main thread

10. Sending Accouting start message

./radius-accttest.py -d 172.16.32.10 -s test -at start -ad 123456
Starting sniffing daemon
Choosen vmnet8 interface for sniffing
Sniffing traffic from udp and src 172.16.32.10 and port 1813
Sending Radius Accounting-Requests
Sending Radius Packet.......
Radius packet details: 172.16.32.1:36692 -> 172.16.32.10:1813
Radius Code: 4 (Accounting-Request)
Radius Id: 178
AVP[0] Type: 1 (User-Name) Value: cisco
AVP[1] Type: 4 (NAS-IP-Address) Value: 172.16.32.1
AVP[2] Type: 44 (Acct-Session-Id) Value: 123456
AVP[3] Type: 40 (Acct-Status-Type) Value: 1 (Start)

Waiting 5 seconds for the responses
Finishing sniffing thread
Results:
Radius-Accounting-Request sent: 1
Radius-Accouting-ACK received: 0
Radius-Acconting-NACK received: 0
Other Radius messages received: 0
Finishing main thread

V. Known Caveats:
1. Scapy does not support two default gateways 
When using VPN adapter we usually have two default gateways:

pluton tmp # ip route show
default dev tun0  scope link 
default via 10.0.0.1 dev wlan0  metric 20 

One for VPN (metric=0), and second for network access (metric=20).
Scapy will try to use the second one - with worse metric.

Workaround: create /32 specific network when needed.
Then most specific network will be used instead of default route.

2. Scapy can not sniff traffic on TUN interface
When using VPN and tun interface (tun0) scapy will not be able to sniff traffic.

VI. TODO
Add support for EAP-PEAP and EAP-TLS.
