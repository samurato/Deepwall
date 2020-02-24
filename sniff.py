#!/usr/bin/env python
from scapy.all import *



def print_summary(pkt):
    if IP in pkt:
        print(extract_ip_information(pkt))
    if TCP in pkt:
        print(extract_tcp_information(pkt))
  



def extract_ip_information(pkt):
    '''
       0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Example Internet Datagram Header source:-https://tools.ietf.org/html/rfc791

    ###[ IP Packet example value]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 82
     id        = 7665
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = 0x54b5
     src       = 192.168.163.161
     dst       = 192.168.163.2


    This Function will extract all the IP packet's information Further information on IP 
    refer to http://www.pearsonitcertification.com/articles/article.aspx?p=1843887 for more infomration
    on IP structure.
    '''
    ip_version = pkt[IP].version #Extracts the version of IP used as of  JAN 2020 ip v4 and v6 are used.
    ip_internet_header_length=pkt[IP].ihl # Extracts the internet Header length :- typically 32 bit words
    ip_terms_of_service=pkt[IP].tos # Terms of service(TOS) used for QOS purpos    
    ip_length =pkt[IP].len  #Total length of the ip packet including the data.
    ip_id =pkt[IP].id  # Uniquely set by sender for identification, uses 16 bit
    ip_flags =pkt[IP].flags  #Used to control how the IP packet is treated by a device in terms of fragmentation.
    ip_fragment_offset =pkt[IP].frag  # Fragment offset field  used to identify the fragmented packets and reassemble them.
    ip_time_to_live =pkt[IP].ttl  #Amount of time a packet is allowed to exist on the network.
    ip_protocol =pkt[IP].proto  # Used to represent the tye of protocol used commonly :- TCP, UDP or ICMP
    ip_checksum =pkt[IP].chksum  #checksum to verfiy that the ip header is not compramised.
    ip_source =pkt[IP].src  # Source IP
    ip_destination =pkt[IP].dst  # Destination IP.

    return(ip_source,ip_destination)

def extract_tcp_information(pkt):
    '''

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                TCP Header Format Source :- rfc793
    
    '''
    tcp_source_port = pkt[TCP].sport #TCP Source Port number
    tcp_destination_port = pkt[TCP].dport  #TCP Destination Port number
    #tcp_sequence_number = pkt[TCP].Sequence
    return(pkt[IP])









sniff(filter="ip",prn=print_summary)
# or it possible to filter with filter parameter...!

sniff(iface="ens33", prn=print_summary)
