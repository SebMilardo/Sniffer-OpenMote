#!/usr/bin/env python

########################################################################################################
###
### @author     Alberto Ciolini 
###
########################################################################################################


import pyshark
from event import *


def broccoli(file):

    try:
        conn_obj = connect()

        cap = pyshark.FileCapture(file)
        for pkt in cap:
            if pkt.transport_layer != None:
                protocol = pkt.transport_layer
                src_addr = pkt.ipv6.src_host
                dst_addr = pkt.ipv6.dst_host
                src_port = pkt[pkt.transport_layer].srcport
                dst_port = pkt[pkt.transport_layer].dstport
                if protocol == 'TCP':
                    pkt_tcp = pkt.tcp
                    if pkt_tcp.flags_syn == '1':
                        send_tcp_req(conn_obj, src_addr, src_port, dst_addr, dst_port)
                    else:
                        send_transport_protocol(conn_obj, protocol, src_addr, src_port, dst_addr, dst_port)
                else:
                    send_transport_protocol(conn_obj, protocol, src_addr, src_port, dst_addr, dst_port)

            if hasattr(pkt, 'icmpv6'):
                pkt_icmp = pkt.icmpv6
                if pkt_icmp.type == '128':
                    src_addr = pkt.ipv6.src_host
                    dst_addr = pkt.ipv6.dst_host
                    timestamp = pkt.frame_info.time_relative
                    seq = pkt_icmp.echo_sequence_number
                    send_ping(conn_obj, src_addr, dst_addr, seq, timestamp)

    except IOError as io:
        print str(io) + '. Execute file Tesi.bro before Bro.py!'

    return
