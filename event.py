#!/usr/bin/env python

########################################################################################################
###
### @author     Alberto Ciolini 
###
########################################################################################################



from broccoli import *


@event
def event_received(dst_time):
    print("Bro: event received successful at %f!" % dst_time)


def connect():
    bro = Connection("127.0.0.1:47758")

    return bro


def send_transport_protocol(conn_obj, protocol, src_addr, src_port, dst_addr, dst_port):
    conn_obj.send("transport_protocol", string(protocol), string(src_addr), count(src_port),
                  string(dst_addr), count(dst_port))

    return


def send_tcp_req(conn_obj, src_addr, src_port, dst_addr, dst_port):
    conn_obj.send("tcp_req", string(src_addr), count(src_port), string(dst_addr), count(dst_port))

    return


def send_ping(conn_obj, src_addr, dst_addr, seq, timestamp):
    conn_obj.send("ping", string(src_addr), string(dst_addr), count(seq), time(timestamp))

    return
