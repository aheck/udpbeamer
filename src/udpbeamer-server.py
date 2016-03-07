#!/usr/bin/python

import argparse
import hashlib
import os
import sys
import socket
import struct
import thread
import time
import traceback

from scapy.all import *

# keep track of packets captured on the interface
captured_packets_lock = thread.allocate_lock()
captured_packets = []
captured_packets_dict = {}

# keep track of packets 'announced' over our TCP side-channel
announced_packets_lock = thread.allocate_lock()
announced_packets = []
announced_packets_dict = {}

parser = argparse.ArgumentParser(description="UDP \"connection\" quality measuring tool")

parser.add_argument("udp_port", metavar='UDP_PORT', type=int,
                          help="UDP port to monitor")
parser.add_argument('-w', '--write-pcap', default=False, action='store_true',
        help='Write packets to announced.pcap and captured.pcap')

args = parser.parse_args()
udp_port = args.udp_port
print("UDP PORT: %d" % (udp_port))

#if write_pcap:
    #announced_pcap = PcapWriter("announced.pcap", append=True, sync=True)
    #captured_pcap = PcapWriter("captured.pcap", append=True, sync=True)
    #pktdump.write(pkt)

def packet_hash(packet):
    h = hashlib.sha1()

    # remove ethernet padding to normalize packets
    packet = IP(str(packet[IP])[0:packet[IP].len])

    h.update(str(packet[IP].payload))

    return h.hexdigest()

def run_tcp_server():
    try:
        serversocket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)

        serversocket.bind(('0.0.0.0', 3450))
        serversocket.listen(1)

        (clientsocket, address) = serversocket.accept()

        while 1:
            length = clientsocket.recv(4)
            length = struct.unpack("!I", length)[0]
            data = clientsocket.recv(length)
            received_over_tcp = time.time()
            p = Ether(data)

            pkt_hash = packet_hash(p)
            pkt_entry = {
                    'pkt_hash': pkt_hash,
                    'packet': p,
                    'received_over_tcp': received_over_tcp,
                    'seen_on_interface': False
                    }

            announced_packets_lock.acquire()

            try:
                announced_packets.append(pkt_entry)
                announced_packets_dict[pkt_hash] = pkt_entry
            finally:
                announced_packets_lock.release()

    except Exception:
        print(traceback.format_exc())

def udp_monitor_callback(p):
    received_physically = time.time()

    if UDP in p and p[UDP].dport == udp_port:

        pkt_hash = packet_hash(p)
        pkt_entry = {
                'pkt_hash': pkt_hash,
                'packet': p,
                'received_physically': received_physically,
                }

        captured_packets_lock.acquire()

        try:
            captured_packets.append(pkt_entry)
            captured_packets_dict[pkt_hash] = pkt_entry
        finally:
            captured_packets_lock.release()

def run_capture():
    print("Starting to capture packets...")
    sniff(prn=udp_monitor_callback, filter="udp", store=0)

capture_thread = thread.start_new_thread(run_capture, ())

time.sleep(3) # magic sleep to give Scapy time for initialization

tcp_sever = thread.start_new_thread(run_tcp_server, ())

def packet_entry_str(entry):
    p = entry['packet']
    return "%s:%d => %s:%d %s" % (p[IP].src, p[UDP].sport, p[IP].dst,
            p[UDP].dport, entry['pkt_hash'])

def check_packet_arrivals():
    now = time.time()

    for i, entry in enumerate(announced_packets):
        # forget packets that are older than 20 seconds
        if now - entry['received_over_tcp'] > 20:
            del announced_packets[i]
            del announced_packets_dict[entry['pkt_hash']]
            if entry['pkt_hash'] in captured_packets_dict:
                captured_packets.remove(captured_packets_dict[entry['pkt_hash']])
                del captured_packets_dict[entry['pkt_hash']]

            continue

        if entry['seen_on_interface']:
            continue

        if entry['pkt_hash'] in captured_packets_dict:
            entry['seen_on_interface'] = True

            print("Packet received: %s" % (packet_entry_str(entry)))
            continue

        if now - entry['received_over_tcp'] > 10:
            print("\033[1;31mPacket missing > 10s: %s\033[0;0m" % (packet_entry_str(entry)))

while 1:
    time.sleep(2)

    announced_packets_lock.acquire()
    captured_packets_lock.acquire()

    try:
        check_packet_arrivals()
    finally:
        announced_packets_lock.release()
        captured_packets_lock.release()
