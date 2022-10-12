import socket
import pprint
import os
import threading
import time
import random

from scapy.all import *
from struct import *

from Crypto.Cipher import AES

global ack_counter
global nSeq
global recdata

ack_counter = {}
nSeq = {}
recdata = {}

def pkt_callback(packet):
    data = b''
    
    global datalen
    global recdata
    global ack_counter
    global nSeq
    global netiface
    
    key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10'
    
    if packet[0][2].flags == 'S':
        try:
            nSeq[packet[0][1].src + ':' + str(packet[0][2].sport)] = random.randint(2 << 16, 2 << 24)
            sendp(Ether()/IP(dst=packet[0][1].src)/TCP(sport=packet[0][2].dport, dport=packet[0][2].sport, seq=nSeq[packet[0][1].src + ':' + str(packet[0][2].sport)], ack=1, flags='SA'), iface=netiface, verbose=False)
        except Exception as e:
            return str(e)
        ack_counter[packet[0][1].src + ':' + str(packet[0][2].sport)] = 2
        recdata[packet[0][1].src + ':' + str(packet[0][2].sport)] = b''
        
    if packet[0][2].flags == 'FA':
        try:
            sendp(Ether()/IP(dst=packet[0][1].src)/TCP(sport=packet[0][2].dport, dport=packet[0][2].sport, seq=nSeq[packet[0][1].src + ':' + str(packet[0][2].sport)]+1, ack=ack_counter[packet[0][1].src + ':' + str(packet[0][2].sport)], flags='FA'), iface=netiface, verbose=False)
            ack_counter.pop(packet[0][1].src + ':' + str(packet[0][2].sport), None)
            nSeq.pop(packet[0][1].src + ':' + str(packet[0][2].sport), None)
            decipher = AES.new(key, AES.MODE_ECB)
            dtext = decipher.decrypt(recdata[packet[0][1].src + ':' + str(packet[0][2].sport)][:datalen[packet[0][1].src + ':' + str(packet[0][2].sport)]])
            return f"{packet[0][1].src}:{packet[0][2].sport} ==> {packet[0][1].dst}:{packet[0][2].dport}: {dtext.decode('utf-8')}"
        except Exception as e:
            return str(e)
        
    if packet[0][2].flags == 'PA' and (packet[0][1].src + ':' + str(packet[0][2].sport)) in ack_counter and (packet[0][1].src + ':' + str(packet[0][2].sport)) in nSeq:
        if packet[0][1].tos == 0:
            datalen[packet[0][1].src + ':' + str(packet[0][2].sport)] = packet[0][1].id
        try:
            data = pack('>L', packet[0][2].options[2][1][0]) + pack('>L', packet[0][2].options[2][1][1])
        except:
            data = b'\x00' * 8
        recdata[packet[0][1].src + ':' + str(packet[0][2].sport)] += data
        try:
            sendp(Ether()/IP(dst=packet[0][1].src)/TCP(sport=packet[0][2].dport, dport=packet[0][2].sport, seq=nSeq[packet[0][1].src + ':' + str(packet[0][2].sport)]+1, ack=ack_counter[packet[0][1].src + ':' + str(packet[0][2].sport)], flags='A'), iface=netiface, verbose=False)
            ack_counter[packet[0][1].src + ':' + str(packet[0][2].sport)] += 1
        except:
            return str(e)
        
    return None


if __name__ == "__main__":
    print('Найдено интерфейсов:', len(IFACES))
    print(IFACES)
    ifind = input('Index интерфейса: ')

    global netiface
    global datalen
    datalen = {}
    
    try:
        netiface = dev_from_index(int(ifind))
    except Exception as e:
        print(e)
        exit()
    
    t = AsyncSniffer(iface = netiface, filter = 'tcp and dst port 10007', prn = pkt_callback)
    
    t.start()
    input('PRESS ANY KEY TO EXIT\n')
    t.stop()
    