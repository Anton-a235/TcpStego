import socket
import pprint
import os
import threading
import time
import random

from scapy.all import *

from Crypto.Cipher import AES

global mutex
global dst_ip
global dst_port

def pkt_callback(packet):
    global mutex
    global dst_ip
    global dst_port
    
    if 'A' in packet[0][2].flags and packet[0][1].src == dst_ip and packet[0][2].sport == dst_port:
        mutex.release()
    
    return None


def send_data(dst_ip, ifc, data):
    global dst_port
    global mutex
    
    nSeq = random.randint(2 << 16, 2 << 24)
    src_port = random.randint(11000, 60000)
    dst_port = 10007
    
    mutex = threading.Lock()
    t = AsyncSniffer(prn=pkt_callback, filter="tcp and src port 10007", iface = ifc)
    t.start()
    
    mutex.acquire()
    
    #SYN
    sendp(Ether()/IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, seq=nSeq, flags='S'), iface=ifc, verbose=False)
    mutex.acquire()
    sendp(Ether()/IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, seq=nSeq+1, ack=1, flags='A'), iface=ifc, verbose=False)
    
    dparts = [data[i:i+8] for i in range(0, len(data), 8)]
    dparts[-1] = dparts[-1].ljust(8, b'\x00')
    
    #PSH+ACK
    sendp(Ether()/IP(dst=dst_ip, tos=0, id=len(data))/TCP(sport=src_port, dport=dst_port, seq=nSeq+1, ack=1, flags='PA', options=[('NOP', None), ('NOP', None), ('Timestamp', dparts[0])])/'\x00', iface=ifc, verbose=False)
    mutex.acquire()
    
    it = 2
    
    for dpart in dparts[1:]:
        sendp(Ether()/IP(dst=dst_ip, tos=1, id=it-1)/TCP(sport=src_port, dport=dst_port, seq=nSeq+it, ack=1, flags='PA', options=[('NOP', None), ('NOP', None), ('Timestamp', dparts[it-1])])/'\x00', iface=ifc, verbose=False)
        mutex.acquire()
        it += 1
    
    #FIN+ACK
    sendp(Ether()/IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, seq=nSeq+it, ack=1, flags='FA'), iface=ifc, verbose=False)
    mutex.acquire()
    sendp(Ether()/IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, seq=nSeq+it+1, ack=2, flags='A'), iface=ifc, verbose=False)
    
    t.stop()


if __name__ == "__main__":
    print("Найдено интерфейсов:", len(IFACES))
    print(IFACES)
    ifind = input("Index интерфейса: ")

    try:
        ifc = dev_from_index(int(ifind))
    except Exception as e:
        print(e)
        exit()
        
    global dst_ip
    dst_ip = input('IP получателя > ').strip()
    
    key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10'
    
    while True:
        data = bytes(input('Сообщение > '), 'utf-8')
        
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            ctext = cipher.encrypt(data.ljust(len(data.ljust(8, b'\x00')) // 8 * 8 + 8, b'\x00'))
            send_data(dst_ip, ifc, ctext)
        except Exception as e:
            print(e)
    