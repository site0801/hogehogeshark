import sys
from socket import *

def main():
    i = 0
    ETH_P_IP = 0x800
    interface = "enp0s9"
    sock = socket(PF_PACKET, SOCK_RAW, ETH_P_IP)
    sock.bind((interface, ETH_P_IP))
    while True:
        packet = sock.recv(4096)
        packet_len = len(packet)
        print(packet)
        print("packet_len:" + str(packet_len))
        print("")
        i += 1
        
        '''
        with open("data" + str(i), "wb") as fout:
            packet = bytearray(packet)
            packet.append(0)
            packet.extend([1, 127])
            fout.write(packet)
        '''
        src = ":".join(["%02x" % ord(x) for x in packet[0:6]])
        dst = ":".join(["%02x" % ord(x) for x in packet[6:12]])
        type = ntohs(ord(packet[12:13]))
        print("%s > %s, ethertype %04x, length %d" % (src, dst, type, packet_len))

if __name__ == '__main__':
    main()
