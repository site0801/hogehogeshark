#-*- coding:utf-8 -*-
import sys
from socket import *

def main(interface):
    ETH_P_IP = 0x800
    ETH_P_ARP = 0x806
    #socket()を作成する
    sock = socket(PF_PACKET, SOCK_RAW, ETH_P_IP)
    sock.bind((interface, ETH_P_IP))
    while True:
        i = 0
        j = 0
        count = 1
        packet = sock.recv(4096)
        packet_analyze(packet)
        #packet_len = len(packet)
        #dst = ":".join(["%02x" % x for x in packet[0:6]])
        #src = ":".join(["%02x" % x for x in packet[6:12]])
        #type = ntohs(ord(packet[12:13]))
        #print("src:%s > dst:%s, ethertype:%04x, length:%d" % (src, dst, type, packet_len))
        '''
        #Binary save "data*"
        with open("data" + str(i), "wb") as fout:
            packet = bytearray(packet)
            packet.append(0)
            packet.extend([1, 127])
            fout.write(packet)
        '''
        #packet内にあるバイナリを16進に変換する(wiresharkの下に表示されてるような感じになる。)
        packet = packet.hex()
        
        ##show clear UI
        for (i,j) in zip(packet[::2], packet[1::2]):
            if count % 16 == 0 and count != 0:
                print(i+j)
            elif count % 8 == 0 and count % 16 != 0:
                print(i+j, end="")
                print("  ", end=" ")
            else:
                print(i+j, end=" ")
            count += 1
        print("")
        print("")

def packet_analyze(packet):
    eth_dst = ":".join(["%02x" % x for x in packet[:6]])
    eth_src = ":".join(["%02x" % x for x in packet[6:12]])
    eth_type = ntohs(ord(packet[12:13]))
    packet_len = len(packet)
    packet = packet.hex()
    ip_ver = packet[28]
    #ipのverを確認する
    if ip_ver == "4":
        ip_ver = "IPv4"
    elif ip_ver == "6":
        ip_ver = "IPv6"
    else:
        print("IPverがおかしいです。¥n確認してください。")
    #ip_lengthは"変数*４"した数字が本来のバイト数となる(通信量節約のため)
    ip_length = packet[29]
    ip_length = int(ip_length) *4
    print("src:%s > dst:%s, ethertype:%04x, length:%d" % (eth_src, eth_dst, eth_type , packet_len))
    print("ip_ver:%s, ip_length:%dByte" % (ip_ver, ip_length))
    print(type(ip_length))
    print(ip_length)

if __name__ == '__main__':
    argvs = sys.argv
    argc = len(argvs)

    if argc != 2:
      print("Please confirm argument")
      sys.exit()
    interface = argvs[1]
    main(interface)

