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
        '''
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
    #packet_length
    packet_len = len(packet)
    #Destination MAC Address
    eth_dst = ":".join(["%02x" % x for x in packet[:6]])
    #Source MAC Address
    eth_src = ":".join(["%02x" % x for x in packet[6:12]])
    #Ethernet Type
    ##EthernetHeaderのあとに何が続くかを示す
    eth_type = ntohs(ord(packet[12:13]))
    #packetのデータを16進数化
    packet = packet.hex()
    #IP version
    ip_ver = packet[28]
    if ip_ver == "4":
        ip_ver = "IPv4"
    elif ip_ver == "6":
        ip_ver = "IPv6"
    else:
        print("IP_verがおかしいです。¥n確認してください。")
    #IP Header length
    #ip_lengthは"変数*４"した数字が本来のバイト数となる(通信量節約のため)
    ip_head_len = packet[29]
    ip_head_len = int(ip_head_len) *4
    #Type of Service
    ip_tos = packet[30:32]
    #Total Length
    ip_total_len = packet[32:36]
    #Identification
    ip_id = packet[36:40]
    #Flags
    ip_flag = packet[40]
    #Flagment offset
    ip_flag_offset = packet[41:44]
    #TTL
    ip_ttl = packet[44]
    #Next_Header_Protocol
    ip_protocol = packet[45]
    #Header Checksum
    ip_checksum = packet[46:50]
    #Source IP Address
    #Destination IP Address



    
    #出力
    print("[Ethernet Header]")
    print("src:%s >>> dst:%s\nethertype:%04x, length:%d" % (eth_src, eth_dst, eth_type , packet_len))
    print("[IP Header]")
    print("ver:%s, head_length:%dByte, ToS:%s" % (ip_ver, ip_head_len, ip_tos))
    print("total_length:%s, identification:%s" % (ip_total_len, ip_id))
    print("flags:%s, flagment_offset:%s" % (ip_flag, ip_flag_offset))
    print("TTL:%s, Next_Header_Protocol:%s, Checksum:%s" % (ip_ttl, ip_protocol, ip_checksum))
    #print("src:%s >>> dst:%s" % (ip_src, ip_dst))
    print("[Binary]")


if __name__ == '__main__':
    argvs = sys.argv
    argc = len(argvs)
    if argc != 2:
      print("Please confirm argument")
      sys.exit()
    interface = argvs[1]
    main(interface)
