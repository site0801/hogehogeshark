#-*- coding:utf-8 -*-
import sys
from socket import *
ETH_P_IP = 0x800
ETH_P_ARP = 0x806


def main(interface):
    #socket()を作成する
    sock = socket(PF_PACKET, SOCK_RAW, ETH_P_IP)
    sock.bind((interface, ETH_P_IP))
    while True:
        i = 0
        j = 0
        count = 1
        packet = sock.recv(4096)
        #packet_analyze(packet)
        eth_analyze(packet)
        packet = packet.hex()
        print("[Binary]")
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

def eth_analyze(packet):
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
    #出力
    print("[Ethernet Header]")
    print("src:%s >>> dst:%s\nethertype:%04x, length:%d" % (eth_src, eth_dst, eth_type , packet_len))
    #eth_typeの結果からこれ以降が何かを判断して処理を投げる  
    if eth_type == 0x0800:
       ip_analyze(packet)
    elif eth_type == 0x0806:
       arp_analyze(packet)
    elif eth_type == 0x86DD:
       ipv6_analyze(packet)
    else:
        print("このパケットのEthernetHeaderのtypeの数値が異常か対応していない数値です。\n確認してください")
        print(type(eth_type))

def ip_analyze(packet):
    #[IP_Header]
    #IP version
    ip_ver = packet[28]
    if ip_ver == "4":
        ip_ver = "IPv4"
    elif ip_ver == "6":
        ip_ver = "IPv6"
    else:
        print("IP_verがおかしいか対応していないバージョンです。¥n確認してください。")
    #IP Header length
    #ip_lengthは"変数*４"した数字が本来のバイト数となる(通信量節約のためそういう仕様らしい)
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
    ip_ttl = packet[44:46]
    #Next_Header_Protocol
    ##[01:ICMP, 06:TCP, 17:UDP, else:not support protocol]
    ip_protocol = packet[46:48]
    #Header Checksum
    ip_checksum = packet[48:52]
    #Source IP Address
    ip_src_oct1 = int(packet[52:54], 16)
    ip_src_oct2 = int(packet[54:56], 16)
    ip_src_oct3 = int(packet[56:58], 16)
    ip_src_oct4 = int(packet[58:60], 16)
    #Destination IP Address
    ip_dst_oct1 = int(packet[60:62], 16)
    ip_dst_oct2 = int(packet[62:64], 16)
    ip_dst_oct3 = int(packet[64:66], 16)
    ip_dst_oct4 = int(packet[66:68], 16)         
    #出力
    print("[IP Header]")
    print("ver:%s, head_length:%dByte, ToS:%s" % (ip_ver, ip_head_len, ip_tos))
    print("total_length:%s, identification:%s" % (ip_total_len, ip_id))
    print("flags:%s, flagment_offset:%s" % (ip_flag, ip_flag_offset))
    print("TTL:%s, Next_Header_Protocol:%s, Checksum:%s" % (ip_ttl, ip_protocol, ip_checksum))
    print("src:%s.%s.%s.%s >>> dst:%s.%s.%s.%s" % (ip_src_oct1, ip_src_oct2, ip_src_oct3, ip_src_oct4, ip_dst_oct1, ip_dst_oct2, ip_dst_oct3, ip_dst_oct4))
    #ip_protocol毎に行う処理
    ##[01:ICMP, 06:TCP, 17:UDP, else:not support protocol]
    if ip_protocol == "01":
        icmp_analyze(packet)
    elif ip_protocol == "06":
        tcp_analyze(packet)
    elif ip_protocol == "17":
        udp_analyze(packet)
    else:
        print("not support Layer4 protocol.\nごめんなさい！")

def arp_analyze(packet):
    print("arp解析は現在工事中！\nごめんなさい！")

def ipv6_analyze(packet):
    print("ipv6解析は現在工事中！\nごめんなさい！")

def icmp_analyze(packet):
    #icmp_type
    icmp_type = packet[68:70]
    #icmp_code
    icmp_code = packet[70:72]
    #icmp_checksum
    icmp_checksum = packet[72:76]
    #icmp_id
    icmp_id = packet[76:80]
    #icmp_seq
    icmp_seq = packet[80:84]
    #icmp_data
    icmp_data = packet[84:]
    #出力
    print("[ICMP Header]")
    print("type:%s, code:%s, checksum:%s" % (icmp_type, icmp_code, icmp_checksum))
    if icmp_type == "00" or icmp_type == "08":
        print("id:%s, sequenece:%s" % (icmp_id, icmp_seq))
        print("[ICMP Data]")
        print("data:%s" % icmp_data)
    else:
        print("")

def tcp_analyze(packet):
    print("tcp解析は現在工事中！\nごめんなさい！")

def udp_analyze(packet):
    print("udp解析は現在工事中！\nごめんなさい！")

if __name__ == '__main__':
    argvs = sys.argv
    argc = len(argvs)
    if argc != 2:
      print("Please confirm argument")
      sys.exit()
    interface = argvs[1]
    main(interface)
