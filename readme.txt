import socket
import struct
from scapy.all import *


# arp头部结构
class ARPHeader(Packet):
    name = "ARPHeader"
    fields_desc = [
        ShortField("hardware_type", 0),
        ShortField("protocol_type", 0),
        ByteField("hardware_add_len", 0),
        ByteField("protocol_add_len", 0),
        ShortField("operation_field", 0),
        MACField("source_mac_add", "00:00:00:00:00:00"),
        IPField("source_ip_add", "0.0.0.0"),
        MACField("dest_mac_add", "00:00:00:00:00:00"),
        IPField("dest_ip_add", "0.0.0.0"),
    ]


# 以太网帧结构
class EthernetHeader(Packet):
    name = "EthernetHeader"
    fields_desc = [
        MACField("dest_mac_add", "00:00:00:00:00:00"),
        MACField("source_mac_add", "00:00:00:00:00:00"),
        ShortField("type", 0),
    ]


# ARP最终包结构
class ARPPacket(Packet):
    name = "ARPPacket"
    fields_desc = [
        EthernetHeader(),
        ARPHeader(),
    ]


# 获取本机IP地址和MAC地址
def get_self_ip_mac():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    mac = hex(uuid.getnode())[2:]
    mac = ":".join(mac[i:i+2] for i in range(0, len(mac), 2))
    return ip, mac


# 构建ARP请求包
def build_arp_request(source_ip, source_mac, dest_ip):
    ether = EthernetHeader(dest_mac_add="ff:ff:ff:ff:ff:ff", source_mac_add=source_mac, type=0x0806)
    arp = ARPHeader(hardware_type=1, protocol_type=0x0800, hardware_add_len=6, protocol_add_len=4,
                    operation_field=1, source_mac_add=source_mac, source_ip_add=source_ip,
                    dest_mac_add="00:00:00:00:00:00", dest_ip_add=dest_ip)
    packet = ether / arp
    return packet


# 发送ARP请求包
def send_arp_request(packet, iface):
    sendp(packet, iface=iface, verbose=False)


# 分析捕获的数据包，获取活动主机的IP地址和MAC地址
def analyze_packet(packet):
    if packet.haslayer(ARPPacket):
        arp = packet[ARPPacket].payload
        if arp.operation_field == 2:
            ip = arp.source_ip_add
            mac = arp.source_mac_add
            print("IP地址: {}\tMAC地址: {}".format(ip, mac))


def main():
    # 获取本机IP地址和MAC地址
    ip, mac = get_self_ip_mac()

    # 构建ARP请求包
    packet = build_arp_request(ip, mac, "192.168.0.1")

    # 发送ARP请求包
    send_arp_request(packet, "eth0")

    # 开始捕获数据包并进行分析
    sniff(prn=analyze_packet, filter="arp", store=0)


if __name__ == "__main__":
    main()


