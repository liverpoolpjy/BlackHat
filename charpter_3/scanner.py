# -*- coding:utf-8 -*-

import socket
import os
import struct
from ctypes import *
import threading
import time
from netaddr import IPNetwork, IPAddress
from get_ip import get_lan_ip

# host = socket.gethostbyname(socket.gethostname())
host = get_lan_ip()
print "shut down windows firewall!"
print "local ip is %s" % host
print "-----------------"


subnet = "192.168.1.0/24"

# 校验字符串
magic_message = "PYTHONRULES"


# 批量发送UDP数据包
def udp_sender(sub_net, message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(sub_net):
        try:
            sender.sendto(message, ("%s" % ip, 65212))
        except:
            pass

is_windows = False
if os.name == "nt":
    is_windows = True


# IP头定义
class IP(Structure):
    _fields_ = [
        ("ihl",        c_ubyte, 4),
        ("version",    c_ubyte, 4),
        ("tos",        c_ubyte),
        ("len",        c_ushort),
        ("id",         c_ushort),
        ("offset",     c_ushort),
        ("ttl",        c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum",        c_ushort),
        ("src",        c_ulong),
        ("dst",        c_ulong),
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # 协议字段与协议名称对应
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # 可读性更强的ip地址
        # socket.inet_ntoa 将ipv4地址转化成点分十进制地址
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # 协议类型
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):
    _fields_ = [
        ("type",        c_ubyte),
        ("code",        c_ubyte),
        ("checksum",    c_ushort),
        ("unused",      c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


if is_windows:
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if is_windows:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# 发送数据包
t = threading.Thread(target=udp_sender, args=(subnet, magic_message))
t.start()


try:
    while True:
        # 读取数据包
        raw_buffer = sniffer.recvfrom(65535)[0]

        # 将缓冲区前20字节按IP头进行解析
        ip_header = IP(raw_buffer[0:20])

        if ip_header.protocol == "ICMP":
            offset = ip_header.ihl * 4     # ihl是头长度，报头长度为该字段*4字节
            buf = raw_buffer[offset: offset + sizeof(ICMP)]

            # 解析ICMP数据
            icmp_header = ICMP(buf)

            if icmp_header.code == 3 and icmp_header.type == 3:

                # 确认相应主机在子网内
                if IPAddress(ip_header.src_address) in IPNetwork(subnet):

                    # 确认ICMP包含有校验字符串
                    if raw_buffer[len(raw_buffer) - len(magic_message):] == magic_message:
                        print "Host Up: %s" % ip_header.src_address


# 处理CTRL+ C
except KeyboardInterrupt, e:
    if is_windows:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    print str(e)
