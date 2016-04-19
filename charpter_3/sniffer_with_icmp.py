# -*- coding:utf-8 -*-

import socket
import os
import struct
from ctypes import *

host = socket.gethostbyname(socket.gethostname())
# host = '192.168.1.109'
print host

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
            self.protocol = self.protocol_map[self.protocol_num]


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

try:
    while True:
        # 读取数据包
        raw_buffer = sniffer.recvfrom(65565)[0]

        # 将缓冲区前20字节按IP头进行解析
        ip_header = IP(raw_buffer[0:20])

        # # 输出协议和通信双方IP地址
        # print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)

        if ip_header.protocol == "ICMP":

            print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)

            # 计算ICMP包的起始位置
            offset = ip_header.ihl * 4     # ihl是头长度，报头长度为该字段*4字节
            buf = raw_buffer[offset: offset + sizeof(ICMP)]

            # 解析ICMP数据
            icmp_header = ICMP(buf)

            print "ICMP -> type: %d Code: %d" % (icmp_header.type, icmp_header.code)


# 处理CTRL+ C
except KeyboardInterrupt:
    if is_windows:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
