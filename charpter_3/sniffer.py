# -*- coding:utf-8 -*-

import os
import socket

# host = "192.168.0.109"
host = socket.gethostbyname(socket.gethostname())
is_windows = False
if os.name == "nt":
    is_windows = True

# windows平台使用IP协议
if is_windows:
    socket_protocol = socket.IPPROTO_IP
# 其他平台使用ICMP协议
else:
    socket_protocol = socket.IPPROTO_ICMP

# 创建基于协议的socket
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

# 绑定到公共端口
sniffer.bind((host, 0))

# 包含IP头部
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# windows平台上，设置IOCTL启用混杂模式
if is_windows:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# 读取单个数据包
print sniffer.recvfrom(65565)

# 在windows上关闭混杂模式
if is_windows:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


