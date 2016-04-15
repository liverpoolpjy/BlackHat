# -*- coding:utf-8 -*-
import socket
import threading

bind_ip = "0.0.0.0"
bind_port = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((bind_ip, bind_port))

server.listen(5)
print "[*] Listening on %s:%d" % (bind_ip, bind_port)


def handle_client(client_socket, client_addr):
    request = client_socket.recv(1024)

    print "[*] Received %s" % request

    print "[*] Accepted connection from: %s:%d" % (client_addr[0], client_addr[1])

    client_socket.send("ACK!")
    client_socket.close()

while True:
    client, addr = server.accept()  # accept函数等待并返回一个一个sockect连接，和一个套接字数组

    client_handler = threading.Thread(target=handle_client, args=(client, addr))  # 这里args参数会传递到handle_client里
    client_handler.start()
