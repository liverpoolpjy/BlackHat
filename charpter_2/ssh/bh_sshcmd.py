# -*- coding:utf-8 -*-

import threading
import paramiko
import subprocess


def ssh_command(ip, user, passwd, command):
    client = paramiko.SSHClient()

    # 建议现实环境用ssh密钥
    # client.load_host_keys('/home/jiayi/.shh/konw_hosts')

    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=passwd)

    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.exec_command(command)
        print ssh_session.recv(1024)
    return

ssh_command('120.26.121.101', 'root', '*', 'id')
