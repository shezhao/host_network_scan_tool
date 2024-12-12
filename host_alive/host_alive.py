# 基于scapy库
# 构造SYN数据包和ICMP数据包
# 检测目标主机是否存活

from time import sleep
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.all import *
import sys
import threading
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # 导出报错信息

# if len(sys.argv) != 4:  # python scan_tool_name.py 127.0.0.1 1 100
#     print("Usage: %s target start_port end_port" % (sys.argv[0]))  # python scan_tool.py IP start_port end_port
#     sys.exit(0)
# target = str(sys.argv[1])
# start_port = int(sys.argv[2])
# end_port = int(sys.argv[3])

# 设置一个全局标志
stop_scanning = False
# target = "localhost"
start_port = 1
end_port = 10000


def alive_icmp(target):
    ans, un_ans = sr(IP(dst=target) / ICMP(), timeout=1)
    for s, r in ans:
        print(r.sprintf("%IP.src% is alive"))


# open_ports = []
# lock = threading.Lock()  # 创建一个锁对象


def alive_syn(target):
    global stop_scanning

    def port_scan(port):
        global stop_scanning
        if not stop_scanning:
            # 以下是扫描端口的现有代码
            packet = IP(dst=target) / TCP(dport=port, flags="S")  # 构造TCP数据包，TCP标志位为SYN
            response = sr1(packet, timeout=0.5, verbose=0)

            # 检查是否接收到响应、响应是否包含TCP层，并且TCP标志位是否为ACK+SYN（0x12）
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                print("\n" + target + " 存活且回应端口 " + str(port))
                stop_scanning = True
                print("Scan will be over!!!")
                # open_ports.append(port)
                # sr(IP(dst=target) / TCP(dport=response.sport, flags="R"), timeout=0.5, verbose=0)  # 构造一个复位（RST）数据包
        else:
            sleep(0.5)
            print("扫描停止")
            return

    threads = []  # 初始化
    scan_port_num = 0
    for port in range(start_port, end_port):
        if not stop_scanning:
            thread = threading.Thread(target=port_scan, args=(port,))
            threads.append(thread)
            scan_port_num += 1
            thread.start()
        else:
            break

    for thread in threads:
        thread.join()
    # if not open_ports:
    #     print("ALL ports are unclear!!!")
    # else:
    #     print("Open ports: ", open_ports)


def alive_arp(target):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target, timeout=2)
    ans, un_ans = srp(pkt, timeout=1)
    for s, r in ans:
        print("sucess")
        print(r.sprintf("%Ether.src% - %ARP.psrc%"))


def menu():
    target = input("please input IP or DNS(eg.172.27.128.1 or github.com):")
    try:
        print("1.icmp")
        print("2.syn")
        print("3.arp")
        print("0.exit")
        cho = int(input("please switch one:"))
        if cho == 1:
            alive_icmp(target)
        elif cho == 2:
            alive_syn(target)
        elif cho == 3:
            alive_arp(target)
        elif cho == 0:
            sys.exit()
    except Exception as e:
        print(e)


menu()
