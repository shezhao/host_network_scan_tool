from scapy.layers.inet import *
from scapy.all import *
import sys
import threading
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # 导出报错信息

if len(sys.argv) != 4:  # python scan_tool_name.py 127.0.0.1 1 100
    print("Usage: %s target start_port end_port" % (sys.argv[0]))  # python port_scan.py IP start_port end_port
    sys.exit(0)
target = str(sys.argv[1])
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

print("Scanning " + target + " for open Tcp ports\n")

if start_port == end_port:
    end_port += 1

open_ports = []  # 初始化


def scan_port(port):
    packet = IP(dst=target) / TCP(dport=port, flags="S")  # 构造TCP数据包，TCP标志位为SYN
    response = sr1(packet, timeout=0.5, verbose=0)

    # 检查是否接收到响应、响应是否包含TCP层，并且TCP标志位是否为ACK+SYN（0x12）
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        open_ports.append(port)
        sr(IP(dst=target) / TCP(dport=response.sport, flags="R"), timeout=0.5, verbose=0)  # 构造一个复位（RST）数据包


# 采用多线程提高效率
# for i in range(start_port, end_port):
#     packet = IP(dst=target)/TCP(dport=i, flags="S")
#     response = sr1(packet, timeout=0.5, verbose=0)
#     if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
#         print("port "+str(i)+" is open")
#         sr(IP(dst=target)/TCP(dport=response.sport, flags="R"), timeout=0.5, verbose = 0)

threads = []  # 初始化

for port in range(start_port, end_port):
    thread = threading.Thread(target=scan_port, args=(port,))
    threads.append(thread)
    if port % 100 == 0:
        print('loading... 完成:' + str(port - start_port + 1) + " 个端口扫描")
    thread.start()

for thread in threads:
    thread.join()
if not open_ports:
    print("ALL ports are unclear!!!")
else:
    print("Open ports: ", open_ports)

print("Scan is over!!!\n")
