import scapy.all as scapy
import argparse
import socket
import time
import threading

print("-" * 50)
print("| NETWORK SCANNER |")
print("-" * 50)

start_time = time.time()

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="specify target ip or ip range")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet / arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    client_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

    return client_list

def print_results(scan_list):
    print("  IP\t\t\t\tMAC\n--------------------------------")
    for client in scan_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
result_list = scan(options.target)

if result_list:
    print_results(result_list)
else:
    print("NO IP ADDRESS FOUND")
    print("-" * 50)
    exit()

print("-" * 50)

usage = input("ENTER TARGET IP: ")
tar2 = socket.gethostbyname(str(usage))
print("-" * 50)
print("SCANNING TARGET IP......")
print("-" * 50)
print("[The 1020 ports scanned but not shown below are in state: closed]")
print("")

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM_)
    s.settimeout(0.5)
    conn = s.connect_ex((tar2, port))

    if not conn:
        print("PORT {} is Open".format(port))

for port in range(1, 1021):  # Changed the range to scan up to port 1020
    thread = threading.Thread(target=scan_port, args=(port,))
    thread.start()

end_time = time.time()
print("")
print("         [SCAN DURATION:", round(end_time - start_time), "Sec]")
print("-" * 50)