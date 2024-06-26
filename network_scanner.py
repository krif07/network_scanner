#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    return parser.parse_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answer_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answer_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(result_list):
    print("---------------------------------------------------------")
    print("IP\t\t\tMAC Address")
    print("---------------------------------------------------------")

    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])
    print("---------------------------------------------------------")


options = get_arguments()
c_list = scan(options.target)
print_result(c_list)
#c_list = scan("192.168.164.1/24")
