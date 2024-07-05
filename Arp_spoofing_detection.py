from scapy.all import *
import pandas as pd
import logging
import sys
from time import sleep

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

arp_table = pd.DataFrame(columns=['IP', 'MAC'])
alerted_hosts = set()

def arp_spoof_detector(packet):
    if ARP in packet and packet[ARP].op in (1, 2):
        arp_src_mac = packet[ARP].hwsrc
        arp_src_ip = packet[ARP].psrc

        if arp_src_ip in arp_table.index:
            known_mac = arp_table.loc[arp_src_ip]['MAC']
            if known_mac != arp_src_mac and arp_src_ip not in alerted_hosts:
                print(f"{colors.WARNING}{colors.BOLD}[!] ALERT: ARP Spoofing detected!{colors.ENDC}")
                print(f"{colors.WARNING}IP:{colors.ENDC} {arp_src_ip}")
                print(f"{colors.WARNING}Real MAC:{colors.ENDC} {known_mac}")
                print(f"{colors.WARNING}Fake MAC:{colors.ENDC} {arp_src_mac}")
                alerted_hosts.add(arp_src_ip)

                print(f"    {colors.HEADER}{colors.BOLD}[Choose an action]{colors.ENDC}")
                action = input(f"    {colors.OKGREEN}[B]lock{colors.ENDC} or {colors.WARNING}[I]gnore{colors.ENDC}: ").strip().lower()
                if action == 'b':
                    print(f"    {colors.WARNING}Blocking traffic from {arp_src_ip}...{colors.ENDC}")
                elif action == 'i':
                    print(f"    {colors.OKGREEN}Ignoring the alert.{colors.ENDC}")
                else:
                    print(f"    {colors.FAIL}Invalid option, ignoring the alert.{colors.ENDC}")

        elif arp_src_mac in arp_table['MAC'].values:
            conflicting_ips = arp_table[arp_table['MAC'] == arp_src_mac].index.tolist()
            print(f"{colors.WARNING}{colors.BOLD}[!] ALERT: New device with duplicate MAC detected!{colors.ENDC}")
            print(f"{colors.WARNING}IPs involved:{colors.ENDC} {conflicting_ips + [arp_src_ip]}")
            print(f"{colors.WARNING}MAC:{colors.ENDC} {arp_src_mac}")

            arp_table.loc[arp_src_ip] = pd.Series({'MAC': arp_src_mac})
            print(f"{colors.OKGREEN}[+] Added to ARP table: IP: {arp_src_ip}, MAC: {arp_src_mac}{colors.ENDC}")

        else:
            arp_table.loc[arp_src_ip] = pd.Series({'MAC': arp_src_mac})
            print(f"{colors.OKGREEN}[+] Added to ARP table: IP: {arp_src_ip}, MAC: {arp_src_mac}{colors.ENDC}")

    progress_chars = [
        "⠋",  
        "⠙",
        "⠹",  
        "⠸",  
    ]
    for char in progress_chars:
        print(char, end='', flush=True)
        time.sleep(0.3) 
        print('\b' * len(char), end='')

def main():
    print(f"{colors.HEADER}{colors.BOLD}ARP Spoof Detection Tool{colors.ENDC}")
    print("------------------------")
    print(f"{colors.OKBLUE}Starting packet sniffing...{colors.ENDC}")

    sniff(filter="arp", prn=arp_spoof_detector, store=0)

if __name__ == "__main__":
    main()
