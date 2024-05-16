# Arper
The provided code is a Python script that performs an ARP poisoning attack on a target machine within a local network. It utilizes the Scapy library for crafting and sending ARP packets, as well as for sniffing network traffic.

## 1. Importing necessary modules:
    - `from scapy.all import *`: Imports all necessary modules from the Scapy library.
    - `import os`: Imports the 'os' module for accessing operating system functionalities.
    - `import sys`: Imports the 'sys' module for system-specific parameters and functions.
    - `import threading`: Imports the 'threading' module for implementing multi-threading capabilities.
    - `import signal`: Imports the 'signal' module for handling signals.

## 2. Setting up variables:
    - `interface = ""`: Specifies the network interface to be used for sending and receiving packets.
    - `target_ip = ""`: Specifies the IP address of the target machine.
    - `gateway_ip = ""`: Specifies the IP address of the gateway/router.
    - `packet_count = 1000`: Specifies the number of packets to sniff.

## 3. Configuring Scapy:
    - `conf.iface = interface`: Sets the network interface to be used by Scapy.
    - `conf.verb = 0`: Sets the verbosity level of Scapy to 0 (suppressing output).

## 4. Defining functions:
    - `restore_target(gateway_ip, gateway_mac, target_ip, target_mac)`: Restores the ARP tables of the target machine and the gateway/router.
    - `poison_target(gateway_ip, gateway_mac, target_ip, target_mac)`: Conducts ARP poisoning by continuously sending malicious ARP packets.

## 5. ARP Poisoning Attack:
    - The script obtains the MAC addresses of the gateway and target machines.
    - It then starts a thread to execute the ARP poisoning attack.
    - Meanwhile, it initiates a packet sniffing process to capture network traffic involving the target machine.

## 6. Packet Sniffing:
    - The script uses a BPF (Berkeley Packet Filter) filter to capture packets involving the target IP address.
    - Sniffed packets are stored in a PCAP file named 'arper.pcap'.

## 7. Exception Handling:
    - The script handles keyboard interrupts (Ctrl+C) to gracefully terminate the ARP poisoning attack and restore the network configuration.
