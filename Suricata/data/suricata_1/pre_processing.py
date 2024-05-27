from scapy.all import *
from scapy.contrib.gtp import GTP_U_Header  # Ensure to import the correct GTP module
from scapy.layers.l2 import Ether

def process_packet(packet):
    """
    Process each packet that has GTP layer
    """
    if packet.haslayer(GTP_U_Header):
        # Extract the inner IP packet
        inner_ip = packet[GTP_U_Header].payload

        # Prepare the packet for injection by adding an Ethernet header
        new_packet = Ether() / inner_ip

        # Ensure the new packet has correct Ethernet type for IP
        new_packet.type = 0x0800  # This is the Ethernet type for IPv4

        # Send the reconstructed packet
        sendp(new_packet, iface="dummy0", verbose=False)

        # Optionally print packet details
        print(f"Sent packet from {new_packet[IP].src} to {new_packet[IP].dst} on dummy0")

def main():
    # Adjust 'iface' to your specific listening interface
    sniff(iface="vxlan0", prn=process_packet, filter="udp port 2152", store=False)

if __name__ == "__main__":
    main()
