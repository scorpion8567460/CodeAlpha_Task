from scapy.all import *

# Define the packet capture callback function
def packet_callback(packet):
    print(packet.summary())  # Print the packet summary

    # You can filter specific types of packets if needed
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}")

# Define the sniffing function
def start_sniffing(interface):
    print(f"Starting to sniff on {interface}...")
    # Capture packets and store them in the 'packets' variable
    packets = sniff(iface=interface, store=True, prn=packet_callback, count=100)  # Capture 100 packets
    
    # After sniffing is done, write packets to a PCAP file
    wrpcap('C:/Users/shoai/Desktop/sniffer/captured_packets.pcap', packets)
    print("Packets saved to 'captured_packets.pcap'")

# Main
if __name__ == "__main__":
    interface = input("Enter the network interface to sniff on (e.g., WiFi 2): ")
    start_sniffing(interface)
