from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        # Determine the protocol name
        protocol_name = "Unknown"
        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"
        elif proto == 1:
            protocol_name = "ICMP"

        print(f"\n[+] New Packet: {src_ip} -> {dst_ip} | Protocol: {protocol_name}")

        # Extract Payload if TCP or UDP
        if packet.haslayer(TCP):
            payload = packet[TCP].payload
            if payload:
                print(f"    [TCP Payload Preview]: {bytes(payload)[:50]}")
                
        elif packet.haslayer(UDP):
            payload = packet[UDP].payload
            if payload:
                print(f"    [UDP Payload Preview]: {bytes(payload)[:50]}")

def main():
    print("=== CodeAlpha Basic Network Sniffer ===")
    print("Starting packet capture... Press Ctrl+C to stop.")
    
    # sniff() starts capturing network traffic. 
    # prn specifies the callback function to run on each packet.
    # store=0 ensures packets aren't kept in memory (prevents high RAM usage)
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()