from scapy.all import *
# Read the capture file
pkts = rdpcap("capture5052.pcapng")
# Total number of packets
print("Number of packets:", len(pkts))
# Number of unique source IPs
src_ips = set(pkt[IP].src for pkt in pkts if IP in pkt)
print("Number of source IPs:", len(src_ips))
# Number of unique destination IPs
dst_ips = set(pkt[IP].dst for pkt in pkts if IP in pkt)
print("Number of destination IPs:", len(dst_ips))
# Number of protocols used
protocols = set(pkt.lastlayer().name for pkt in pkts)
print("Number of protocols used:", len(protocols))
# Count packets per protocol
proto_count = {}
for pkt in pkts:
   proto = pkt.lastlayer().name
   proto_count[proto] = proto_count.get(proto, 0) + 1
print("\nPackets per protocol:")
for proto, count in proto_count.items():
   print(f"{proto}: {count}")
