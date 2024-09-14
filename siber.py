from scapy.all import *

packet = IP(dst="192.168.43.30")/TCP(dport=80)

# Paketleri sürekli gönder
send(packet, count=1000)
