from scapy.all import *
import random
import time

# Hedef IP ve port
target_ip = '192.168.1.100'  # Hedef cihazın IP adresi
target_port = 80  # Örneğin HTTP için standart port

# Gönderilecek veri
data_payload = "Merhaba, bu sahte bir veri paketidir."

def send_data_packet():
    src_ip = "192.168.1." + str(random.randint(2, 254))  # Rastgele kaynak IP
    src_port = random.randint(1024, 65535)  # Rastgele kaynak port

    # TCP üçlü el sıkışma (3-way handshake)
    ip_layer = IP(src=src_ip, dst=target_ip)
    syn_packet = ip_layer / TCP(sport=src_port, dport=target_port, flags='S', seq=1000)
    syn_ack = sr1(syn_packet, timeout=1, verbose=0)

    if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags & 0x12:
        ack_packet = ip_layer / TCP(sport=src_port, dport=target_port, flags='A', seq=1001, ack=syn_ack.seq + 1)
        send(ack_packet, verbose=0)

        # Veri gönderimi (PSH, ACK bayrakları ile)
        push_packet = ip_layer / TCP(sport=src_port, dport=target_port, flags='PA', seq=1001, ack=syn_ack.seq + 1) / data_payload
        send(push_packet, verbose=0)

        # Bağlantıyı sonlandırma
        fin_packet = ip_layer / TCP(sport=src_port, dport=target_port, flags='FA', seq=1001 + len(data_payload), ack=syn_ack.seq + 1)
        fin_ack = sr1(fin_packet, timeout=1, verbose=0)

        if fin_ack and fin_ack.haslayer(TCP) and fin_ack[TCP].flags & 0x11:
            last_ack = ip_layer / TCP(sport=src_port, dport=target_port, flags='A', seq=fin_packet.seq + 1, ack=fin_ack.seq + 1)
            send(last_ack, verbose=0)
    else:
        print("Bağlantı kurulamadı veya hedef cevap vermedi.")

# Belirli aralıklarla veri paketleri gönderme
try:
    while True:
        send_data_packet()
        time.sleep(random.uniform(1, 3))  # Paketler arası bekleme süresi
except KeyboardInterrupt:
    print("Paket gönderimi durduruldu.")
