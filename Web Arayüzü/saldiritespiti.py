from scapy.all import sniff, Dot11, ARP, IP, ICMP, UDP, TCP, Ether, DHCP
import os
import json
from collections import defaultdict
import time
import queue

# Global Queue nesnesi
attack_queue = queue.Queue()

# Engellenmiş IP ve MAC adresleri
blocked_ips = set()
blocked_macs = set()

# Sayaçlar
attack_counters = defaultdict(int)
mac_counters = defaultdict(int)

# Log dosyası
LOG_FILE = "attack_logs.json"

# Loglama fonksiyonu
def log_attack(ip_address=None, mac_address=None, attack_type=None, details=None, interface=None):
    log_entry = {
        "timestamp": time.ctime(),
        "ip_address": ip_address,
        "mac_address": mac_address,
        "attack_type": attack_type,
        "details": details,
        "interface": interface
    }
    with open(LOG_FILE, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")
    print(f"[LOG] {json.dumps(log_entry, indent=4)}")

# IP engelleme
def block_ip(ip_address, reason):
    if ip_address not in blocked_ips:
        blocked_ips.add(ip_address)
        print(f"[+] IP Engelleniyor: {ip_address} ({reason})")
        os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
        log_attack(ip_address=ip_address, attack_type=reason)

# MAC engelleme
def block_mac(mac_address, reason):
    if mac_address not in blocked_macs:
        blocked_macs.add(mac_address)
        print(f"[+] MAC Engelleniyor: {mac_address} ({reason})")
        os.system(f"iptables -A INPUT -m mac --mac-source {mac_address} -j DROP")
        log_attack(mac_address=mac_address, attack_type=reason)

# Saldırı tespiti
def detect_attack(packet):
    try:
        # Deauthentication Attack
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 12:
            mac_addr = packet.addr2
            mac_counters[mac_addr] += 1
            if mac_counters[mac_addr] > 20:
                block_mac(mac_addr, "Deauthentication Attack")

        # ARP Flood
        elif packet.haslayer(ARP):
            src_mac = packet[ARP].hwsrc
            mac_counters[src_mac] += 1
            if mac_counters[src_mac] > 50:
                block_mac(src_mac, "ARP Flood")

        # DDoS/Smurf Attack
        elif packet.haslayer(IP):
            ip_src = packet[IP].src
            attack_counters[ip_src] += 1
            if attack_counters[ip_src] > 100:
                block_ip(ip_src, "DDoS/Smurf Attack")

        # Ping of Death
        elif packet.haslayer(ICMP) and len(packet) > 1000:
            ip_src = packet[IP].src
            block_ip(ip_src, "Ping of Death")

        # DNS Spoofing
        elif packet.haslayer(Ether) and packet.haslayer(IP) and packet[Ether].src != packet[IP].src:
            log_attack(ip_address=packet[IP].src, mac_address=packet[Ether].src, attack_type="DNS Spoofing")

        # TCP SYN Flood
        elif packet.haslayer(TCP) and packet[TCP].flags == "S":
            ip_src = packet[IP].src
            attack_counters[ip_src] += 1
            if attack_counters[ip_src] > 50:
                block_ip(ip_src, "TCP SYN Flood")

        # UDP Flood
        elif packet.haslayer(UDP):
            ip_src = packet[IP].src
            attack_counters[ip_src] += 1
            if attack_counters[ip_src] > 80:
                block_ip(ip_src, "UDP Flood")

        # ICMP Flood
        elif packet.haslayer(ICMP):
            ip_src = packet[IP].src
            attack_counters[ip_src] += 1
            if attack_counters[ip_src] > 100:
                block_ip(ip_src, "ICMP Flood")

        # DHCP Starvation
        elif packet.haslayer(DHCP):
            mac_addr = packet[Ether].src
            mac_counters[mac_addr] += 1
            if mac_counters[mac_addr] > 20:
                block_mac(mac_addr, "DHCP Starvation Attack")

    except Exception as e:
        print(f"[HATA] Paket işleme sırasında bir hata oluştu: {e}")

# Paket yakalama
def packet_sniffer(interface):
    print(f"[*] Saldırı Tespiti Başlatıldı ({interface} arayüzü)")
    sniff(iface=interface, prn=detect_attack, store=0)

# Ana fonksiyon
if __name__ == "__main__":
    interface = "wlan0"  # Arayüzünüzü buraya girin
    packet_sniffer(interface)
