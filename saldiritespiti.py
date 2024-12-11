from scapy.all import sniff, Dot11, ARP, IP, ICMP, UDP, TCP, Ether
import os
import json
from collections import defaultdict
import time

# Engellenmiş IP ve MAC adresleri
blocked_ips = set()
blocked_macs = set()

# Sayaçlar
attack_counters = defaultdict(int)
mac_counters = defaultdict(int)

# Log dosyası
LOG_FILE = "attack_logs.json"

# Loglama fonksiyonu
def log_attack(ip_address=None, mac_address=None, attack_type=None, details=None):
    log_entry = {
        "timestamp": time.ctime(),
        "ip_address": ip_address,
        "mac_address": mac_address,
        "attack_type": attack_type,
        "details": details,
    }
    # Dosyaya yaz
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
    # 1. Deauth Attack
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 12:
        mac_addr = packet.addr2
        mac_counters[mac_addr] += 1
        if mac_counters[mac_addr] > 20:
            block_mac(mac_addr, "Deauthentication Attack")

    # 2. ARP Flood
    if packet.haslayer(ARP):
        src_mac = packet[ARP].hwsrc
        mac_counters[src_mac] += 1
        if mac_counters[src_mac] > 50:
            block_mac(src_mac, "ARP Flood")

    # 3. Evil Twin Attack
    if packet.haslayer(Dot11) and packet[Dot11].addr1 == "ff:ff:ff:ff:ff:ff":
        ssid = packet.info.decode("utf-8", errors="ignore")
        log_attack(mac_address=packet[Dot11].addr2, attack_type="Evil Twin", details=f"SSID={ssid}")

    # 4. DDoS/Smurf Attack
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        attack_counters[ip_src] += 1
        if attack_counters[ip_src] > 100:
            block_ip(ip_src, "DDoS/Smurf Attack")

    # 5. Ping of Death
    if packet.haslayer(ICMP) and len(packet) > 1000:
        ip_src = packet[IP].src
        block_ip(ip_src, "Ping of Death")

    # 6. Wi-Fi Cracking
    if packet.haslayer(Dot11) and packet[Dot11].type == 2 and packet[Dot11].subtype == 4:
        log_attack(mac_address=packet[Dot11].addr2, attack_type="Wi-Fi Cracking")

    # 7. DNS Spoofing
    if packet.haslayer(Ether) and packet.haslayer(IP) and packet[Ether].src != packet[IP].src:
        log_attack(ip_address=packet[IP].src, mac_address=packet[Ether].src, attack_type="DNS Spoofing")

    # 8. MITM Attack
    if packet.haslayer(Ether) and packet.haslayer(IP):
        if packet[Ether].src in mac_counters and packet[IP].src != packet[Ether].src:
            log_attack(ip_address=packet[IP].src, mac_address=packet[Ether].src, attack_type="MITM Attack")

    # 9. TCP SYN Flood
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        ip_src = packet[IP].src
        attack_counters[ip_src] += 1
        if attack_counters[ip_src] > 50:
            block_ip(ip_src, "TCP SYN Flood")

    # 10. UDP Flood
    if packet.haslayer(UDP):
        ip_src = packet[IP].src
        attack_counters[ip_src] += 1
        if attack_counters[ip_src] > 80:
            block_ip(ip_src, "UDP Flood")

    # 11. ICMP Flood
    if packet.haslayer(ICMP):
        ip_src = packet[IP].src
        attack_counters[ip_src] += 1
        if attack_counters[ip_src] > 100:
            block_ip(ip_src, "ICMP Flood")

    # 12. DHCP Starvation
    if packet.haslayer(DHCP):
        mac_addr = packet[Ether].src
        mac_counters[mac_addr] += 1
        if mac_counters[mac_addr] > 20:
            block_mac(mac_addr, "DHCP Starvation Attack")

    # 13. Port Scan
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        ip_src = packet[IP].src
        attack_counters[ip_src] += 1
        if attack_counters[ip_src] > 20:  # Çok fazla SYN isteği
            block_ip(ip_src, "Port Scanning")

    # 14. Fake AP Detection
    if packet.haslayer(Dot11) and packet[Dot11].type == 0:
        ssid = packet.info.decode("utf-8", errors="ignore")
        log_attack(mac_address=packet[Dot11].addr2, attack_type="Fake AP", details=f"SSID={ssid}")

    # 15. Gratuitous ARP
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        log_attack(mac_address=packet[ARP].hwsrc, attack_type="Gratuitous ARP")

# Ağ trafiğini dinle
def start_sniffing(interface):
    print(f"[+] {interface} arayüzü dinleniyor...")
    sniff(iface=interface, prn=detect_attack, store=0)

if __name__ == "__main__":
    network_interface = "wlan0"  # Ethernet için "eth0"
    start_sniffing(network_interface)
