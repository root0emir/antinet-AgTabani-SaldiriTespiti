from flask import Flask, render_template, request, jsonify
import os
import json
import threading
from saldiritespiti import packet_sniffer, attack_queue  # Bu modülün doğru şekilde import edildiğinden emin olun

app = Flask(__name__, template_folder='templates')

# Engellenen IP ve MAC adresleri
blocked_ips = set()
blocked_macs = set()

# Log dosyası
LOG_FILE = "attack_logs.json"

# Ana sayfa (Dashboard) route'u
@app.route('/')
def index():
    return render_template('index.html')

# Ayarlar sayfası
@app.route('/settings')
def settings():
    return render_template('settings.html')

# Kılavuz sayfası
@app.route('/guide')
def guide():
    return render_template('guide.html')

# API: Logları Getir
@app.route('/api/logs', methods=['GET'])
def get_logs():
    logs = []
    while not attack_queue.empty():
        logs.append(attack_queue.get())  # Queue'dan veriyi al
    return jsonify({"logs": logs})

# API: IP veya MAC Engelle
@app.route('/api/block', methods=['POST'])
def block():
    data = request.json
    ip_address = data.get("ip_address")
    mac_address = data.get("mac_address")

    if ip_address and ip_address not in blocked_ips:
        blocked_ips.add(ip_address)
        os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
        return jsonify({"message": f"IP {ip_address} engellendi"}), 200
    if mac_address and mac_address not in blocked_macs:
        blocked_macs.add(mac_address)
        os.system(f"iptables -A INPUT -m mac --mac-source {mac_address} -j DROP")
        return jsonify({"message": f"MAC {mac_address} engellendi"}), 200
    return jsonify({"error": "Engelleme için IP veya MAC adresi belirtilmedi"}), 400

# API: IP veya MAC Engelini Kaldır
@app.route('/api/unblock', methods=['POST'])
def unblock():
    data = request.json
    ip_address = data.get("ip_address")
    mac_address = data.get("mac_address")

    if ip_address and ip_address in blocked_ips:
        blocked_ips.remove(ip_address)
        os.system(f"iptables -D INPUT -s {ip_address} -j DROP")
        return jsonify({"message": f"IP {ip_address} engeli kaldırıldı"}), 200
    if mac_address and mac_address in blocked_macs:
        blocked_macs.remove(mac_address)
        os.system(f"iptables -D INPUT -m mac --mac-source {mac_address} -j DROP")
        return jsonify({"message": f"MAC {mac_address} engeli kaldırıldı"}), 200
    return jsonify({"error": "Engel kaldırmak için IP veya MAC adresi belirtilmedi"}), 400

# Saldırı Tespit Fonksiyonunu Ayrı Bir Thread'de Başlat
def start_attack_detection():
    interface = "wlan0"  # Arayüzünüzü buraya girin (Windows'ta farklı olabilir)
    thread = threading.Thread(target=packet_sniffer, args=(interface,), daemon=True)
    thread.start()

# Flask Uygulamasını Çalıştır
if __name__ == '__main__':
    start_attack_detection()  # Başlatma fonksiyonunu burada çağırıyoruz
    app.run(debug=True)  # Debug'u kapatmayı unutmayın, threading ile bazen sorun olabilir
