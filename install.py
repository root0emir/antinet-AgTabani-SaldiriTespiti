import os
import subprocess
import sys
import shutil

# Manuel Banner Yazdırma Fonksiyonu
def print_banner():
    banner = '''
                     _                     
               _    (_)               _    
  ____  ____  | |_   _  ____    ____ | |_  
 / _  ||  _ \ |  _) | ||  _ \  / _  )|  _) 
( ( | || | | || |__ | || | | |( (/ / | |__ 
 \_||_||_| |_| \___)|_||_| |_| \____) \___)
                                                                                                                                       
   *****antinet Ağ Güvenliği Araçkiti*****
     -Emir K. tarafından geliştirildi-   

    '''
    print(banner)
    print("[*] Bu araç, sisteminizde gerekli kurulumu yapacak.\n")

# Gerekli kütüphaneleri yükle
def install_requirements():
    print("[*] Gerekli kütüphaneler yükleniyor...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

# IPTables ve Python3 için gerekli izinleri ayarla
def set_permissions():
    print("[*] Gerekli izinler ayarlanıyor...")
    python3_path = shutil.which('python3')
    if python3_path:
        subprocess.check_call(['sudo', 'setcap', 'cap_net_raw=eip', python3_path])
    else:
        print("[!] Python3 bulunamadı. Lütfen Python3 yüklü olduğundan emin olun.")
        sys.exit(1)

# IPTables'ın kurulu olup olmadığını kontrol et
def install_iptables():
    print("[*] IPTables kuruluyor...")
    try:
        subprocess.check_call(['sudo', 'apt', 'install', 'iptables', '-y'])
    except subprocess.CalledProcessError:
        print("[!] IPTables kurulamadı. Lütfen el ile kurulumu yapın.")
        sys.exit(1)

# Python ve pip'in yüklü olup olmadığını kontrol et
def check_python_and_pip():
    print("[*] Python ve pip kontrol ediliyor...")
    try:
        subprocess.check_call([sys.executable, '--version'])
        subprocess.check_call([sys.executable, "-m", "pip", "--version"])
    except subprocess.CalledProcessError:
        print("[!] Python veya pip yüklü değil. Lütfen Python3 ve pip'i yükleyin.")
        sys.exit(1)

# Kurulum süreci
def run_installer():
    print_banner()

    print("[*] Kurulum başlatılıyor...")

    # Python ve pip kontrolü
    check_python_and_pip()

    # Gerekli kütüphaneler yükleniyor
    install_requirements()

    # IPTables kuruluyor
    install_iptables()

    # İzinler ayarlanıyor
    set_permissions()

    print("[*] Kurulum tamamlandı! Aracınızı çalıştırmak için 'python3 app.py' komutunu kullanabilirsiniz.")

if __name__ == "__main__":
    run_installer()
