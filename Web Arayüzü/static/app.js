console.log("Herşey yolunda gidiyor");

document.addEventListener('DOMContentLoaded', function () {
    // Logları gösterme
    const logTable = document.getElementById('log-table');
    const totalAttacks = document.getElementById('total_attacks');
    const blockedIps = document.getElementById('blocked_ips');

    // Backend'den saldırı loglarını al
    function fetchLogs() {
        fetch('/api/logs')
            .then(response => response.json())
            .then(data => {
                logTable.innerHTML = ''; // Eski logları temizle
                let attackCount = 0;

                data.logs.forEach(log => {
                    attackCount++;
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${log.timestamp}</td>
                        <td>${log.attack_type}</td>
                        <td>${log.ip_address || 'N/A'}</td>
                        <td>${log.mac_address || 'N/A'}</td>
                        <td>${log.details || 'N/A'}</td>
                    `;
                    logTable.appendChild(row);
                });

                totalAttacks.textContent = attackCount;
                blockedIps.textContent = data.blocked_ips.length;
            })
            .catch(err => console.error('Loglar alınamadı:', err));
    }

    // Her 5 saniyede bir logları yenile
    setInterval(fetchLogs, 5000);

    // İlk yükleme
    fetchLogs();

    // Ayarlar formu
    const settingsForm = document.getElementById('settings-form');
    const blockedIpsList = document.getElementById('blocked-ips');
    const blockedMacsList = document.getElementById('blocked-macs');

    // IP ve MAC engelleme formunun işlevselliği
    settingsForm.addEventListener('submit', function (e) {
        e.preventDefault();

        const ipAddress = document.getElementById('ip-address').value;
        const macAddress = document.getElementById('mac-address').value;

        const data = {};

        if (ipAddress) {
            data.ip_address = ipAddress;
        }

        if (macAddress) {
            data.mac_address = macAddress;
        }

        if (ipAddress || macAddress) {
            fetch('/api/block', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                updateBlockedList();
            })
            .catch(error => console.error('Engelleme işlemi başarısız:', error));
        }
    });

    // Engellenen IP ve MAC adreslerini listele
    function updateBlockedList() {
        fetch('/api/logs')
            .then(response => response.json())
            .then(data => {
                // Engellenen IP'leri güncelle
                blockedIpsList.innerHTML = '';
                data.blocked_ips.forEach(ip => {
                    const li = document.createElement('li');
                    li.textContent = ip;
                    blockedIpsList.appendChild(li);
                });

                // Engellenen MAC'leri güncelle
                blockedMacsList.innerHTML = '';
                data.blocked_macs.forEach(mac => {
                    const li = document.createElement('li');
                    li.textContent = mac;
                    blockedMacsList.appendChild(li);
                });
            })
            .catch(err => console.error('Engellenen adresler alınamadı:', err));
    }

    // Sayfa ilk yüklendiğinde engellenen listeleri güncelle
    updateBlockedList();
});
