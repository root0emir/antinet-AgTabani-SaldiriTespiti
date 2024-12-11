
console.log("Herşey yolunda gidiyor");


document.addEventListener('DOMContentLoaded', function () {
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
});
