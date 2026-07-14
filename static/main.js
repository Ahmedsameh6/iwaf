// IWAF Dashboard — Main JS
// Compatible with new sidebar design

// showMsg and isValidIP are defined in base.html (with icon support)

// Legacy alias for old calls
function showMessage(id, text, type = 'success') { showMsg(id, text, type); }

function resetSlowCounter(ip) {
    fetch(`/reset-slow-counter/${ip}`, { method: 'POST' })
        .then(r => r.json())
        .then(d => { if (d.status === 'success') location.reload(); });
}

function handleCheckIP(event) {
    if (event) event.preventDefault();
    const ip = (document.getElementById('check-ip')?.value || '').trim();
    if (!ip) return showMsg('check-result', 'Please enter an IP address', 'danger');
    if (!isValidIP(ip)) return showMsg('check-result', 'Invalid IP format', 'danger');
    const res = document.getElementById('check-result');
    if (res) res.innerHTML = '<span class="spin"></span> Checking...';
    fetch(`/check-ip/${ip}`)
        .then(r => r.json())
        .then(d => {
            const type = d.status === 'MALICIOUS' ? 'danger' : d.status === 'SUSPICIOUS' ? 'warning' : d.status === 'ERROR' ? 'danger' : 'success';
            const icon = { MALICIOUS: '🚨', SUSPICIOUS: '⚠️', SAFE: '✅', ERROR: '❌' }[d.status] || '❓';
            if (res) res.innerHTML = `<div class="msg msg-${type}" style="flex-direction:column;align-items:flex-start;gap:6px">
                <div style="font-size:15px;font-weight:700">${icon} ${ip} — ${d.status}</div>
                <div style="font-size:12.5px;line-height:2">
                    <b>Reason:</b> ${d.details?.reason || '—'}<br>
                    <b>Malicious Vendors:</b> ${d.details?.malicious_count ?? 0}<br>
                    <b>Suspicious:</b> ${d.details?.suspicious_count ?? 0}<br>
                    <b>Country:</b> ${d.details?.country || 'Unknown'}
                </div>
            </div>`;
        })
        .catch(() => showMsg('check-result', 'Failed to check IP', 'danger'));
}

function handleClearVTCache() {
    fetch('/clear-vt-cache', { method: 'POST' })
        .then(r => r.json())
        .then(d => showMsg('check-result', d.message, d.status === 'success' ? 'success' : 'danger'));
}

// Legacy — kept for compatibility
function fetchStats() {}
function fetchAttackLog() {}
function fetchAttackerLog() {}
function fetchSecurityLog() {}
function updateAttackChart() {}
function deleteLog(type) {
    if (!confirm(`Delete ${type} log?`)) return;
    fetch(`/delete-log/${type}`, { method: 'POST' })
        .then(r => r.json())
        .then(d => { alert(d.message); location.reload(); });
}

document.addEventListener('DOMContentLoaded', () => {
    // Check IP form
    document.getElementById('check-ip-form')?.addEventListener('submit', handleCheckIP);
    document.getElementById('check-ip')?.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); handleCheckIP(null); }});
    document.getElementById('clear-vt-cache')?.addEventListener('click', handleClearVTCache);
});
