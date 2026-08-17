const els = {
  ifaceSelect: document.getElementById('ifaceSelect'),
  bpfFilter: document.getElementById('bpfFilter'),
  startBtn: document.getElementById('startBtn'),
  stopBtn: document.getElementById('stopBtn'),
  resetBtn: document.getElementById('resetBtn'),
  statusPill: document.getElementById('statusPill'),
  statusDot: document.getElementById('statusDot'),
  statusText: document.getElementById('statusText'),
  permBanner: document.getElementById('permBanner'),
  copyPermCmdBtn: document.getElementById('copyPermCmdBtn'),
  statTotal: document.getElementById('statTotal'),
  statPPS: document.getElementById('statPPS'),
  statKBPS: document.getElementById('statKBPS'),
  statTCP: document.getElementById('statTCP'),
  statUDP: document.getElementById('statUDP'),
  statICMP: document.getElementById('statICMP'),
  statOTHER: document.getElementById('statOTHER'),
  presetPills: document.getElementById('presetPills'),
  protoFilter: document.getElementById('protoFilter'),
  ipFilter: document.getElementById('ipFilter'),
  exportBtn: document.getElementById('exportBtn'),
  packetBody: document.getElementById('packetBody'),
  talkerList: document.getElementById('talkerList'),
  alertList: document.getElementById('alertList'),

  // Modal elements
  packetModal: document.getElementById('packetModal'),
  closeModalBtn: document.getElementById('closeModalBtn'),
  modalPktId: document.getElementById('modalPktId'),
  mTime: document.getElementById('mTime'),
  mLen: document.getElementById('mLen'),
  mProto: document.getElementById('mProto'),
  mSrcIp: document.getElementById('mSrcIp'),
  mSrcType: document.getElementById('mSrcType'),
  mDstIp: document.getElementById('mDstIp'),
  mDstType: document.getElementById('mDstType'),
  mPorts: document.getElementById('mPorts'),
  mSrcMac: document.getElementById('mSrcMac'),
  mDstMac: document.getElementById('mDstMac'),
  mIpVer: document.getElementById('mIpVer'),
  mTtl: document.getElementById('mTtl'),
  mIpId: document.getElementById('mIpId'),
  mProtoName: document.getElementById('mProtoName'),
  mSrcPort: document.getElementById('mSrcPort'),
  mDstPort: document.getElementById('mDstPort'),
  mFlags: document.getElementById('mFlags'),
  mSeq: document.getElementById('mSeq'),
  mAck: document.getElementById('mAck'),
  mWin: document.getElementById('mWin'),
  mHexDump: document.getElementById('mHexDump'),
};

let pollTimer = null;
let chart = null;
let isRunning = false;

function initChart() {
  const ctx = document.getElementById('protoChart').getContext('2d');
  chart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['TCP', 'UDP', 'ICMP', 'OTHER'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ['#35E7C9', '#FF9F45', '#FF5C5C', '#7C879C'],
        borderColor: '#10151F',
        borderWidth: 3,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#7C879C', font: { size: 11 }, boxWidth: 10, padding: 12 }
        }
      },
      cutout: '65%'
    }
  });
}

async function loadInterfaces() {
  try {
    const res = await fetch('/api/interfaces');
    const data = await res.json();
    els.ifaceSelect.innerHTML = '';
    data.interfaces.forEach(item => {
      const opt = document.createElement('option');
      opt.value = typeof item === 'string' ? item : item.id;
      opt.textContent = typeof item === 'string' ? item : item.name;
      els.ifaceSelect.appendChild(opt);
    });
  } catch (e) {
    console.error('Could not load interfaces', e);
  }
}

function setRunningUI(running) {
  isRunning = running;
  els.startBtn.disabled = running;
  els.stopBtn.disabled = !running;
  els.statusText.textContent = running ? 'LIVE' : 'IDLE';
  els.statusPill.classList.toggle('live', running);
}

async function startCapture() {
  const body = {
    interface: els.ifaceSelect.value || null,
    filter: els.bpfFilter.value.trim() || null,
  };
  const res = await fetch('/api/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  await res.json();
  setRunningUI(true);
  startPolling();
}

async function stopCapture() {
  await fetch('/api/stop', { method: 'POST' });
  setRunningUI(false);
}

async function resetCapture() {
  await fetch('/api/reset', { method: 'POST' });
  refreshAll();
}

function exportCSV() {
  window.location.href = '/api/export';
}

function protoTag(proto) {
  return `<span class="proto-tag proto-${proto}">${proto}</span>`;
}

async function refreshPackets() {
  const proto = els.protoFilter.value;
  const ip = els.ipFilter.value.trim();
  const params = new URLSearchParams({ protocol: proto, ip, limit: 200 });
  const res = await fetch('/api/packets?' + params.toString());
  const data = await res.json();

  if (!data.packets.length) {
    els.packetBody.innerHTML = `<tr class="empty-row"><td colspan="8">No packets match the current filters yet.</td></tr>`;
    return;
  }

  els.packetBody.innerHTML = data.packets.map(p => {
    const port = (p.src_port && p.dst_port) ? `${p.src_port} → ${p.dst_port}` : '—';
    const payload = p.payload ? p.payload.replace(/</g, '&lt;') : '—';
    return `<tr class="pkt-row" onclick="inspectPacket(${p.id})">
      <td>#${p.id}</td>
      <td>${p.time}</td>
      <td>${p.src_ip}</td>
      <td>${p.dst_ip}</td>
      <td>${protoTag(p.protocol)}</td>
      <td>${port}</td>
      <td>${p.length}</td>
      <td class="payload-cell" title="${payload}">${payload}</td>
    </tr>`;
  }).join('');
}

async function inspectPacket(pktId) {
  try {
    const res = await fetch(`/api/packet/${pktId}`);
    if (!res.ok) return;
    const p = await res.json();

    els.modalPktId.textContent = p.id;
    els.mTime.textContent = p.time;
    els.mLen.textContent = p.length;
    els.mProto.textContent = p.protocol;
    els.mSrcIp.textContent = p.src_ip;
    els.mSrcType.textContent = p.src_type;
    els.mDstIp.textContent = p.dst_ip;
    els.mDstType.textContent = p.dst_type;
    els.mPorts.textContent = (p.src_port && p.dst_port) ? `${p.src_port} → ${p.dst_port}` : 'N/A';

    els.mSrcMac.textContent = p.src_mac;
    els.mDstMac.textContent = p.dst_mac;
    els.mIpVer.textContent = p.ip_version || '4';
    els.mTtl.textContent = p.ttl || 'N/A';
    els.mIpId.textContent = p.ip_id || 'N/A';

    els.mProtoName.textContent = p.protocol;
    els.mSrcPort.textContent = p.src_port || 'N/A';
    els.mDstPort.textContent = p.dst_port || 'N/A';
    els.mFlags.textContent = p.flags || 'None';
    els.mSeq.textContent = p.seq || 'N/A';
    els.mAck.textContent = p.ack || 'N/A';
    els.mWin.textContent = p.window || 'N/A';

    els.mHexDump.textContent = p.hex_dump || 'No payload data';

    els.packetModal.classList.remove('hidden');
  } catch (e) {
    console.error('Error fetching packet detail', e);
  }
}

function closeModal() {
  els.packetModal.classList.add('hidden');
}

async function refreshStats() {
  const res = await fetch('/api/stats');
  const data = await res.json();

  els.statTotal.textContent = data.total_packets;
  els.statPPS.textContent = data.pps !== undefined ? data.pps : '0.0';
  els.statKBPS.textContent = data.kbps !== undefined ? data.kbps : '0.0';

  els.statTCP.textContent = data.protocol_counts.TCP || 0;
  els.statUDP.textContent = data.protocol_counts.UDP || 0;
  els.statICMP.textContent = data.protocol_counts.ICMP || 0;
  els.statOTHER.textContent = data.protocol_counts.OTHER || (data.protocol_counts.ARP || 0);

  // Toggle BPF permission banner
  if (data.bpf_permitted === false) {
    els.permBanner.classList.remove('hidden');
  } else {
    els.permBanner.classList.add('hidden');
  }

  if (chart) {
    chart.data.datasets[0].data = [
      data.protocol_counts.TCP || 0,
      data.protocol_counts.UDP || 0,
      data.protocol_counts.ICMP || 0,
      data.protocol_counts.OTHER || (data.protocol_counts.ARP || 0),
    ];
    chart.update('none');
  }

  if (data.top_talkers && data.top_talkers.length) {
    els.talkerList.innerHTML = data.top_talkers.map(t =>
      `<li><span>${t.ip}</span><span class="count">${t.count}</span></li>`
    ).join('');
  } else {
    els.talkerList.innerHTML = `<li class="muted">No data yet</li>`;
  }

  if (data.running !== isRunning) setRunningUI(data.running);
}

async function refreshAlerts() {
  const res = await fetch('/api/alerts');
  const data = await res.json();

  if (!data.alerts.length) {
    els.alertList.innerHTML = `<li class="muted">No alerts. Traffic monitoring active.</li>`;
    return;
  }

  els.alertList.innerHTML = data.alerts.slice(0, 25).map(a => {
    const formattedMsg = (a.message || '').replace(/</g, '&lt;').replace(/\n/g, '<br>');
    return `
    <li class="${a.level}">
      <span class="alert-time">${a.time}</span>
      ${formattedMsg}
    </li>
  `;
  }).join('');
}

function refreshAll() {
  refreshPackets();
  refreshStats();
  refreshAlerts();
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(refreshAll, 1000);
}

// Preset pills click handler
els.presetPills.addEventListener('click', (e) => {
  if (!e.target.classList.contains('pill')) return;
  document.querySelectorAll('.preset-pills .pill').forEach(btn => btn.classList.remove('active'));
  e.target.classList.add('active');
  els.protoFilter.value = e.target.dataset.proto;
  refreshPackets();
});

// Modal tabs handler
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
  });
});

// Event Listeners
els.startBtn.addEventListener('click', startCapture);
els.stopBtn.addEventListener('click', stopCapture);
els.resetBtn.addEventListener('click', resetCapture);
els.exportBtn.addEventListener('click', exportCSV);
els.ipFilter.addEventListener('input', () => {
  clearTimeout(window._ipDebounce);
  window._ipDebounce = setTimeout(refreshPackets, 300);
});

els.closeModalBtn.addEventListener('click', closeModal);
els.packetModal.addEventListener('click', (e) => {
  if (e.target === els.packetModal) closeModal();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
});

els.copyPermCmdBtn.addEventListener('click', () => {
  navigator.clipboard.writeText('sudo chmod 666 /dev/bpf*');
  els.copyPermCmdBtn.textContent = 'Copied!';
  setTimeout(() => { els.copyPermCmdBtn.textContent = 'Copy Command'; }, 2000);
});

// Init
initChart();
loadInterfaces().then(() => {
  refreshAll();
  startPolling();
  // Auto start capture on page open
  startCapture();
});
