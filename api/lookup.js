const fetch = require('node-fetch');
const net = require('net');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { domain } = req.query || req.body || {};
  if (!domain) {
    return res.status(400).json({ error: 'Parameter domain wajib diisi.' });
  }

  try {
    const clean = domain.replace(/^https?:\/\//, '').split('/')[0];
    const results = {
      domain: clean,
      origin_ip: 'tidak ditemukan',
      discovered_ips: [],
      open_ports: [],
      country: '—',
      city: '—',
      isp: '—',
      asn: '—',
      cloudflare_detected: false,
      confidence: 'LOW'
    };

    // ===== 1. PANGGIL CLOUDRECON VIA HTTP =====
    try {
      const crRes = await fetch(`https://cloudrecon-api.vercel.app/api?domain=${clean}`);
      const crData = await crRes.json();
      if (crData.origin_ip) {
        results.origin_ip = crData.origin_ip;
        results.discovered_ips = crData.discovered_ips || [];
        results.cloudflare_detected = crData.cloudflare_detected || false;
        results.confidence = crData.confidence || 'MEDIUM';
      }
    } catch (err) {
      console.warn('CloudRecon API error:', err.message);
    }

    // ===== 2. FALLBACK: DNS GOOGLE =====
    if (results.origin_ip === 'tidak ditemukan') {
      try {
        const dnsRes = await fetch(`https://dns.google/resolve?name=${clean}&type=A`);
        const dnsData = await dnsRes.json();
        if (dnsData.Answer) {
          const dnsIps = dnsData.Answer.filter(a => a.type === 1).map(a => a.data);
          results.discovered_ips = [...new Set([...results.discovered_ips, ...dnsIps])];
          results.origin_ip = dnsIps[0] || 'tidak ditemukan';
        }
      } catch {}
    }

    // ===== 3. GEOIP (HARUS JALAN) =====
    if (results.origin_ip && results.origin_ip !== 'tidak ditemukan') {
      try {
        const geoRes = await fetch(`https://ip-api.com/json/${results.origin_ip}?fields=status,country,city,isp,org,as`);
        const geo = await geoRes.json();
        // Ini penting: log hasil geo buat debug
        console.log('Geo result:', JSON.stringify(geo));

        if (geo.status === 'success') {
          results.country = geo.country || '—';
          results.city = geo.city || '—';
          results.isp = geo.isp || geo.org || '—';
          results.asn = geo.as || '—';
        } else {
          console.warn('Geo lookup gagal untuk IP:', results.origin_ip);
        }
      } catch (err) {
        console.error('Geo error:', err.message);
      }
    }

    // ===== 4. PORT SCAN =====
    if (results.origin_ip && results.origin_ip !== 'tidak ditemukan') {
      const ports = [80, 443, 8080, 8443, 3000, 3306, 22, 21, 25];
      const openPorts = [];
      for (const port of ports) {
        const isOpen = await new Promise((resolve) => {
          const socket = new net.Socket();
          socket.setTimeout(1000);
          socket.on('connect', () => { socket.destroy(); resolve(true); });
          socket.on('timeout', () => { socket.destroy(); resolve(false); });
          socket.on('error', () => resolve(false));
          socket.connect(port, results.origin_ip);
        });
        if (isOpen) openPorts.push(port);
      }
      results.open_ports = openPorts;
    }

    res.status(200).json(results);

  } catch (err) {
    res.status(500).json({ error: err.message || 'Terjadi kesalahan.' });
  }
};
