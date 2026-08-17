const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
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
    const clean = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const results = {
      domain: clean,
      origin_ip: 'tidak ditemukan',
      discovered_ips: [],
      open_ports: [],
      country: '—',
      city: '—',
      isp: '—',
      cloudflare_detected: false,
      confidence: 'LOW',
      sources: {}
    };

    // ========== 1. PANGGIL CLOUDRECON ==========
    try {
      const reconPath = path.join(__dirname, '..', 'cloudrecon', 'recon.py');
      const reconResult = await new Promise((resolve, reject) => {
        exec(
          `python3 ${reconPath} ${clean} --passive --output`,
          { timeout: 25000 },
          (error, stdout, stderr) => {
            if (error) return reject(error);
            resolve(stdout);
          }
        );
      });

      // Ekstrak IP dari output
      const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
      const ips = [...new Set(reconResult.match(ipRegex) || [])];
      results.discovered_ips = ips;
      results.origin_ip = ips[0] || 'tidak ditemukan';
      results.cloudflare_detected = reconResult.includes('Cloudflare NS') || reconResult.toLowerCase().includes('cloudflare');
      results.sources.cloudrecon = true;

    } catch (err) {
      console.warn('CloudRecon error:', err.message);
      results.sources.cloudrecon = false;
    }

    // ========== 2. FALLBACK: DNS GOOGLE ==========
    if (results.origin_ip === 'tidak ditemukan') {
      try {
        const dnsRes = await fetch(`https://dns.google/resolve?name=${clean}&type=A`);
        const dnsData = await dnsRes.json();
        if (dnsData.Answer) {
          const dnsIps = dnsData.Answer
            .filter(a => a.type === 1)
            .map(a => a.data);
          results.discovered_ips = [...new Set([...results.discovered_ips, ...dnsIps])];
          results.origin_ip = dnsIps[0] || 'tidak ditemukan';
          results.sources.dns_google = true;
        }
      } catch {}
    }

    // ========== 3. GEOIP (ip-api.com) ==========
    if (results.origin_ip && results.origin_ip !== 'tidak ditemukan') {
      try {
        const geoRes = await fetch(`https://ip-api.com/json/${results.origin_ip}?fields=status,country,city,isp,org,as`);
        const geo = await geoRes.json();
        if (geo.status === 'success') {
          results.country = geo.country || '—';
          results.city = geo.city || '—';
          results.isp = geo.isp || geo.org || '—';
          results.asn = geo.as || '—';
        }
      } catch {}
    }

    // ========== 4. PORT SCAN ==========
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

    // ========== 5. CONFIDENCE ==========
    let confidenceScore = 0;
    if (results.sources.cloudrecon) confidenceScore++;
    if (results.sources.dns_google) confidenceScore++;
    if (results.discovered_ips.length > 1) confidenceScore++;
    if (results.origin_ip !== 'tidak ditemukan' && results.origin_ip.match(/^\d+\.\d+\.\d+\.\d+$/)) confidenceScore++;

    results.confidence = confidenceScore >= 3 ? 'HIGH' : confidenceScore >= 2 ? 'MEDIUM' : 'LOW';

    // ========== 6. KIRIM RESPON ==========
    res.status(200).json(results);

  } catch (err) {
    res.status(500).json({ error: err.message || 'Terjadi kesalahan.' });
  }
};
