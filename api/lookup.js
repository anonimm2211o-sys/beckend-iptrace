const fetch = require('node-fetch');
const net = require('net');
const dns = require('dns');

// ========== HELPER: RESOLVE CNAME KE IP ==========
function resolveHostname(hostname) {
  return new Promise((resolve) => {
    dns.resolve4(hostname, (err, addresses) => {
      if (err) {
        // Coba IPv6 kalo IPv4 gagal
        dns.resolve6(hostname, (err6, addresses6) => {
          if (err6) return resolve(null);
          resolve(addresses6);
        });
      } else {
        resolve(addresses);
      }
    });
  });
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { domain } = req.query || req.body || {};
  if (!domain) {
    return res.status(400).json({ error: 'Parameter domain wajib diisi.' });
  }

  try {
    // ========== NORMALISASI DOMAIN ==========
    let clean = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    clean = clean.toLowerCase().trim();

    // Validasi domain sederhana
    if (!clean || !clean.includes('.')) {
      return res.status(400).json({ error: 'Domain tidak valid.' });
    }

    const results = {
      domain: clean,
      cloudflare_detected: false,
      origin_ip: null,
      discovered_ips: [],
      open_ports: [],
      sources: {},
      country: '—',
      city: '—',
      isp: '—',
      headers: {}
    };

    const allIps = new Set();

    // ========== 1. DNS RESOLVE (CNAME -> IP) ==========
    try {
      const ipResult = await resolveHostname(clean);
      if (ipResult && ipResult.length > 0) {
        for (const ip of ipResult) {
          if (ip && typeof ip === 'string' && ip.match(/\d+\.\d+\.\d+\.\d+/)) {
            allIps.add(ip);
          }
        }
        results.sources.dns_direct = ipResult.filter(ip => ip.match(/\d+\.\d+\.\d+\.\d+/));
      }
    } catch {}

    // ========== 2. CLOUDFLARE DETECTION ==========
    try {
      const cfCheck = await fetch(`https://${clean}`, { 
        method: 'HEAD', 
        timeout: 5000,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
      });
      const headers = cfCheck.headers;
      results.headers = Object.fromEntries(headers.entries());
      results.cloudflare_detected = !!(
        headers.get('cf-ray') || 
        headers.get('cf-cache-status') || 
        headers.get('server')?.toLowerCase().includes('cloudflare')
      );
    } catch {}

    // ========== 3. CRTSH (Certificate Transparency) ==========
    try {
      const crtRes = await fetch(`https://crt.sh/?q=%25.${clean}&output=json`, { timeout: 8000 });
      const crtData = await crtRes.json();
      if (Array.isArray(crtData)) {
        const crtIps = [];
        for (const entry of crtData) {
          if (entry.name_value && entry.name_value.includes(clean)) {
            const subdomain = entry.name_value.toLowerCase().trim();
            if (subdomain !== clean && subdomain.includes(clean)) {
              try {
                const subIps = await resolveHostname(subdomain);
                if (subIps) {
                  for (const ip of subIps) {
                    if (ip && typeof ip === 'string' && ip.match(/\d+\.\d+\.\d+\.\d+/)) {
                      crtIps.push(ip);
                    }
                  }
                }
              } catch {}
            }
          }
        }
        results.sources.crt_sh = [...new Set(crtIps)];
        for (const ip of crtIps) allIps.add(ip);
      }
    } catch {}

    // ========== 4. HACKERTARGET (DNS History) ==========
    try {
      const htRes = await fetch(`https://api.hackertarget.com/hostsearch/?q=${clean}`, { timeout: 6000 });
      const htData = await htRes.text();
      const lines = htData.split('\n');
      const htIps = [];
      for (const line of lines) {
        const parts = line.split(',');
        if (parts.length === 2) {
          const ip = parts[1].trim();
          if (ip.match(/\d+\.\d+\.\d+\.\d+/)) {
            htIps.push(ip);
          }
        }
      }
      results.sources.hackertarget = [...new Set(htIps)];
      for (const ip of htIps) allIps.add(ip);
    } catch {}

    // ========== 5. OTX ALIENVAULT (Passive DNS) ==========
    try {
      const otxRes = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${clean}/passive_dns`, { timeout: 6000 });
      const otxData = await otxRes.json();
      if (otxData.passive_dns) {
        const otxIps = otxData.passive_dns
          .map(p => p.address)
          .filter(ip => ip && ip.match(/\d+\.\d+\.\d+\.\d+/));
        results.sources.otx = [...new Set(otxIps)];
        for (const ip of otxIps) allIps.add(ip);
      }
    } catch {}

    // ========== 6. DNS GOOGLE (fallback) ==========
    if (allIps.size === 0) {
      try {
        const dnsRes = await fetch(`https://dns.google/resolve?name=${clean}&type=A`, { timeout: 5000 });
        const dnsData = await dnsRes.json();
        if (dnsData.Answer) {
          const dnsIps = dnsData.Answer
            .filter(a => a.type === 1)
            .map(a => a.data)
            .filter(ip => ip.match(/\d+\.\d+\.\d+\.\d+/));
          results.sources.dns_google = dnsIps;
          for (const ip of dnsIps) allIps.add(ip);
        }
      } catch {}
    }

    // ========== 7. KONVERSI SET KE ARRAY ==========
    results.discovered_ips = [...allIps];

    // ========== 8. ORIGIN IP (ambil IP pertama yang valid) ==========
    const validIp = results.discovered_ips.find(ip => ip && ip.match(/\d+\.\d+\.\d+\.\d+/));
    results.origin_ip = validIp || 'tidak ditemukan';

    // ========== 9. PORT SCANNING ==========
    if (results.origin_ip && results.origin_ip !== 'tidak ditemukan') {
      const ports = [80, 443, 8080, 8443, 3000, 3306, 22, 21, 25, 53];
      const openPorts = [];
      for (const port of ports) {
        const isOpen = await new Promise((resolve) => {
          const socket = new net.Socket();
          socket.setTimeout(1500);
          socket.on('connect', () => { socket.destroy(); resolve(true); });
          socket.on('timeout', () => { socket.destroy(); resolve(false); });
          socket.on('error', () => resolve(false));
          socket.connect(port, results.origin_ip);
        });
        if (isOpen) openPorts.push(port);
      }
      results.open_ports = openPorts;
    }

    // ========== 10. GEOIP LOOKUP (ip-api.com) ==========
    if (results.origin_ip && results.origin_ip !== 'tidak ditemukan') {
      try {
        const geoRes = await fetch(`https://ip-api.com/json/${results.origin_ip}?fields=country,city,isp,org`, { timeout: 5000 });
        const geo = await geoRes.json();
        results.country = geo.country || '—';
        results.city = geo.city || '—';
        results.isp = geo.isp || geo.org || '—';
      } catch {}
    }

    // ========== 11. KIRIM RESPON ==========
    res.status(200).json({
      domain: results.domain,
      origin_ip: results.origin_ip,
      discovered_ips: results.discovered_ips,
      open_ports: results.open_ports,
      cloudflare_detected: results.cloudflare_detected,
      country: results.country,
      city: results.city,
      isp: results.isp,
      sources: results.sources,
      headers: results.headers
    });

  } catch (err) {
    res.status(500).json({ 
      error: err.message || 'Terjadi kesalahan.',
      domain: req.query?.domain || 'unknown'
    });
  }
};
