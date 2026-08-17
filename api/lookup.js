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
      cloudflare_detected: false,
      origin_ip: null,
      discovered_ips: [],
      open_ports: [],
      sources: {},
      headers: {}
    };

    // ========== 1. CLOUDFLARE DETECTION ==========
    try {
      const cfCheck = await fetch(`https://${clean}`, { method: 'HEAD', timeout: 5000 });
      const headers = cfCheck.headers;
      results.headers = Object.fromEntries(headers.entries());
      results.cloudflare_detected = !!(
        headers.get('cf-ray') || 
        headers.get('cf-cache-status') || 
        headers.get('server')?.includes('cloudflare')
      );
    } catch {}

    // ========== 2. CRTSH ==========
    try {
      const crtRes = await fetch(`https://crt.sh/?q=%25.${clean}&output=json`);
      const crtData = await crtRes.json();
      const crtIps = [];
      if (Array.isArray(crtData)) {
        for (const entry of crtData) {
          if (entry.name_value && entry.name_value.includes(clean)) {
            try {
              const subRes = await fetch(`https://dns.google/resolve?name=${entry.name_value}&type=A`);
              const subData = await subRes.json();
              if (subData.Answer) {
                for (const ans of subData.Answer) {
                  if (ans.data && !crtIps.includes(ans.data)) {
                    crtIps.push(ans.data);
                  }
                }
              }
            } catch {}
          }
        }
      }
      results.sources.crt_sh = crtIps;
      results.discovered_ips = [...new Set(crtIps)];
    } catch {}

    // ========== 3. HACKERTARGET ==========
    try {
      const htRes = await fetch(`https://api.hackertarget.com/hostsearch/?q=${clean}`);
      const htData = await htRes.text();
      const lines = htData.split('\n');
      const htIps = [];
      for (const line of lines) {
        const parts = line.split(',');
        if (parts.length === 2 && parts[1].match(/\d+\.\d+\.\d+\.\d+/)) {
          htIps.push(parts[1]);
        }
      }
      results.sources.hackertarget = htIps;
      results.discovered_ips = [...new Set([...results.discovered_ips, ...htIps])];
    } catch {}

    // ========== 4. OTX ==========
    try {
      const otxRes = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${clean}/passive_dns`);
      const otxData = await otxRes.json();
      if (otxData.passive_dns) {
        const otxIps = otxData.passive_dns.map(p => p.address).filter(Boolean);
        results.sources.otx = otxIps;
        results.discovered_ips = [...new Set([...results.discovered_ips, ...otxIps])];
      }
    } catch {}

    // ========== 5. SECURITYTRAILS ==========
    try {
      const stRes = await fetch(`https://api.securitytrails.com/v1/history/${clean}/dns/a`, {
        headers: { 'APIKEY': 'your-api-key-here' }
      });
      const stData = await stRes.json();
      if (stData.records) {
        const stIps = stData.records.flatMap(r => r.values || []);
        results.sources.securitytrails = stIps;
        results.discovered_ips = [...new Set([...results.discovered_ips, ...stIps])];
      }
    } catch {}

    // ========== 6. DNS GOOGLE (fallback) ==========
    if (results.discovered_ips.length === 0) {
      try {
        const dnsRes = await fetch(`https://dns.google/resolve?name=${clean}&type=A`);
        const dnsData = await dnsRes.json();
        if (dnsData.Answer) {
          const dnsIps = dnsData.Answer.map(a => a.data);
          results.sources.dns_google = dnsIps;
          results.discovered_ips = dnsIps;
        }
      } catch {}
    }

    // ========== 7. ORIGIN IP ==========
    results.origin_ip = results.discovered_ips[0] || 'tidak ditemukan';

    // ========== 8. PORT SCANNING ==========
    if (results.origin_ip && results.origin_ip !== 'tidak ditemukan') {
      const ports = [80, 443, 8080, 8443, 3000, 3306, 22, 21, 25, 53, 143, 993, 995, 3306, 5432, 6379, 27017];
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

    // ========== 9. GEO LOOKUP ==========
    let country = '—', city = '—', isp = '—';
    if (results.origin_ip && results.origin_ip !== 'tidak ditemukan') {
      try {
        const geoRes = await fetch(`https://ip-api.com/json/${results.origin_ip}?fields=country,city,isp`);
        const geo = await geoRes.json();
        country = geo.country || '—';
        city = geo.city || '—';
        isp = geo.isp || '—';
      } catch {}
    }

    // ========== 10. KIRIM HASIL ==========
    res.status(200).json({
      origin_ip: results.origin_ip,
      domain: results.domain,
      open_ports: results.open_ports,
      discovered_ips: results.discovered_ips,
      sources: results.sources,
      cloudflare_detected: results.cloudflare_detected,
      country: country,
      city: city,
      isp: isp
    });

  } catch (err) {
    res.status(500).json({ error: err.message || 'Terjadi kesalahan.' });
  }
};
