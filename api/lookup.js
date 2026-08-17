const fetch = require('node-fetch');

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
      origin_ip: null,
      discovered_ips: [],
      sources: {}
    };

    // 1. crt.sh (Certificate Transparency)
    try {
      const crtRes = await fetch(`https://crt.sh/?q=%25.${clean}&output=json`);
      const crtData = await crtRes.json();
      const crtIps = [];
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
      results.discovered_ips = [...new Set(crtIps)];
      results.sources.crt_sh = crtIps;
    } catch {}

    // 2. HackerTarget DNS History
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
      results.discovered_ips = [...new Set([...results.discovered_ips, ...htIps])];
      results.sources.hackertarget = htIps;
    } catch {}

    // 3. OTX AlienVault Passive DNS
    try {
      const otxRes = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${clean}/passive_dns`);
      const otxData = await otxRes.json();
      if (otxData.passive_dns) {
        const otxIps = otxData.passive_dns.map(p => p.address).filter(Boolean);
        results.discovered_ips = [...new Set([...results.discovered_ips, ...otxIps])];
        results.sources.otx = otxIps;
      }
    } catch {}

    // 4. SecurityTrails (DAFTAR API KEY GRATIS DULU)
    try {
      const stRes = await fetch(`https://api.securitytrails.com/v1/history/${clean}/dns/a`, {
        headers: { 'APIKEY': 'your-api-key-here' } // ← GANTI PAKE API KEY LU
      });
      const stData = await stRes.json();
      if (stData.records) {
        const stIps = stData.records.flatMap(r => r.values || []);
        results.discovered_ips = [...new Set([...results.discovered_ips, ...stIps])];
        results.sources.securitytrails = stIps;
      }
    } catch {}

    // Ambil IP pertama sebagai origin
    results.origin_ip = results.discovered_ips[0] || 'tidak ditemukan';

    res.status(200).json(results);

  } catch (err) {
    res.status(500).json({ error: err.message || 'Terjadi kesalahan.' });
  }
};
