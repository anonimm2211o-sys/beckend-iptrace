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

    // 1. Certificate Transparency (crt.sh)
    try {
      const crtRes = await fetch(`https://crt.sh/?q=%25.${clean}&output=json`);
      const crtData = await crtRes.json();
      const crtIps = [];
      for (const entry of crtData) {
        if (entry.name_value && entry.name_value.includes(clean)) {
          // Coba resolve subdomain
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

    // 2. DNS History via SecurityTrails (gratis, tanpa API key)
    try {
      const stRes = await fetch(`https://api.securitytrails.com/v1/history/${clean}/dns/a`, {
        headers: { 'APIKEY': 'your-api-key' } // gratis daftar dulu
      });
      const stData = await stRes.json();
      if (stData.records) {
        const stIps = stData.records.flatMap(r => r.values || []);
        results.discovered_ips = [...new Set([...results.discovered_ips, ...stIps])];
        results.sources.securitytrails = stIps;
      }
    } catch {}

    // 3. Passive DNS via OTX AlienVault (gratis)
    try {
      const otxRes = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${clean}/passive_dns`);
      const otxData = await otxRes.json();
      if (otxData.passive_dns) {
        const otxIps = otxData.passive_dns.map(p => p.address).filter(Boolean);
        results.discovered_ips = [...new Set([...results.discovered_ips, ...otxIps])];
        results.sources.otx = otxIps;
      }
    } catch {}

    // 4. Coba DNS A langsung (fallback)
    if (results.discovered_ips.length === 0) {
      try {
        const dnsRes = await fetch(`https://dns.google/resolve?name=${clean}&type=A`);
        const dnsData = await dnsRes.json();
        if (dnsData.Answer) {
          const dnsIps = dnsData.Answer.map(a => a.data);
          results.discovered_ips = dnsIps;
          results.sources.dns_google = dnsIps;
        }
      } catch {}
    }

    // Ambil IP pertama sebagai origin
    results.origin_ip = results.discovered_ips[0] || 'tidak ditemukan';

    res.status(200).json(results);

  } catch (err) {
    res.status(500).json({ error: err.message || 'Terjadi kesalahan.' });
  }
};
