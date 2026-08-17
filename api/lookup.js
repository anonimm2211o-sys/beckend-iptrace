const fetch = require('node-fetch');
const net = require('net');
const dns = require('dns');
const crypto = require('crypto');

// ========== HELPERS ==========
function resolveHostname(hostname) {
  return new Promise((resolve) => {
    dns.resolve4(hostname, (err, addresses) => {
      if (err) {
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

function isValidIP(ip) {
  return ip && typeof ip === 'string' && ip.match(/^\d+\.\d+\.\d+\.\d+$/);
}

function isCloudflareIP(ip) {
  const cfRanges = [
    '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '141.101.64.0/18', '162.158.0.0/15', '173.245.48.0/20', '188.114.96.0/20',
    '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17'
  ];
  const ipNum = ip.split('.').reduce((a, b) => a * 256 + parseInt(b), 0);
  for (const range of cfRanges) {
    const [base, bits] = range.split('/');
    const baseNum = base.split('.').reduce((a, b) => a * 256 + parseInt(b), 0);
    const mask = ~((1 << (32 - parseInt(bits))) - 1);
    if ((ipNum & mask) === (baseNum & mask)) return true;
  }
  return false;
}

function hashResponse(res) {
  const body = res.body ? res.body.slice(0, 1024) : '';
  return crypto.createHash('md5').update(body).digest('hex') + res.status;
}

function similarityScore(hash1, hash2) {
  if (!hash1 || !hash2) return 0;
  return hash1 === hash2 ? 1 : 0.5;
}

// ========== SUBDOMAIN LIST ==========
const SUBDOMAINS = [
  'mail', 'dev', 'ftp', 'ssh', 'api', 'vpn', 'test', 'staging',
  'direct', 'origin', 'remote', 'admin', 'cpanel', 'webmail',
  'blog', 'shop', 'app', 'cdn', 'static', 'media', 'img', 'video',
  'download', 'upload', 'support', 'help', 'docs', 'wiki', 'forum',
  'community', 'status', 'dashboard', 'console', 'manage', 'portal',
  'sip', 'voip', 'ns1', 'ns2', 'mx1', 'mx2', 'smtp', 'pop3', 'imap',
  'autodiscover', 'autoconfig', 'owa', 'exchange', 'lync', 'skype',
  'gateway', 'proxy', 'sso', 'auth', 'login', 'account', 'my'
];

// ========== MAIN HANDLER ==========
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { domain } = req.query || req.body || {};
  if (!domain) {
    return res.status(400).json({ error: 'Parameter domain wajib diisi.' });
  }

  try {
    let clean = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    clean = clean.toLowerCase().trim();
    if (!clean || !clean.includes('.')) {
      return res.status(400).json({ error: 'Domain tidak valid.' });
    }

    const results = {
      domain: clean,
      origin_ip: 'tidak ditemukan',
      discovered_ips: [],
      open_ports: [],
      sources: {
        dns_direct: [],
        subdomain_enum: [],
        crt_sh: [],
        hackertarget: [],
        otx: [],
        certspotter: [],
        dns_google: []
      },
      cloudflare_detected: false,
      country: '—',
      city: '—',
      isp: '—',
      asn: '—',
      confidence: 'LOW',
      headers: {}
    };

    const allIps = new Set();

    // ========== 1. DNS DIRECT ==========
    try {
      const ipResult = await resolveHostname(clean);
      if (ipResult) {
        const valid = ipResult.filter(isValidIP);
        results.sources.dns_direct = valid;
        for (const ip of valid) allIps.add(ip);
      }
    } catch {}

    // ========== 2. SUBDOMAIN BRUTE FORCE ==========
    const subIps = [];
    for (const sub of SUBDOMAINS) {
      try {
        const fqdn = `${sub}.${clean}`;
        const ips = await resolveHostname(fqdn);
        if (ips) {
          for (const ip of ips) {
            if (isValidIP(ip) && !isCloudflareIP(ip)) {
              subIps.push(ip);
            }
          }
        }
      } catch {}
    }
    results.sources.subdomain_enum = [...new Set(subIps)];
    for (const ip of subIps) allIps.add(ip);

    // ========== 3. CLOUDFLARE DETECTION ==========
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

    // ========== 4. CRTSH ==========
    try {
      const crtRes = await fetch(`https://crt.sh/?q=%25.${clean}&output=json`, { timeout: 8000 });
      const crtData = await crtRes.json();
      if (Array.isArray(crtData)) {
        const crtIps = [];
        for (const entry of crtData) {
          if (entry.name_value && entry.name_value.includes(clean)) {
            const sub = entry.name_value.toLowerCase().trim();
            if (sub !== clean && sub.includes(clean)) {
              try {
                const subIps2 = await resolveHostname(sub);
                if (subIps2) {
                  for (const ip of subIps2) {
                    if (isValidIP(ip) && !isCloudflareIP(ip)) crtIps.push(ip);
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

    // ========== 5. CERTSPOTTER ==========
    try {
      const csRes = await fetch(`https://api.certspotter.com/v1/issuances?domain=${clean}&include_subdomains=true&expand=dns_names`, { timeout: 8000 });
      const csData = await csRes.json();
      if (Array.isArray(csData)) {
        const csIps = [];
        for (const entry of csData) {
          for (const name of entry.dns_names || []) {
            if (name.includes(clean)) {
              try {
                const ips2 = await resolveHostname(name);
                if (ips2) {
                  for (const ip of ips2) {
                    if (isValidIP(ip) && !isCloudflareIP(ip)) csIps.push(ip);
                  }
                }
              } catch {}
            }
          }
        }
        results.sources.certspotter = [...new Set(csIps)];
        for (const ip of csIps) allIps.add(ip);
      }
    } catch {}

    // ========== 6. HACKERTARGET ==========
    try {
      const htRes = await fetch(`https://api.hackertarget.com/hostsearch/?q=${clean}`, { timeout: 6000 });
      const htData = await htRes.text();
      const lines = htData.split('\n');
      const htIps = [];
      for (const line of lines) {
        const parts = line.split(',');
        if (parts.length === 2) {
          const ip = parts[1].trim();
          if (isValidIP(ip) && !isCloudflareIP(ip)) htIps.push(ip);
        }
      }
      results.sources.hackertarget = [...new Set(htIps)];
      for (const ip of htIps) allIps.add(ip);
    } catch {}

    // ========== 7. OTX ==========
    try {
      const otxRes = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${clean}/passive_dns`, { timeout: 6000 });
      const otxData = await otxRes.json();
      if (otxData.passive_dns) {
        const otxIps = otxData.passive_dns
          .map(p => p.address)
          .filter(ip => isValidIP(ip) && !isCloudflareIP(ip));
        results.sources.otx = [...new Set(otxIps)];
        for (const ip of otxIps) allIps.add(ip);
      }
    } catch {}

    // ========== 8. DNS GOOGLE ==========
    if (allIps.size === 0) {
      try {
        const dnsRes = await fetch(`https://dns.google/resolve?name=${clean}&type=A`, { timeout: 5000 });
        const dnsData = await dnsRes.json();
        if (dnsData.Answer) {
          const dnsIps = dnsData.Answer
            .filter(a => a.type === 1)
            .map(a => a.data)
            .filter(isValidIP);
          results.sources.dns_google = dnsIps;
          for (const ip of dnsIps) allIps.add(ip);
        }
      } catch {}
    }

    // ========== 9. ACTIVE ORIGIN SCANNING ==========
    let baselineHash = null;
    let baselineStatus = null;
    try {
      const baselineRes = await fetch(`https://${clean}`, { timeout: 5000 });
      baselineStatus = baselineRes.status;
      const body = await baselineRes.text();
      baselineHash = crypto.createHash('md5').update(body.slice(0, 1024)).digest('hex') + baselineRes.status;
    } catch {}

    let bestMatch = null;
    let bestScore = 0;
    if (baselineHash && allIps.size > 0) {
      for (const ip of allIps) {
        try {
          const directRes = await fetch(`http://${ip}`, {
            headers: { 'Host': clean },
            timeout: 3000
          });
          const body2 = await directRes.text();
          const directHash = crypto.createHash('md5').update(body2.slice(0, 1024)).digest('hex') + directRes.status;
          const score = directHash === baselineHash ? 1 : 0.5;
          if (score > bestScore && score > 0.4) {
            bestScore = score;
            bestMatch = ip;
          }
        } catch {}
      }
    }

    // ========== 10. DETERMINE ORIGIN IP ==========
    if (bestMatch) {
      results.origin_ip = bestMatch;
      results.confidence = bestScore > 0.9 ? 'HIGH' : bestScore > 0.7 ? 'MEDIUM' : 'LOW';
    } else if (allIps.size > 0) {
      const nonCfIps = [...allIps].filter(ip => !isCloudflareIP(ip));
      if (nonCfIps.length > 0) {
        results.origin_ip = nonCfIps[0];
        results.confidence = 'MEDIUM';
      } else {
        results.origin_ip = [...allIps][0];
        results.confidence = 'LOW';
      }
    }

    // ========== 11. PORT SCAN ==========
    if (results.origin_ip && results.origin_ip !== 'tidak ditemukan') {
      const ports = [80, 443, 8080, 8443, 3000, 3306, 22, 21, 25, 53];
      for (const port of ports) {
        const isOpen = await new Promise((resolve) => {
          const socket = new net.Socket();
          socket.setTimeout(1500);
          socket.on('connect', () => { socket.destroy(); resolve(true); });
          socket.on('timeout', () => { socket.destroy(); resolve(false); });
          socket.on('error', () => resolve(false));
          socket.connect(port, results.origin_ip);
        });
        if (isOpen) results.open_ports.push(port);
      }
    }

    // ========== 12. GEOIP ==========
    if (results.origin_ip && results.origin_ip !== 'tidak ditemukan') {
      try {
        const geoRes = await fetch(`https://ip-api.com/json/${results.origin_ip}?fields=status,country,city,isp,org,as`, { timeout: 5000 });
        const geo = await geoRes.json();
        if (geo.status === 'success') {
          results.country = geo.country || '—';
          results.city = geo.city || '—';
          results.isp = geo.isp || geo.org || '—';
          results.asn = geo.as || '—';
        }
      } catch {}
    }

    // ========== 13. KIRIM RESPON ==========
    res.status(200).json({
      domain: results.domain,
      origin_ip: results.origin_ip,
      discovered_ips: results.discovered_ips,
      open_ports: results.open_ports,
      cloudflare_detected: results.cloudflare_detected,
      country: results.country,
      city: results.city,
      isp: results.isp,
      asn: results.asn,
      confidence: results.confidence,
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
