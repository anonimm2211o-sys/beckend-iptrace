const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');
const net = require('net');
const dns = require('dns');
const crypto = require('crypto');

// ========== HELPER: RESOLVE HOSTNAME ==========
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

// ========== HELPER: CEK IP VALID ==========
function isValidIP(ip) {
  return ip && typeof ip === 'string' && ip.match(/^\d+\.\d+\.\d+\.\d+$/);
}

// ========== HELPER: CEK CLOUDFLARE IP RANGE ==========
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

// ========== SUBDOMAIN LIST (100+) ==========
const SUBDOMAINS = [
  'mail', 'dev', 'ftp', 'ssh', 'api', 'vpn', 'test', 'staging',
  'direct', 'origin', 'remote', 'admin', 'cpanel', 'webmail',
  'blog', 'shop', 'app', 'cdn', 'static', 'media', 'img', 'video',
  'download', 'upload', 'support', 'help', 'docs', 'wiki', 'forum',
  'community', 'status', 'dashboard', 'console', 'manage', 'portal',
  'sip', 'voip', 'ns1', 'ns2', 'mx1', 'mx2', 'smtp', 'pop3', 'imap',
  'autodiscover', 'autoconfig', 'owa', 'exchange', 'lync', 'skype',
  'gateway', 'proxy', 'sso', 'auth', 'login', 'account', 'my',
  'www2', 'www3', 'web', 'files', 'assets', 'res', 'images',
  'js', 'css', 'fonts', 'data', 'backup', 'old', 'new', 'beta',
  'demo', 'stage', 'prod', 'production', 'live', 'dev2'
];

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
      asn: '—',
      cloudflare_detected: false,
      confidence: 'LOW',
      sources: {}
    };

    const allIps = new Set();

    // ========== 1. CLOUDRECON (Python) ==========
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
      const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
      const ips = [...new Set(reconResult.match(ipRegex) || [])];
      for (const ip of ips) allIps.add(ip);
      results.sources.cloudrecon = true;
      results.cloudflare_detected = reconResult.includes('Cloudflare NS') || reconResult.toLowerCase().includes('cloudflare');
    } catch (err) {
      console.warn('CloudRecon error:', err.message);
      results.sources.cloudrecon = false;
    }

    // ========== 2. SUBDOMAIN BRUTE FORCE ==========
    for (const sub of SUBDOMAINS) {
      try {
        const fqdn = `${sub}.${clean}`;
        const ips = await resolveHostname(fqdn);
        if (ips) {
          for (const ip of ips) {
            if (isValidIP(ip) && !isCloudflareIP(ip)) {
              allIps.add(ip);
            }
          }
        }
      } catch {}
    }
    results.sources.subdomain_bruteforce = true;

    // ========== 3. CERTIFICATE TRANSPARENCY (crt.sh) ==========
    try {
      const crtRes = await fetch(`https://crt.sh/?q=%25.${clean}&output=json`, { timeout: 8000 });
      const crtData = await crtRes.json();
      if (Array.isArray(crtData)) {
        for (const entry of crtData) {
          if (entry.name_value && entry.name_value.includes(clean)) {
            const sub = entry.name_value.toLowerCase().trim();
            if (sub !== clean && sub.includes(clean)) {
              try {
                const subIps = await resolveHostname(sub);
                if (subIps) {
                  for (const ip of subIps) {
                    if (isValidIP(ip) && !isCloudflareIP(ip)) allIps.add(ip);
                  }
                }
              } catch {}
            }
          }
        }
      }
      results.sources.crt_sh = true;
    } catch {}

    // ========== 4. HACKERTARGET DNS HISTORY ==========
    try {
      const htRes = await fetch(`https://api.hackertarget.com/hostsearch/?q=${clean}`, { timeout: 6000 });
      const htData = await htRes.text();
      const lines = htData.split('\n');
      for (const line of lines) {
        const parts = line.split(',');
        if (parts.length === 2) {
          const ip = parts[1].trim();
          if (isValidIP(ip) && !isCloudflareIP(ip)) allIps.add(ip);
        }
      }
      results.sources.hackertarget = true;
    } catch {}

    // ========== 5. OTX ALIENVAULT PASSIVE DNS ==========
    try {
      const otxRes = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${clean}/passive_dns`, { timeout: 6000 });
      const otxData = await otxRes.json();
      if (otxData.passive_dns) {
        for (const record of otxData.passive_dns) {
          const ip = record.address;
          if (isValidIP(ip) && !isCloudflareIP(ip)) allIps.add(ip);
        }
      }
      results.sources.otx = true;
    } catch {}

    // ========== 6. DNS GOOGLE ==========
    try {
      const dnsRes = await fetch(`https://dns.google/resolve?name=${clean}&type=A`);
      const dnsData = await dnsRes.json();
      if (dnsData.Answer) {
        for (const a of dnsData.Answer) {
          if (a.type === 1 && a.data) {
            const ip = a.data;
            if (isValidIP(ip) && !isCloudflareIP(ip)) allIps.add(ip);
          }
        }
      }
      results.sources.dns_google = true;
    } catch {}

    // ========== 7. ACTIVE ORIGIN SCANNING ==========
    let baselineHash = null;
    try {
      const baselineRes = await fetch(`https://${clean}`, { timeout: 5000 });
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

    // ========== 8. DETERMINE ORIGIN IP ==========
    if (bestMatch) {
      results.origin_ip = bestMatch;
      results.confidence = 'HIGH';
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

    results.discovered_ips = [...allIps];

    // ========== 9. GEOIP ==========
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

    // ========== 10. PORT SCAN ==========
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

    // ========== 11. KIRIM RESPON ==========
    res.status(200).json(results);

  } catch (err) {
    res.status(500).json({ error: err.message || 'Terjadi kesalahan.' });
  }
};
