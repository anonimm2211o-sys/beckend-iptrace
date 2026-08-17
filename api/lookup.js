const dns = require('dns');
const net = require('net');
const { fetch, createSession } = require('wreq-js');

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { domain, mode } = req.query || req.body || {};
  if (!domain) {
    return res.status(400).json({ error: 'Parameter domain wajib diisi.' });
  }

  try {
    const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];
    const results = {
      domain: cleanDomain,
      dns_ips: [],
      origin_ip: null,
      cloudflare_detected: false,
      ports: [],
      headers: {},
      tech_stack: []
    };

    // ========== 1. DNS LOOKUP (IP ASLI) ==========
    const ips = await new Promise((resolve, reject) => {
      dns.resolve4(cleanDomain, (err, addresses) => {
        if (err) return reject(err);
        resolve(addresses);
      });
    });
    results.dns_ips = ips;

    // ========== 2. CF BYPASS + HEADER CAPTURE pake wreq-js ==========
    let session = null;
    let realIp = null;
    let isBehindCF = false;

    try {
      session = await createSession({
        browser: 'chrome_142',
        os: 'windows'
      });

      const cfTest = await session.fetch(`https://${cleanDomain}`, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/142.0.0.0 Safari/537.36'
        }
      });

      // Cek header Cloudflare
      const cfRay = cfTest.headers.get('cf-ray');
      const cfCache = cfTest.headers.get('cf-cache-status');
      const server = cfTest.headers.get('server') || '';

      isBehindCF = !!(cfRay || cfCache || server.includes('cloudflare'));

      results.cloudflare_detected = isBehindCF;
      results.headers = Object.fromEntries(cfTest.headers.entries());

      // ========== 3. Coba dapetin IP asli lewat header CF-Connecting-IP ==========
      if (isBehindCF) {
        const connectingIp = cfTest.headers.get('cf-connecting-ip') ||
                             cfTest.headers.get('true-client-ip') ||
                             cfTest.headers.get('x-forwarded-for')?.split(',')[0];
        if (connectingIp) {
          realIp = connectingIp;
          results.origin_ip = realIp;
        }
      }

      // Kalo ga dapet dari CF header, fallback ke DNS
      if (!realIp && ips.length > 0) {
        realIp = ips[0];
        results.origin_ip = realIp;
      }

      // ========== 4. PORT SCANNING (TCP Connect) ==========
      const portsToScan = [80, 443, 8080, 8443, 3000, 3306, 22, 21, 25, 587, 993, 995, 53, 123, 1433, 5432, 6379, 9200, 27017];
      const openPorts = [];

      if (realIp && realIp !== 'tidak ditemukan') {
        for (const port of portsToScan) {
          const isOpen = await new Promise((resolve) => {
            const socket = new net.Socket();
            socket.setTimeout(1500);

            socket.on('connect', () => {
              socket.destroy();
              resolve(true);
            });

            socket.on('timeout', () => {
              socket.destroy();
              resolve(false);
            });

            socket.on('error', () => {
              resolve(false);
            });

            socket.connect(port, realIp);
          });

          if (isOpen) openPorts.push(port);
        }
      }
      results.ports = openPorts;

    } catch (err) {
      // Fallback kalo wreq-js gagal (misal di Vercel ga support Rust)
      console.warn('[!] wreq-js fallback:', err.message);
      results.origin_ip = ips[0] || null;
    } finally {
      if (session) await session.close();
    }

    // ========== 5. RESULT FINAL ==========
    res.status(200).json({
      status: 'success',
      data: {
        domain: results.domain,
        detected_cloudflare: results.cloudflare_detected,
        origin_ip: results.origin_ip || results.dns_ips[0] || 'tidak ditemukan',
        dns_ips: results.dns_ips,
        open_ports: results.ports,
        headers: results.headers
      }
    });

  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message || 'Terjadi kesalahan di server.'
    });
  }
};
