const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

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

    // Clone CloudRecon kalo belum ada di /tmp
    const cloudreconDir = '/tmp/cloudrecon';
    if (!fs.existsSync(cloudreconDir)) {
      await new Promise((resolve, reject) => {
        exec(
          `git clone https://github.com/intspired/CloudRecon.git ${cloudreconDir}`,
          (error, stdout, stderr) => {
            if (error) return reject(error);
            resolve(stdout);
          }
        );
      });
    }

    // Jalanin CloudRecon mode passive
    const outputFile = `/tmp/${clean}_recon.json`;
    await new Promise((resolve, reject) => {
      exec(
        `python3 ${cloudreconDir}/recon.py ${clean} --passive --output --output-file ${outputFile}`,
        { timeout: 30000 },
        (error, stdout, stderr) => {
          if (error) return reject(error);
          resolve(stdout);
        }
      );
    });

    // Baca hasil JSON
    const result = JSON.parse(fs.readFileSync(outputFile, 'utf8'));

    res.status(200).json({
      domain: clean,
      origin_ip: result.origin_ip || 'tidak ditemukan',
      discovered_ips: result.discovered_ips || [],
      sources: result.sources || {},
      open_ports: result.open_ports || []
    });

  } catch (err) {
    res.status(500).json({ error: err.message || 'Terjadi kesalahan.' });
  }
};
