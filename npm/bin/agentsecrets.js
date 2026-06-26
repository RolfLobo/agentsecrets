#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const https = require('https');
const tar = require('tar');

const PACKAGE_JSON = require('../package.json');
const VERSION = PACKAGE_JSON.version;
const GITHUB_REPO = "The-17/agentsecrets";

function getPlatformInfo() {
  const type = os.type();
  const arch = os.arch();

  let os_name = '';
  if (type === 'Darwin') os_name = 'darwin';
  else if (type === 'Linux') os_name = 'linux';
  else if (type === 'Windows_NT') os_name = 'windows';

  let arch_name = '';
  if (arch === 'x64') arch_name = 'amd64';
  else if (arch === 'arm64') arch_name = 'arm64';
  else if (arch === 'ia32') arch_name = '386';

  return { os_name, arch_name };
}

async function downloadBinary(url, dest, isZip = false) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        const nextIsZip = isZip || url.split('?')[0].endsWith('.zip');
        return downloadBinary(res.headers.location, dest, nextIsZip).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to download: ${res.statusCode}`));
      }

      const tempDir = path.join(os.tmpdir(), `agentsecrets-${Date.now()}`);
      fs.mkdirSync(tempDir, { recursive: true });

      const isWin = isZip || url.split('?')[0].endsWith('.zip');
      if (isWin) {
        const zipPath = path.join(tempDir, 'archive.zip');
        const fileStream = fs.createWriteStream(zipPath);
        res.pipe(fileStream);
        fileStream.on('finish', () => {
          fileStream.close(() => {
            const { execSync } = require('child_process');
            try {
              // Use ErrorActionPreference = Stop so PowerShell errors trigger execSync failure
              execSync('powershell.exe -NoProfile -Command "$ErrorActionPreference = \'Stop\'; Expand-Archive -Path \'' + zipPath + '\' -DestinationPath \'' + tempDir + '\' -Force"', { stdio: 'pipe' });
              const binaryName = 'agentsecrets.exe';
              const src = path.join(tempDir, binaryName);
              if (fs.existsSync(src)) {
                fs.mkdirSync(path.dirname(dest), { recursive: true });
                fs.renameSync(src, dest);
                resolve();
              } else {
                reject(new Error('Binary ' + binaryName + ' not found in zip archive'));
              }
            } catch (err) {
              const stderr = err.stderr ? err.stderr.toString() : '';
              reject(new Error('Failed to extract ZIP archive on Windows: ' + err.message + '\nPowerShell Error: ' + stderr));
            }
          });
        });
        fileStream.on('error', reject);
        return;
      }

      res.pipe(tar.x({ C: tempDir }))
        .on('finish', () => {
          const binaryName = os.platform() === 'win32' ? 'agentsecrets.exe' : 'agentsecrets';
          const src = path.join(tempDir, binaryName);
          if (fs.existsSync(src)) {
            fs.mkdirSync(path.dirname(dest), { recursive: true });
            fs.renameSync(src, dest);
            fs.chmodSync(dest, 0o755);

            // Pre-register with keychain-auth if available. This eliminates
            // the one-time setup spinner on the user's first command.
            try {
              const { execFileSync } = require('child_process');
              execFileSync('keychain-auth', ['register', dest], {
                timeout: 5000,
                stdio: 'ignore',
              });
            } catch (_) {
              // Silent — AutoSetup handles registration at runtime if needed
            }

            resolve();
          } else {
            reject(new Error(`Binary ${binaryName} not found in archive`));
          }
        })
        .on('error', reject);
    }).on('error', reject);
  });
}

async function getLatestVersion() {
  return new Promise((resolve, reject) => {
    https.get({
      hostname: 'api.github.com',
      path: `/repos/${GITHUB_REPO}/releases/latest`,
      headers: { 'User-Agent': 'agentsecrets-npm' }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.tag_name) {
            resolve(json.tag_name.replace(/^v/, ''));
          } else {
            reject(new Error('No tag_name in latest release'));
          }
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

async function getBinaryPath() {
  const { os_name, arch_name } = getPlatformInfo();
  const binDir = path.join(os.homedir(), '.agentsecrets', 'bin');
  const binaryName = os_name === 'windows' ? 'agentsecrets.exe' : 'agentsecrets';
  
  // Try to get the latest version from GitHub
  let version = VERSION;
  try {
    version = await getLatestVersion();
    console.log(`Latest AgentSecrets version: ${version}`);
  } catch (err) {
    console.error(`Failed to fetch latest version from GitHub: ${err.message}. Falling back to package version ${VERSION}.`);
  }

  const binaryPath = path.join(binDir, `${binaryName}_${version}`);

  if (fs.existsSync(binaryPath)) {
    return binaryPath;
  }

  console.error(`AgentSecrets binary not found. Downloading v${version} for ${os_name}/${arch_name}...`);

  const ext = os_name === 'windows' ? 'zip' : 'tar.gz';
  const assetName = `agentsecrets_${version}_${os_name}_${arch_name}.${ext}`;
  const url = `https://github.com/${GITHUB_REPO}/releases/download/v${version}/${assetName}`;

  try {
    await downloadBinary(url, binaryPath);
    return binaryPath;
  } catch (err) {
    throw new Error(`Failed to download AgentSecrets binary: ${err.message}\nURL: ${url}`);
  }
}

async function main() {
  try {
    const binaryPath = await getBinaryPath();
    const args = process.argv.slice(2);
    const proc = spawn(binaryPath, args, { stdio: 'inherit' });
    proc.on('close', (code) => process.exit(code || 0));
    proc.on('error', (err) => {
      console.error(`Failed to execute AgentSecrets: ${err.message}`);
      process.exit(1);
    });
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { getBinaryPath };
