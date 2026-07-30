const { Wallets } = require('fabric-network');
const fs = require('fs');
const path = require('path');

async function importIdentity(org, mspId, alias, overwrite = false) {
  const walletPath = path.join(__dirname, 'wallet');
  const wallet = await Wallets.newFileSystemWallet(walletPath);
  
  if (!overwrite) {
    const existing = await wallet.get(alias);
    if (existing) {
      console.log(`Identity ${alias} already exists in the wallet. Skipping.`);
      return;
    }
  }

  const credPath = path.join(__dirname, '..', 'network', 'crypto-config', 'peerOrganizations', `${org}.tpsr.com`, 'users', `Admin@${org}.tpsr.com`, 'msp');
  
  if (!fs.existsSync(credPath)) {
    throw new Error(`MSP directory not found: ${credPath}`);
  }

  const certPath = path.join(credPath, 'signcerts', `Admin@${org}.tpsr.com-cert.pem`);
  const cert = fs.readFileSync(certPath).toString();
  
  const keyDir = path.join(credPath, 'keystore');
  const keyFiles = fs.readdirSync(keyDir).filter(f => f.endsWith('_sk'));
  if (keyFiles.length !== 1) {
    throw new Error(`Ambiguous key condition: Expected exactly one private key in ${keyDir}, found ${keyFiles.length}`);
  }
  
  const keyPath = path.join(keyDir, keyFiles[0]);
  const key = fs.readFileSync(keyPath).toString();
  
  const identity = {
    credentials: {
      certificate: cert,
      privateKey: key,
    },
    mspId: mspId,
    type: 'X.509',
  };
  
  await wallet.put(alias, identity);
  console.log(`Successfully imported ${alias} to wallet`);
}

async function main() {
  const overwrite = process.argv.includes('--force');
  await importIdentity('vendor', 'VendorMSP', 'vendorAdmin', overwrite);
  await importIdentity('security', 'SecurityMSP', 'securityAdmin', overwrite);
  await importIdentity('auditor', 'AuditorMSP', 'auditorAdmin', overwrite);
}

main().catch(err => {
  console.error(err.message);
  process.exit(1);
});
