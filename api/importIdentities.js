const { Wallets } = require('fabric-network');
const fs = require('fs');
const path = require('path');

async function importIdentity(org, mspId, alias) {
  const walletPath = path.join(__dirname, 'wallet');
  const wallet = await Wallets.newFileSystemWallet(walletPath);
  
  const credPath = path.join(__dirname, '..', 'network', 'crypto-config', 'peerOrganizations', `${org}.tpsr.com`, 'users', `Admin@${org}.tpsr.com`, 'msp');
  
  const certPath = path.join(credPath, 'signcerts', `Admin@${org}.tpsr.com-cert.pem`);
  const cert = fs.readFileSync(certPath).toString();
  
  const keyDir = path.join(credPath, 'keystore');
  const keyFiles = fs.readdirSync(keyDir);
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
  await importIdentity('security', 'SecurityMSP', 'securityAdmin');
  await importIdentity('auditor', 'AuditorMSP', 'auditorAdmin');
}

main().catch(console.error);
