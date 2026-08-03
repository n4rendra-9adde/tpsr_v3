'use strict';

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { Gateway, Wallets } = require('fabric-network');

function readConnectionProfile() {
  const profilePath = process.env.FABRIC_CONNECTION_PROFILE;
  if (!profilePath) {
    throw new Error('FABRIC_CONNECTION_PROFILE is required');
  }

  const resolvedPath = path.isAbsolute(profilePath)
    ? profilePath
    : path.resolve(process.cwd(), profilePath);

  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Fabric connection profile not found at ${resolvedPath}`);
  }

  const profileJson = fs.readFileSync(resolvedPath, 'utf8');
  return JSON.parse(profileJson);
}

async function getWallet() {
  const walletPath = process.env.FABRIC_WALLET_PATH;
  if (!walletPath) {
    throw new Error('FABRIC_WALLET_PATH is required');
  }

  const resolvedWalletPath = path.isAbsolute(walletPath)
    ? walletPath
    : path.resolve(process.cwd(), walletPath);

  return Wallets.newFileSystemWallet(resolvedWalletPath);
}

async function connectGateway(identityAlias) {
  if (!identityAlias) {
    throw new Error('identityAlias is required');
  }

  const connectionProfile = readConnectionProfile();
  const wallet = await getWallet();

  const identityExists = await wallet.get(identityAlias);
  if (!identityExists) {
    throw new Error(`An identity for the alias "${identityAlias}" does not exist in the wallet`);
  }

  const gateway = new Gateway();
  await gateway.connect(connectionProfile, {
    wallet,
    identity: identityAlias,
    discovery: { enabled: true, asLocalhost: true },
  });

  return gateway;
}

async function getContractForIdentity(identityAlias) {
  const channelName = process.env.FABRIC_CHANNEL_NAME;
  const chaincodeName = process.env.FABRIC_CHAINCODE_NAME;

  if (!channelName) {
    throw new Error('FABRIC_CHANNEL_NAME is required');
  }
  if (!chaincodeName) {
    throw new Error('FABRIC_CHAINCODE_NAME is required');
  }

  const gateway = await connectGateway(identityAlias);
  const network = await gateway.getNetwork(channelName);
  const contract = network.getContract(chaincodeName);

  return {
    gateway,
    network,
    contract,
  };
}

async function getContract() {
  return getContractForIdentity(process.env.FABRIC_VENDOR_IDENTITY || process.env.FABRIC_IDENTITY);
}

async function getVendorContract() {
  const identity = process.env.FABRIC_VENDOR_IDENTITY;
  if (!identity) throw new Error('FABRIC_VENDOR_IDENTITY is required');
  return getContractForIdentity(identity);
}

async function getSecurityGovernanceContract() {
  const identity = process.env.FABRIC_SECURITY_IDENTITY;
  if (!identity) throw new Error('FABRIC_SECURITY_IDENTITY is required');
  return getContractForIdentity(identity);
}

async function getAuditorContract() {
  const identity = process.env.FABRIC_AUDITOR_IDENTITY;
  if (!identity) throw new Error('FABRIC_AUDITOR_IDENTITY is required');
  return getContractForIdentity(identity);
}

function disconnectGateway(gateway) {
  if (gateway && typeof gateway.disconnect === 'function') {
    gateway.disconnect();
  }
}

module.exports = {
  readConnectionProfile,
  getWallet,
  connectGateway,
  getContract,
  getVendorContract,
  getSecurityGovernanceContract,
  getAuditorContract,
  disconnectGateway,
};
