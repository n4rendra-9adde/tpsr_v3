const fabric = require('../fabric');
const fs = require('fs');
const { Gateway, Wallets } = require('fabric-network');

jest.mock('fs');
jest.mock('fabric-network', () => ({
  Gateway: jest.fn().mockImplementation(() => ({
    connect: jest.fn().mockResolvedValue(),
    disconnect: jest.fn(),
    getNetwork: jest.fn().mockResolvedValue({
      getContract: jest.fn().mockReturnValue({}),
    }),
  })),
  Wallets: {
    newFileSystemWallet: jest.fn(),
  },
}));

describe('Fabric Startup Configuration Validation', () => {
  let originalEnv;

  beforeEach(() => {
    originalEnv = process.env;
    process.env = { ...originalEnv };
    jest.clearAllMocks();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  test('readConnectionProfile throws if FABRIC_CONNECTION_PROFILE is missing', () => {
    delete process.env.FABRIC_CONNECTION_PROFILE;
    expect(() => fabric.readConnectionProfile()).toThrow('FABRIC_CONNECTION_PROFILE is required');
  });

  test('getWallet throws if FABRIC_WALLET_PATH is missing', async () => {
    delete process.env.FABRIC_WALLET_PATH;
    await expect(fabric.getWallet()).rejects.toThrow('FABRIC_WALLET_PATH is required');
  });

  test('getContractForIdentity checks if identity exists in wallet', async () => {
    process.env.FABRIC_CONNECTION_PROFILE = 'profile.json';
    process.env.FABRIC_WALLET_PATH = 'wallet';
    process.env.FABRIC_CHANNEL_NAME = 'tpsrchannel';
    process.env.FABRIC_CHAINCODE_NAME = 'sbom';
    
    fs.existsSync.mockReturnValue(true);
    fs.readFileSync.mockReturnValue('{}');
    
    const mockWallet = {
      get: jest.fn().mockResolvedValue(false), // identity not found
    };
    Wallets.newFileSystemWallet.mockResolvedValue(mockWallet);

    await expect(fabric.getVendorContract()).rejects.toThrow('FABRIC_VENDOR_IDENTITY is required');
    
    process.env.FABRIC_VENDOR_IDENTITY = 'missingAdmin';
    await expect(fabric.getVendorContract()).rejects.toThrow('An identity for the alias "missingAdmin" does not exist in the wallet');
  });

  test('getSecurityGovernanceContract throws if identity is missing from config', async () => {
    delete process.env.FABRIC_SECURITY_IDENTITY;
    await expect(fabric.getSecurityGovernanceContract()).rejects.toThrow('FABRIC_SECURITY_IDENTITY is required');
  });

  test('getAuditorContract throws if identity is missing from config', async () => {
    delete process.env.FABRIC_AUDITOR_IDENTITY;
    await expect(fabric.getAuditorContract()).rejects.toThrow('FABRIC_AUDITOR_IDENTITY is required');
  });
});
