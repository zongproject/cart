// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include <iostream>

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x19;
        pchMessageStart[1] = 0xf3;
        pchMessageStart[2] = 0x9a;
        pchMessageStart[3] = 0x54;
        vAlertPubKey = ParseHex("04128d00de3b13a00fd3e6e69b6487f4d16415c7e18fbc2a3088212e915e022722f0c1c7154254cb7dacc569c799f55c8f97ecd6b7dcc92a8855d4040d19ca8082");
        nDefaultPort = 54321;
        nRPCPort = 54320;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);

        const char* pszTimestamp = "Samsung Galaxy S10 Will Have InBuilt Cryptocurrency Wallet";
        std::vector<CTxIn> vin;
        std::vector<CTxOut> vout;
        vin.resize(1);
        vout.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        vout[0].nValue = 0;
        vout[0].scriptPubKey = CScript() << ParseHex("04c629dd47950d15c4f63db4e67247335e09dec8b4ca4c157a23858e2503709e5fe3ba75d5b5263b046ae4b20af135a4dc79e66123ad9a15e65a98798bfee60724") << OP_CHECKSIG;
        CTransaction txNew(1, 1551265533, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1551265533;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 30074010;
		
		
/*
nNonce is: 30074010
Hash is: 000001e618e2bed97d574602b5dd51fbba827a600a4758461be8bcd162c4347d
Block is: CBlock(hash=000001e618e2bed97d574602b5dd51fbba827a600a4758461be8bcd162c4347d, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=4a09612a7a64cabe1d27c6e94f7e10b2e86853353ecb4fc2c2c675e87a530232, nTime=1551265533, nBits=1e0fffff, nNonce=30074010, vtx=1, vchBlockSig=)
  Coinbase(hash=4a09612a7a64cabe1d27c6e94f7e10b2e86853353ecb4fc2c2c675e87a530232, nTime=1551265533, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a3a53616d73756e672047616c617879205331302057696c6c204861766520496e4275696c742043727970746f63757272656e63792057616c6c6574)
    CTxOut(nValue=0.00, scriptPubKey=04c629dd47950d15c4f63db4e67247335e09dec8b4ca4c157a23858e2503709e5fe3ba75d5b5263b046ae4b20af135a4dc79e66123ad9a15e65a98798bfee60724 OP_CHECKSIG)

  vMerkleTree:  4a09612a7a64cabe1d27c6e94f7e10b2e86853353ecb4fc2c2c675e87a530232

*/

        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x000001e618e2bed97d574602b5dd51fbba827a600a4758461be8bcd162c4347d"));
        assert(genesis.hashMerkleRoot == uint256("0x4a09612a7a64cabe1d27c6e94f7e10b2e86853353ecb4fc2c2c675e87a530232"));
                
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 28); // C
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 87); // c
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 45); // K
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x89)(0x39)(0x62).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xb5)(0x18).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        nLastPOWBlock = 100;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x37;
        pchMessageStart[1] = 0x19;
        pchMessageStart[2] = 0xa7;
        pchMessageStart[3] = 0x4c;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("04f23c200c79d5ee12ae7caa912c40e121c6b3ddad9d8d01c986e57eb62320c66df892275db5cf4628ef5757232222f0b6a930f20e3bb9304a0d127f030c741fb4");
        nDefaultPort = 64321;
        nRPCPort = 64320;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 66143;

        hashGenesisBlock = genesis.GetHash();

/*
testnet nNonce is: 66143
Hash is: 00000ad57b1a3a80607a27185838b037a37224dbc0db5b7d49878e733b4914e7
Block is: CBlock(hash=00000ad57b1a3a80607a27185838b037a37224dbc0db5b7d49878e733b4914e7, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=4a09612a7a64cabe1d27c6e94f7e10b2e86853353ecb4fc2c2c675e87a530232, nTime=1551265533, nBits=1f00ffff, nNonce=66143, vtx=1, vchBlockSig=)
  Coinbase(hash=4a09612a7a64cabe1d27c6e94f7e10b2e86853353ecb4fc2c2c675e87a530232, nTime=1551265533, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a3a53616d73756e672047616c617879205331302057696c6c204861766520496e4275696c742043727970746f63757272656e63792057616c6c6574)
    CTxOut(nValue=0.00, scriptPubKey=04c629dd47950d15c4f63db4e67247335e09dec8b4ca4c157a23858e2503709e5fe3ba75d5b5263b046ae4b20af135a4dc79e66123ad9a15e65a98798bfee60724 OP_CHECKSIG)

  vMerkleTree:  4a09612a7a64cabe1d27c6e94f7e10b2e86853353ecb4fc2c2c675e87a530232

*/

        assert(hashGenesisBlock == uint256("0x00000ad57b1a3a80607a27185838b037a37224dbc0db5b7d49878e733b4914e7"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 65); // T
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 127); // t
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 58); // Q
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x19)(0x55).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x25)(0x63).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        nLastPOWBlock = 0x7fffffff;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    
    bool fTestNet = GetBoolArg("-testnet", false);
    
    if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
