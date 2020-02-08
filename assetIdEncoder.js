const digibyte = require('digibyte');
const bs58check = digibyte.encoding.Base58Check;
const bech32 = require('bech32');
const Opcode = digibyte.Opcode;
const hash = require('crypto-hashing');
const debug = require('debug')('assetIdEncoder');
const UNLOCKEPADDING = {
  aggregatable: 0x2e37,
  hybrid: 0x2e6b,
  dispersed: 0x2e4e
};
const LOCKEPADDING = {
  aggregatable: 0x20ce,
  hybrid: 0x2102,
  dispersed: 0x20e4
};
const DGB_P2PKH = 0x1e;
const BTC_TESTNET_P2PKH = 0x6f;
const DGB_P2SH = 0x3f;
const DGB_P2SH_LEGACY = 0x05;
const BTC_TESTNET_P2SH = 0xc4;
const NETWORKVERSIONS = [DGB_P2PKH, BTC_TESTNET_P2PKH, DGB_P2SH, DGB_P2SH_LEGACY, BTC_TESTNET_P2SH];
const POSTFIXBYTELENGTH = 2;

const padLeadingZeros = function (hex, byteSize) {
  if (!byteSize) {
    byteSize = Math.ceil(hex.length / 2);
  }
  return (hex.length === byteSize * 2) ? hex : padLeadingZeros('0' + hex, byteSize);
}

const createIdFromTxidIndex = function (txid, index, padding, divisibility) {
  debug('createIdFromTxidIndex');
  debug('txid = ', txid, ', index = ', index);
  const str = txid + ':' + index;
  return hashAndBase58CheckEncode(str, padding, divisibility);
}

const createIdFromPreviousOutputScriptPubKey = function (previousOutputHex, padding, divisibility) {
  const buffer = Buffer.from(previousOutputHex, 'hex');
  debug('buffer = ', buffer);
  return hashAndBase58CheckEncode(buffer, padding, divisibility);
}

const createIdFromPubKeyHashInput = function (scriptSig, padding, divisibility) {
  debug('createIdFromPubKeyHashInput');
  if (!scriptSig.asm) {
    scriptSig.asm = new digibyte.Script(scriptSig.hex).toASM();
  }
  let publicKey = scriptSig.asm.split(' ')[1];
  debug('publicKey = ', publicKey);
  publicKey = Buffer.from(publicKey, 'hex');
  const pubKey = new digibyte.PublicKey(publicKey);
  const pubKeyHashOutput = digibyte.Script.buildPublicKeyHashOut(pubKey).toBuffer();
  debug('pubKeyHashOutput = ', pubKeyHashOutput);
  return hashAndBase58CheckEncode(pubKeyHashOutput, padding, divisibility);
}

const createIdFromScriptHashInput = function (scriptSig, padding, divisibility) {
  debug('createIdFromScriptHashInput');
  const buffer = scriptSig.hex ? Buffer.from(scriptSig.hex, 'hex') : digibyte.Script.fromASM(scriptSig.asm)
  debug('buffer = ', buffer)
  const chunks = new digibyte.Script(buffer).chunks;
  const lastChunk = chunks[chunks.length - 1].buf;
  debug('lastChunk = ', lastChunk)
  let redeemScriptChunks = new digibyte.Script(lastChunk).chunks;
  redeemScriptChunks = redeemScriptChunks.map(chunk => Buffer.isBuffer(chunk.buf) ? chunk.buf : Buffer.from(chunk.opcodenum.toString(16), 'hex'));
  const redeemScript = Buffer.concat(redeemScriptChunks);
  debug('redeemScript = ', redeemScript)
  const scriptHashOutput = digibyte.Script.buildScriptHashOut(new digibyte.Script(redeemScript)).toBuffer();
  return hashAndBase58CheckEncode(scriptHashOutput, padding, divisibility)
}

const createIdFromAddress = function (address, padding, divisibility) {
  debug('createIdFromAddress');
  let addressBuffer;
  let versionBuffer;
  let version = 0;
  try {
    addressBuffer = bs58check.decode(address);
    versionBuffer = addressBuffer.slice(0, 1);
    version = parseInt(versionBuffer.toString('hex'), 16);
    if (NETWORKVERSIONS.indexOf(version) === -1) throw new Error('Unrecognized address network')
    if (version === DGB_P2SH || version === DGB_P2SH_LEGACY || version === BTC_TESTNET_P2SH) {
      const scriptHash = addressBuffer.slice(versionBuffer.length, 21);
      const s = new digibyte.Script();
      s.add(Opcode.OP_HASH160)
        .add(scriptHash)
        .add(Opcode.OP_EQUAL);
        s.network = 'livenet';
      return hashAndBase58CheckEncode(s.toBuffer(), padding, divisibility);
    }
    if (version === DGB_P2PKH || version === BTC_TESTNET_P2PKH) {
      const pubKeyHash = addressBuffer.slice(versionBuffer.length, 21);
      const s = new digibyte.Script();
      s.add(Opcode.OP_DUP)
        .add(Opcode.OP_HASH160)
        .add(pubKeyHash)
        .add(Opcode.OP_EQUALVERIFY)
        .add(Opcode.OP_CHECKSIG);
      s.network = 'livenet';
      debug('pubKeyHashOutput = ', s.toBuffer());
      return hashAndBase58CheckEncode(s.toBuffer(), padding, divisibility);
    }
  } catch (e) {
    console.log(e)
    const result = bech32.decode(address);
    const info = {
      prefix: result.prefix,
      data: Buffer.from(bech32.fromWords(result.words.slice(1))),
      version: result.words[0]      
    };
    addressBuffer = info.data;
    if (info.data.length === 20) {
      const s = new digibyte.Script();
      s.add(Opcode.OP_DUP)
        .add(Opcode.OP_HASH160)
        .add(info.data)
        .add(Opcode.OP_EQUALVERIFY)
        .add(Opcode.OP_CHECKSIG);
      s.network = 'livenet';
      return hashAndBase58CheckEncode(s.toBuffer(), padding, divisibility);
    } else if (info.data.length === 32) {
      // TODO
    }
  }
}

const hashAndBase58CheckEncode = function (payloadToHash, padding, divisibility) {
  debug('hashAndBase58CheckEncode');
  debug('padding and divisibility = ' + padding.toString(16) + ', ' + divisibility);
  const hash256 = hash.sha256(payloadToHash);
  const hash160 = hash.ripemd160(hash256);
  debug('hash160 = ', hash160);
  padding = Buffer.from(padLeadingZeros(padding.toString(16)), 'hex');
  divisibility = Buffer.from(padLeadingZeros(divisibility.toString(16), POSTFIXBYTELENGTH), 'hex');
  const concatenation = Buffer.concat([padding, hash160, divisibility]);
  return bs58check.encode(concatenation);
}

module.exports = function (digibyteTransaction) {
  debug('digibyteTransaction.txid = ', digibyteTransaction.txid);
  if (!digibyteTransaction.dadata) throw new Error('Missing DigiAsset Metadata');
  if (digibyteTransaction.dadata[0].type !== 'issuance') throw new Error('Not An issuance transaction');
  if (typeof digibyteTransaction.dadata[0].lockStatus === 'undefined') throw new Error('Missing Lock Status data');
  const lockStatus = digibyteTransaction.dadata[0].lockStatus;
  const aggregationPolicy = digibyteTransaction.dadata[0].aggregationPolicy || 'aggregatable';
  const divisibility = digibyteTransaction.dadata[0].divisibility || 0;
  const firstInput = digibyteTransaction.vin[0];
  let padding;
  if (lockStatus) {
    padding = LOCKEPADDING[aggregationPolicy];
    return createIdFromTxidIndex(firstInput.txid, firstInput.vout, padding, divisibility);
  }

  padding = UNLOCKEPADDING[aggregationPolicy];
  if (firstInput.previousOutput && firstInput.previousOutput.hex) {
    return createIdFromPreviousOutputScriptPubKey(firstInput.previousOutput.hex, padding, divisibility);
  }

  if (firstInput.scriptSig && (firstInput.scriptSig.hex || firstInput.scriptSig.asm)) {
    const scriptSig = firstInput.scriptSig;
    scriptSig.hex = scriptSig.hex || digibyte.Script.fromASM(scriptSig.asm).toBuffer().toString('hex');
    debug('scriptSig.hex = ', scriptSig.hex);
    const buffer = Buffer.from(scriptSig.hex, 'hex');
    const script = new digibyte.Script(buffer);
    if (script.isPublicKeyHashIn()) {
      return createIdFromPubKeyHashInput(scriptSig, padding, divisibility);
    }
    if (script.isScriptHashIn()) {
      return createIdFromScriptHashInput(scriptSig, padding, divisibility);
    }
  }

  if (firstInput.address) {
    return createIdFromAddress(firstInput.address, padding, divisibility);
  }
}