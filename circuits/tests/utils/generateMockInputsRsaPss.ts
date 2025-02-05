import * as forge from 'node-forge';

import { SignatureAlgorithm } from '../../../common/src/utils/types';
import { hexToDecimal } from '../../../common/src/utils/bytes';
import { bytesToBigDecimal } from '../../../common/src/utils/bytes';
import { getNAndK } from '../../../common/src/utils/passports/passport';
import { splitToWords } from '../../../common/src/utils/bytes';

export const generateMockRsaPssInputs = (
  signatureAlgorithm: SignatureAlgorithm,
  saltLength: number
) => {
  const [sigAlg, hashAlgorithm, exponent, modulusLength] = signatureAlgorithm.split('_');

  // Generate RSA key pair
  const keypair = forge.pki.rsa.generateKeyPair({
    bits: parseInt(modulusLength),
    e: parseInt(exponent),
  });
  const message = 'helloworld';

  // Create message hash
  const md = forge.md[hashAlgorithm].create();
  md.update(forge.util.binary.raw.encode(Buffer.from(message)));
  const messageHash = md.digest().bytes();
  const messageBits = Array.from(messageHash)
    .map((char: string) => {
      const byte = char.charCodeAt(0);
      return Array.from({ length: 8 }, (_, i) => (byte >> (7 - i)) & 1);
    })
    .flat();

  // Create PSS signature
  const pss = forge.pss.create({
    md: forge.md[hashAlgorithm].create(),
    mgf: forge.mgf.mgf1.create(forge.md[hashAlgorithm].create()),
    saltLength,
  });
  const signatureBytes = keypair.privateKey.sign(md, pss);
  const signature = Array.from(signatureBytes, (c: string) => c.charCodeAt(0));

  // Get modulus from public key
  const modulus = keypair.publicKey.n.toString(16);

  const { n, k } = getNAndK(signatureAlgorithm);

  return {
    signature: splitToWords(BigInt(bytesToBigDecimal(signature)), n, k),
    modulus: splitToWords(BigInt(hexToDecimal(modulus)), n, k),
    message: messageBits,
    n,
    k,
  };
};

export const generateMalleableRsaPssInputs = (
  signatureAlgorithm: SignatureAlgorithm,
  saltLength: number
) => {
  const [sigAlg, hashAlgorithm, exponent, modulusLength] = signatureAlgorithm.split('_');
  
  // Generate RSA key pair
  const keypair = forge.pki.rsa.generateKeyPair({
    bits: parseInt(modulusLength),
    e: parseInt(exponent),
  });
  
  const message = 'helloworld';
  const md = forge.md[hashAlgorithm].create();
  md.update(forge.util.binary.raw.encode(Buffer.from(message)));
  const messageHash = md.digest().bytes();
  
  // Create valid signature
  const pss = forge.pss.create({
    md: forge.md[hashAlgorithm].create(),
    mgf: forge.mgf.mgf1.create(forge.md[hashAlgorithm].create()),
    saltLength,
  });
  
  const signatureBytes = keypair.privateKey.sign(md, pss);
  const signature = Array.from(signatureBytes, (c: string) => c.charCodeAt(0));
  
  const modulus = BigInt('0x' + keypair.publicKey.n.toString(16));
  const sigValue = BigInt(bytesToBigDecimal(signature));
  const malleableValue = sigValue + modulus;
  
  const { n, k } = getNAndK(signatureAlgorithm);
  
  return {
    signature: splitToWords(malleableValue, n, k),
    modulus: splitToWords(modulus, n, k),
    message: Array.from(messageHash).map((char: string) => {
      const byte = char.charCodeAt(0);
      return Array.from({ length: 8 }, (_, i) => (byte >> (7 - i)) & 1);
    }).flat()
  };
};