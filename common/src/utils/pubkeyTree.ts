import {
  PUBKEY_TREE_DEPTH,
  COMMITMENT_TREE_TRACKER_URL,
  SignatureAlgorithmIndex,
} from '../constants/constants';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import axios from 'axios';
import { poseidon16, poseidon2, poseidon6, poseidon7 } from 'poseidon-lite';
import { formatDg2Hash, getNAndK, getNAndKCSCA, hexToDecimal, splitToWords } from './utils';
import { parseCertificate } from './certificates/handleCertificate';
import { flexiblePoseidon } from './poseidon';
import { SignatureAlgorithm } from './types';

export function customHasher(pubKeyFormatted: string[]) {
  const rounds = Math.ceil(pubKeyFormatted.length / 16);
  const hash = new Array(rounds);
  for (let i = 0; i < rounds; i++) {
    hash[i] = { inputs: new Array(16).fill(BigInt(0)) };
  }
  for (let i = 0; i < rounds; i++) {
    for (let j = 0; j < 16; j++) {
      if (i * 16 + j < pubKeyFormatted.length) {
        hash[i].inputs[j] = BigInt(pubKeyFormatted[i * 16 + j]);
      }
    }
  }
  const finalHash = flexiblePoseidon(hash.map((h) => poseidon16(h.inputs)));
  return finalHash.toString();
}

export function getLeaf(dsc: string): string {
  const { signatureAlgorithm, hashFunction, modulus, x, y, bits, curve, exponent } =
    parseCertificate(dsc);
  const { n, k } = getNAndK(signatureAlgorithm);
  const sigAlgKey = `${signatureAlgorithm}_${hashFunction}_${curve || exponent}_${bits}`;
  const sigAlgIndex = SignatureAlgorithmIndex[sigAlgKey];

  if (sigAlgIndex == undefined) {
    console.error(`\x1b[31mInvalid signature algorithm: ${sigAlgKey}\x1b[0m`);
    throw new Error(`Invalid signature algorithm: ${sigAlgKey}`);
  }
  if (signatureAlgorithm === 'ecdsa') {
    let qx = splitToWords(BigInt(hexToDecimal(x)), n, k);
    let qy = splitToWords(BigInt(hexToDecimal(y)), n, k);
    return customHasher([sigAlgIndex, ...qx, ...qy]);
  } else {
    const pubkeyChunked = splitToWords(BigInt(hexToDecimal(modulus)), n, k);
    return customHasher([sigAlgIndex, ...pubkeyChunked]);
  }
}
export function getLeafCSCA(dsc: string): string {
  const { signatureAlgorithm, hashFunction, modulus, x, y, bits, curve, exponent } =
    parseCertificate(dsc);
  let n, k;
  // if (signatureAlgorithm == 'ecdsa') {
    const n_and_k = getNAndK(`${signatureAlgorithm}_${hashFunction}_${curve || exponent}_${bits}` as SignatureAlgorithm);
    n = n_and_k.n;
    k = n_and_k.k;

  // } else {
    // const n_and_k = getNAndKCSCA(signatureAlgorithm);
    // n = n_and_k.n;
    // k = n_and_k.k;
  // }
  console.log(`${signatureAlgorithm}_${hashFunction}_${curve || exponent}_${bits}`);
  const sigAlgKey = `${signatureAlgorithm}_${hashFunction}_${curve || exponent}_${bits}`;
  console.log('sigAlgKey', sigAlgKey);
  const sigAlgIndex = SignatureAlgorithmIndex[sigAlgKey];
  console.log('sigAlgIndex', sigAlgIndex);

  if (sigAlgIndex == undefined) {
    console.error(`\x1b[31mInvalid signature algorithm: ${sigAlgKey}\x1b[0m`);
    throw new Error(`Invalid signature algorithm: ${sigAlgKey}`);
  }
  if (signatureAlgorithm === 'ecdsa') {
    let qx = splitToWords(BigInt(hexToDecimal(x)), n, k);
    let qy = splitToWords(BigInt(hexToDecimal(y)), n, k);
    return customHasher([sigAlgIndex, ...qx, ...qy]);
  } else {
    const pubkeyChunked = splitToWords(BigInt(hexToDecimal(modulus)), n, k);
    return customHasher([sigAlgIndex, ...pubkeyChunked]);
  }
}

export function generateCommitment(
  secret: string,
  attestation_id: string,
  pubkey_leaf: string,
  mrz_bytes: any[],
  dg2Hash: any[]
) {
  const dg2Hash2 = customHasher(formatDg2Hash(dg2Hash).map((x) => x.toString()));
  const commitment = poseidon7([
    secret,
    attestation_id,
    pubkey_leaf,
    mrz_bytes[0],
    mrz_bytes[1],
    mrz_bytes[2],
    dg2Hash2,
  ]);
  return commitment;
}

export async function fetchTreeFromUrl(url: string): Promise<LeanIMT> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  const commitmentMerkleTree = await response.json();
  console.log('\x1b[90m%s\x1b[0m', 'commitment merkle tree: ', commitmentMerkleTree);
  const tree = LeanIMT.import((a, b) => poseidon2([a, b]), commitmentMerkleTree);
  return tree;
}
