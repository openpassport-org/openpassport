export const sigAlgs = [
  { sigAlg: 'rsa', hashFunction: 'sha1', domainParameter: '3', keyLength: '4096' },
  //   { sigAlg: 'rsa', hashFunction: 'sha384', domainParameter: '65537', keyLength: '4096' },
  { sigAlg: 'rsapss', hashFunction: 'sha256', domainParameter: '65537', keyLength: '3072' },
  //   { sigAlg: 'ecdsa', hashFunction: 'sha1', domainParameter: 'secp256r1', keyLength: '256' },
  //   { sigAlg: 'ecdsa', hashFunction: 'sha512', domainParameter: 'brainpoolP384r1', keyLength: '384' },
  { sigAlg: 'ecdsa', hashFunction: 'sha384', domainParameter: 'brainpoolP256r1', keyLength: '256' },
];

export const fullSigAlgs = [
  { sigAlg: 'rsa', hashFunction: 'sha1', domainParameter: '65537', keyLength: '4096' },
  { sigAlg: 'rsa', hashFunction: 'sha1', domainParameter: '3', keyLength: '4096' },
  { sigAlg: 'rsa', hashFunction: 'sha256', domainParameter: '65537', keyLength: '4096' },
  { sigAlg: 'rsa', hashFunction: 'sha384', domainParameter: '65537', keyLength: '4096' },
  { sigAlg: 'rsa', hashFunction: 'sha512', domainParameter: '65537', keyLength: '4096' },
  { sigAlg: 'rsa', hashFunction: 'sha256', domainParameter: '3', keyLength: '4096' },
  { sigAlg: 'rsapss', hashFunction: 'sha256', domainParameter: '65537', keyLength: '4096' },
  { sigAlg: 'rsapss', hashFunction: 'sha256', domainParameter: '65537', keyLength: '2048' },
  { sigAlg: 'rsapss', hashFunction: 'sha256', domainParameter: '65537', keyLength: '3072' },
  { sigAlg: 'rsapss', hashFunction: 'sha256', domainParameter: '3', keyLength: '3072' },
  { sigAlg: 'rsapss', hashFunction: 'sha256', domainParameter: '3', keyLength: '4096' },
  { sigAlg: 'rsapss', hashFunction: 'sha384', domainParameter: '65537', keyLength: '3072' },
  { sigAlg: 'rsapss', hashFunction: 'sha384', domainParameter: '65537', keyLength: '4096' },
  { sigAlg: 'ecdsa', hashFunction: 'sha1', domainParameter: 'secp256r1', keyLength: '256' },
  // { sigAlg: 'ecdsa', hashFunction: 'sha1', domainParameter: 'secp384r1', keyLength: '384' }, //killed
  { sigAlg: 'ecdsa', hashFunction: 'sha1', domainParameter: 'brainpoolP256r1', keyLength: '256' },
  { sigAlg: 'ecdsa', hashFunction: 'sha256', domainParameter: 'brainpoolP256r1', keyLength: '256' },
  { sigAlg: 'ecdsa', hashFunction: 'sha256', domainParameter: 'secp256r1', keyLength: '256' },
  { sigAlg: 'ecdsa', hashFunction: 'sha256', domainParameter: 'secp384r1', keyLength: '384' },

  { sigAlg: 'ecdsa', hashFunction: 'sha384', domainParameter: 'brainpoolP256r1', keyLength: '256' },
  { sigAlg: 'ecdsa', hashFunction: 'sha384', domainParameter: 'brainpoolP384r1', keyLength: '384' },
  { sigAlg: 'ecdsa', hashFunction: 'sha384', domainParameter: 'secp384r1', keyLength: '384' },
  { sigAlg: 'ecdsa', hashFunction: 'sha512', domainParameter: 'brainpoolP256r1', keyLength: '256' },
  { sigAlg: 'ecdsa', hashFunction: 'sha512', domainParameter: 'brainpoolP384r1', keyLength: '384' },
];
