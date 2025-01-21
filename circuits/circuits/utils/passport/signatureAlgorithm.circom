pragma circom 2.1.9;

/*
 ID to Signature Algorithm
  1: rsa_sha256_65537_2048
  3: rsa_sha1_65537_2048
  4: rsapss_sha256_65537_2048
  7: ecdsa_sha1_secp256r1_256
  8: ecdsa_sha256_secp256r1_256
  9: ecdsa_sha384_secp384r1_384
 10: rsa_sha256_65537_4096
 11: rsa_sha1_65537_4096
 12: rsapss_sha256_65537_4096
 13: rsa_sha256_3_2048
 14: rsa_sha256_65537_3072
 15: rsa_sha512_65537_4096
 16: rsapss_sha256_3_3072
 17: rsapss_sha256_3_4096
 18: rsapss_sha384_65537_3072
 19: rsapss_sha256_65537_3072
 21: ecdsa_sha256_brainpoolP256r1_256
 22: ecdsa_sha384_brainpoolP384r1_384
 23: ecdsa_sha256_secp384r1_384
 24: ecdsa_sha384_brainpoolP256r1_256
 25: ecdsa_sha512_brainpoolP256r1_256
 26: ecdsa_sha512_brainpoolP384r1_384
 27: ecdsa_sha1_brainpoolP224r1_224
 28: ecdsa_sha256_brainpoolP224r1_224
 29: ecdsa_sha512_brainpoolP512r1_512
 30: ecdsa_sha224_brainpoolP224r1_224
 31: rsa_sha512_65537_2048
 32: rsa_sha256_3_4096
 33: rsa_sha1_3_4096
 34: rsa_sha384_65537_4096
*/

function getHashLength(signatureAlgorithm) {
    if (signatureAlgorithm == 1 ) {
        return 256;
    }
    if (signatureAlgorithm == 3) {
        return 160;
    }
    if (signatureAlgorithm == 4) {
        return 256;
    }
    if (signatureAlgorithm == 7) {
        return 160;
    }
    if (signatureAlgorithm == 8) {
        return 256;
    }
    if (signatureAlgorithm == 9) {
        return 384;
    }
    if (signatureAlgorithm == 10) {
        return 256;
    }
    if (signatureAlgorithm == 11) {
        return 160;
    }
    if (signatureAlgorithm == 12) {
        return 256;
    }
    if (signatureAlgorithm == 13) {
        return 256;
    }
    if (signatureAlgorithm == 14) {
        return 256;
    }
    if (signatureAlgorithm == 15) {
        return 512;
    }
    if (signatureAlgorithm == 16) {
        return 256;
    }
    if (signatureAlgorithm == 17) {
        return 256;
    }
    if (signatureAlgorithm == 18) {
        return 384;
    }
    if (signatureAlgorithm == 19) {
        return 256;
    }
    if (signatureAlgorithm == 20) {
        return 256;
    }
    if (signatureAlgorithm == 21) { 
        return 256;
    }
    if (signatureAlgorithm == 22) {
        return 384;
    }
    if (signatureAlgorithm == 23) { 
        return 256;
    }
    if (signatureAlgorithm == 24) {
        return 384;
    }
    if (signatureAlgorithm == 25) {
        return 512; 
    }
    if (signatureAlgorithm == 26) { 
        return 512;
    }
    if (signatureAlgorithm == 27) { 
        return 160;
    }
    if (signatureAlgorithm == 28) { 
        return 256;
    }
    if (signatureAlgorithm == 29) { 
        return 512;
    }
    if (signatureAlgorithm == 30) { 
        return 224;
    }
    if (signatureAlgorithm == 31) {
        return 512;
    }
    if (signatureAlgorithm == 32) {
        return 256;
    }
    if (signatureAlgorithm == 33) {
        return 160;
    }
    if (signatureAlgorithm == 34) {
        return 384;
    }
    return 0;
}

function getKeyLength(signatureAlgorithm) {
    if (signatureAlgorithm == 1 ) {
        return 2048;
    }
    if (signatureAlgorithm == 3) {
        return 2048;
    }
    if (signatureAlgorithm == 4) {
        return 2048;
    }
    if (signatureAlgorithm == 7) {
        return 256;
    }
    if (signatureAlgorithm == 8) {
        return 256;
    }
    if (signatureAlgorithm == 9) {
        return 384;
    }
    if (signatureAlgorithm == 10) {
        return 4096;
    }
    if (signatureAlgorithm == 11) {
        return 4096;
    }
    if (signatureAlgorithm == 12) {
        return 4096;
    }
    if (signatureAlgorithm == 13) {
        return 2048;
    }
    if (signatureAlgorithm == 14) {
        return 3072;
    }
    if (signatureAlgorithm == 15) {
        return 4096;
    }
    if (signatureAlgorithm == 16) {
        return 3072;
    }
    if (signatureAlgorithm == 17) {
        return 4096;
    }
    if (signatureAlgorithm == 18) {
        return 3072;
    }
    if (signatureAlgorithm == 19) {
        return 3072;
    }
    if (signatureAlgorithm == 21) { 
        return 256;
    }
    if (signatureAlgorithm == 22) { 
        return 384;
    }
    if (signatureAlgorithm == 23) { 
        return 384;
    }
    if (signatureAlgorithm == 24) { 
        return 256;
    } 
    if (signatureAlgorithm == 25) { 
        return 256;
    }
    if (signatureAlgorithm == 26) { 
        return 384;
    }
    if (signatureAlgorithm == 27) { 
        return 224;
    }
    if (signatureAlgorithm == 28) { 
        return 224;
    }
    if (signatureAlgorithm == 29) { 
        return 512;
    }
    if (signatureAlgorithm == 30) { 
        return 224;
    }
    if (signatureAlgorithm == 31) {
        return 2048;
    }
    if (signatureAlgorithm == 32) {
        return 4096;
    }
    if (signatureAlgorithm == 33) {
        return 4096;
    }
    if (signatureAlgorithm == 34) {
        return 4096;
    }
    return 0;
}

//returns 1 for rsa, 2 for ecdsa
function getKLengthFactor(signatureAlgorithm) {
    if (signatureAlgorithm == 1) {
        return 1;
    }
    if (signatureAlgorithm == 3) {
        return 1;
    }
    if (signatureAlgorithm == 4) {
        return 1;
    }
    if (signatureAlgorithm == 7) {
        return 2;
    }
    if (signatureAlgorithm == 8) {
        return 2;
    }
    if (signatureAlgorithm == 9) {
        return 2;
    }
    if (signatureAlgorithm == 10) {
        return 1;
    }
    if (signatureAlgorithm == 11) {
        return 1;
    }
    if (signatureAlgorithm == 12) {
        return 1;
    }
    if (signatureAlgorithm == 13) {
        return 1;
    }
    if (signatureAlgorithm == 14) {
        return 1;
    }
    if (signatureAlgorithm == 15) {
        return 1;
    }
    if (signatureAlgorithm == 16) {
        return 1;
    }
    if (signatureAlgorithm == 17) {
        return 1;
    }
    if (signatureAlgorithm == 18) {
        return 1;
    }
    if (signatureAlgorithm == 19) {
        return 1;
    }
    if (signatureAlgorithm == 21) { 
        return 2;
    }
    if (signatureAlgorithm == 22) { 
        return 2;
    }
    if (signatureAlgorithm == 23) { 
        return 2;
    }
    if (signatureAlgorithm == 24) { 
        return 2;
    }
    if (signatureAlgorithm == 25) { 
        return 2;
    }
    if (signatureAlgorithm == 26) { 
        return 2;
    }
    if (signatureAlgorithm == 27) { 
        return 2;
    }
    if (signatureAlgorithm == 28) { 
        return 2;
    }
    if (signatureAlgorithm == 29) { 
        return 2;
    }
    if (signatureAlgorithm == 30) { 
        return 2;
    }
    if (signatureAlgorithm == 31) {
        return 1;
    }
    if (signatureAlgorithm == 32) {
        return 1;
    }
    if (signatureAlgorithm == 33) {
        return 1;
    }
    if (signatureAlgorithm == 34) {
        return 1;
    }
    return 0;

}

function getExponentBits(signatureAlgorithm) {
    // returns the amounts of bits of the exponent of type 2^n +1
    if (signatureAlgorithm == 1 ) {
        return 17; // 65537
    }
    if (signatureAlgorithm == 3 ) {
        return 17;
    }
    if (signatureAlgorithm == 4 ) {
        return 17;
    }
    if (signatureAlgorithm == 10) {
        return 17;
    }
    if (signatureAlgorithm == 11) {
        return 17;
    }
    if (signatureAlgorithm == 12) {
        return 17;
    }
    if (signatureAlgorithm == 13) {
        return 2; // 3
    }
    if (signatureAlgorithm == 14) {
        return 17;
    }
    if (signatureAlgorithm == 15) {
        return 17;
    }
    if (signatureAlgorithm == 16) {
        return 2;
    }
    if (signatureAlgorithm == 17) {
        return 2;
    }
    if (signatureAlgorithm == 18) {
        return 17;
    }
    if (signatureAlgorithm == 19) {
        return 17;
    }
    if (signatureAlgorithm == 31) {
        return 17;
    }
    if (signatureAlgorithm == 32) {
        return 2;
    }
    if (signatureAlgorithm == 33) {
        return 2;
    }
    if (signatureAlgorithm == 34) {
        return 17;
    }
    return 0;
}
