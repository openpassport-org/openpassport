pragma circom 2.1.9;

include "./signatureAlgorithm.circom";
include "../circomlib/signatures/ecdsa.circom";

template Secp256r1Verifier(signatureAlgorithm, n, k) {
    var kLengthFactor = getKLengthFactor(signatureAlgorithm);
    var kScaled = k * kLengthFactor;

    var HASH_LEN_BITS = getHashLength(signatureAlgorithm);
    var msg_len = (HASH_LEN_BITS + n) \ n;

    signal input signature[kScaled];
    signal input pubKey[kScaled];
    signal input hashParsed[msg_len];

    signal msgHash[6];

    for(var i = 0; i < 6; i++) {
        if (i < msg_len) {
            msgHash[i] <== hashParsed[i];
        } else {
            msgHash[i] <== 0;
        }
    }


    signal signature_r[k]; // ECDSA signature component r
    signal signature_s[k]; // ECDSA signature component s
    signal pubKey_x[k];
    signal pubKey_y[k];

    for (var i = 0; i < k; i++) {
        signature_r[i] <== signature[i];
        signature_s[i] <== signature[i + k];
        pubKey_x[i] <== pubKey[i];
        pubKey_y[i] <== pubKey[i + k];
    }
    signal pubkey_xy[2][k] <== [pubKey_x, pubKey_y];

    // verify eContentHash signature
    // component ecdsa_verify = ECDSAVerifyNoPubkeyCheck(n, k);
    component ecdsa_verify = verifyECDSABigInt(n, k, [ 
        18446744073709551612, 
        4294967295, 
        0, 
        18446744069414584321 
    ], 
    [
        4309448131093880907,
        7285987128567378166,
        12964664127075681980,
        6540974713487397863
    ],
    [ 
        18446744073709551615, 
        4294967295, 
        0, 
        18446744069414584321 
    ]);

    ecdsa_verify.pubkey <== pubkey_xy;
    ecdsa_verify.signature <== [signature_r, signature_s];
    ecdsa_verify.hashed <== hashParsed;
    ecdsa_verify.dummy <== 0;

    // ecdsa_verify.r <== signature_r;
    // ecdsa_verify.s <== signature_s;
    // ecdsa_verify.msghash <== msgHash;
    // ecdsa_verify.pubkey <== pubkey_xy;

    // 1 === ecdsa_verify.result;

}