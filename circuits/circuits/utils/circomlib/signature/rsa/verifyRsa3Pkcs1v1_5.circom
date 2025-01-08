pragma circom 2.1.9;

include "@zk-email/circuits/lib/fp.circom";
include "./pkcs1v1_5Padding.circom";
include "circomlib/circuits/bitify.circom";

// For 2048bits RSA, CHUNK_SIZE = 64, CHUNK_NUMBER = 32
// For 3072bits RSA, CHUNK_SIZE = 64, CHUNK_NUMBER = 48
// For 4096bits RSA, CHUNK_SIZE = 64, CHUNK_NUMBER = 64

// HASH_SIZE is the size of the hash in bits

template VerifyRsa3Pkcs1v1_5(CHUNK_SIZE, CHUNK_NUMBER, HASH_SIZE) {
    signal input signature[CHUNK_NUMBER];
    signal input modulus[CHUNK_NUMBER];

    signal input message[CHUNK_NUMBER];

    // 1. Add padding to the hashed message
    component padder = Pkcs1v1_5Padding(CHUNK_SIZE, CHUNK_NUMBER, HASH_SIZE);
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        padder.modulus[i] <== modulus[i];
        padder.message[i] <== message[i];
    }

    // 2. Check that the signature is in proper form and reduced mod modulus.
    component signatureRangeCheck[CHUNK_NUMBER];
    component bigLessThan = BigLessThan(CHUNK_SIZE, CHUNK_NUMBER);
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        signatureRangeCheck[i] = Num2Bits(CHUNK_SIZE);
        signatureRangeCheck[i].in <== signature[i];
        bigLessThan.a[i] <== signature[i];
        bigLessThan.b[i] <== modulus[i];
    }
    bigLessThan.out === 1;

    // 3. Compute the signature^exponent mod modulus
    component bigPow = FpPow3Mod(CHUNK_SIZE, CHUNK_NUMBER);
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        bigPow.base[i] <== signature[i];
        bigPow.modulus[i] <== modulus[i];
    }

    // 4. Check that the computed value is equal to the padded message
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        bigPow.out[i] === padder.out[i];
    }
}

/// @title FpPow3Mod
/// @notice Computes base^3 mod modulus
/// @dev Does not necessarily reduce fully mod modulus (the answer could be too big by a multiple of modulus)
/// @param n Number of bits per chunk the modulus is split into.
/// @param k Number of chunks the modulus is split into.
/// @input base The base to exponentiate; assumes to consist of `k` chunks, each of which must fit in `n` bits
/// @input modulus The modulus; assumes to consist of `k` chunks, each of which must fit in `n` bits
/// @output out The result of the exponentiation.
template FpPow3Mod(n, k) {
    signal input base[k];
    signal input modulus[k];

    signal output out[k];

    component doublers = FpMul(n, k);
    component adder = FpMul(n, k);

    for (var j = 0; j < k; j++) {
        adder.p[j] <== modulus[j];
        doublers.p[j] <== modulus[j];
    }
    for (var j = 0; j < k; j++) {
        doublers.a[j] <== base[j];
        doublers.b[j] <== base[j];
    }
    for (var j = 0; j < k; j++) {
        adder.a[j] <== base[j];
        adder.b[j] <== doublers.out[j];
    }
    for (var j = 0; j < k; j++) {
        out[j] <== adder.out[j];
    }
}
