pragma circom 2.1.6;

include "../../bigInt/bigInt.circom";
include "../../utils/isNBits.circom";
include "@openpassport/zk-email-circuits/lib/bigint.circom";

/// @notice Validates the RSA-PSS signature format
/// @dev Checks that the signature and public key are within the modulus length.
/// @param CHUNK_SIZE Size of each chunk in bits
/// @param CHUNK_NUMBER Number of chunks in modulus
/// @param KEY_LENGTH RSA key length (modulus length) in bits
template ValidateRsaPss(CHUNK_SIZE, CHUNK_NUMBER, KEY_LENGTH) {
    signal input pubkey[CHUNK_NUMBER]; 
    signal input signature[CHUNK_NUMBER];
    
    var fullChunks = KEY_LENGTH \ CHUNK_SIZE;
    var remainingBits = KEY_LENGTH % CHUNK_SIZE;

    component sigBitChecks[CHUNK_NUMBER];
    component pubkeyBitChecks[CHUNK_NUMBER];

    // Check value in each chunk can be represented in CHUNK_SIZE bits
    for (var i = 0; i < fullChunks; i++) {
        sigBitChecks[i] = isNBits(CHUNK_SIZE);
        pubkeyBitChecks[i] = isNBits(CHUNK_SIZE);
        sigBitChecks[i].in <== signature[i];
        pubkeyBitChecks[i].in <== pubkey[i];
    }
    if (remainingBits > 0) {
        sigBitChecks[fullChunks] = isNBits(remainingBits);
        pubkeyBitChecks[fullChunks] = isNBits(remainingBits);
        sigBitChecks[fullChunks].in <== signature[fullChunks];
        pubkeyBitChecks[fullChunks].in <== pubkey[fullChunks];
    }
    //zero padding for remaining chunks
    for(var i = fullChunks + 1; i < CHUNK_NUMBER; i++) {
        signature[i] === 0;
        pubkey[i] === 0;
    }

    //signature cannot exceed public key modulus
    component bigLessThan = BigLessThan(CHUNK_SIZE, CHUNK_NUMBER);
    bigLessThan.a <== signature;
    bigLessThan.b <== pubkey;
    bigLessThan.out === 1;
}