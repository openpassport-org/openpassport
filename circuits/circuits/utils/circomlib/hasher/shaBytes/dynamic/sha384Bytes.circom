pragma circom 2.1.9;

include "../../../bitify/bitify.circom";
include "../../../bitify/comparators.circom";
// include "../../other/fp.circom";
// include "../../other/array.circom";
include "../../../utils/array.circom";

include "../../sha2/sha384_temp/sha384_hash_bits.circom";

template Sha384Bytes(maxByteLength) {
    signal input paddedIn[maxByteLength];
    signal input paddedInLength;
    signal output out[384];

    var maxBits = maxByteLength * 8;
    component sha = Sha384Dynamic(maxBits);

    component bytes[maxByteLength];
    for (var i = 0; i < maxByteLength; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== paddedIn[i];
        for (var j = 0; j < 8; j++) {
            sha.in[i*8+j] <== bytes[i].out[7-j];
        }
    }
    sha.paddedInLength <== paddedInLength * 8;

    for (var i = 0; i < 384; i++) {
        out[i] <== sha.out[i];
    }
}
