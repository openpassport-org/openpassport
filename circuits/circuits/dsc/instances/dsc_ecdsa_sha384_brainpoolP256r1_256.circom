pragma circom 2.1.9;

include "../dsc.circom";

component main { public [  merkle_root] } = DSC(24, 64, 4, 64, 4, 1664, 32, 12);


