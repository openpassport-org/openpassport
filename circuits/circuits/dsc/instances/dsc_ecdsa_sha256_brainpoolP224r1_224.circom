pragma circom 2.1.9;

include "../dsc.circom";

component main { public [  merkle_root] } = DSC(28, 32, 7, 32, 7, 1664, 28, 12);
