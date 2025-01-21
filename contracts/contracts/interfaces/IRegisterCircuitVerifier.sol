//SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IRegisterCircuitVerifier {

    struct RegisterCircuitProof {
        uint[2] a;
        uint[2][2] b;
        uint[2] c;
        uint[3] pubSignals;
    }

    function verifyProof (
        RegisterCircuitProof calldata _proof
    ) external view returns (bool);
}