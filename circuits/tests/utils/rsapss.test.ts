import { wasm as wasmTester } from 'circom_tester';
import { describe, it } from 'mocha';
import path from 'path';
import { SignatureAlgorithm } from '../../../common/src/utils/types';
import { generateMalleableRsaPssInputs, generateMockRsaPssInputs } from './generateMockInputsRsaPss';
import { expect } from 'chai';

describe('VerifyRsapss Circuit Test', function () {
  this.timeout(0);
  const fullAlgorithms: { algo: SignatureAlgorithm; saltLength: number }[] = [
    { algo: 'rsapss_sha256_65537_4096', saltLength: 64 },
    { algo: 'rsapss_sha256_65537_3072', saltLength: 64 },
    { algo: 'rsapss_sha256_65537_2048', saltLength: 64 },
    { algo: 'rsapss_sha256_3_4096', saltLength: 64 },
    { algo: 'rsapss_sha256_3_3072', saltLength: 64 },
    { algo: 'rsapss_sha256_3_2048', saltLength: 64 },
    { algo: 'rsapss_sha512_3_4096', saltLength: 64 },
    { algo: 'rsapss_sha512_3_2048', saltLength: 64 },
    { algo: 'rsapss_sha384_65537_4096', saltLength: 48 },
    { algo: 'rsapss_sha384_65537_3072', saltLength: 48 },
    { algo: 'rsapss_sha384_3_4096', saltLength: 48 },
    { algo: 'rsapss_sha384_3_3072', saltLength: 48 },
  ];

  const sigAlgs: { algo: SignatureAlgorithm; saltLength: number }[] = [
    { algo: 'rsapss_sha256_65537_4096', saltLength: 32 },
  ];

  const testSuite = process.env.FULL_TEST_SUITE === 'true' ? fullAlgorithms : sigAlgs;

  testSuite.forEach((algorithm) => {
    it(`should verify RSA-PSS signature using the circuit for ${algorithm.algo}_${algorithm.saltLength}`, async function () {
      this.timeout(0);
      // Generate inputs using the utility function
      const { signature, modulus, message } = generateMockRsaPssInputs(
        algorithm.algo,
        algorithm.saltLength
      );

      // Run circuit with inputs
      const circuit = await wasmTester(
        path.join(
          __dirname,
          `../../circuits/tests/utils/rsapss/test_${algorithm.algo}_${algorithm.saltLength}.circom`
        ),
        {
          include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
        }
      );

      // Log the inputs for debugging
      console.log(`Testing algorithm: ${algorithm.algo} with salt length: ${algorithm.saltLength}`);

      const witness = await circuit.calculateWitness({
        signature,
        modulus,
        message,
      });

      // Check constraints
      await circuit.checkConstraints(witness);
    });

    it('Should fail to verify RSA-PSS signature with invalid signature', async function () {
      const { signature, modulus, message } = generateMockRsaPssInputs(
        algorithm.algo,
        algorithm.saltLength
      );

      const invalidSignature = signature.map((byte: string) => String((parseInt(byte) + 1) % 256));
      const circuit = await wasmTester(
        path.join(
          __dirname,
          `../../circuits/tests/utils/rsapss/test_${algorithm.algo}_${algorithm.saltLength}.circom`
        ),
        {
          include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
        }
      );

      try {
        await circuit.calculateWitness({
          signature: invalidSignature,
          modulus,
          message,
        });
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('Should fail to verify RSA-PSS signature with invalid message', async function () {
      const { signature, modulus, message } = generateMockRsaPssInputs(
        algorithm.algo,
        algorithm.saltLength
      );

      const invalidMessage = message.map((byte: number) => String((byte + 1) % 256));
      const circuit = await wasmTester(
        path.join(
          __dirname,
          `../../circuits/tests/utils/rsapss/test_${algorithm.algo}_${algorithm.saltLength}.circom`
        ),
        {
          include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
        }
      );

      try {
        await circuit.calculateWitness({
          signature,
          modulus,
          message: invalidMessage,
        });
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

  it('Should reject signatures greater than or equal to modulus', async function () {
    const { signature, modulus, message, n, k } = generateMockRsaPssInputs(
      algorithm.algo,
      algorithm.saltLength
    );
  
    const largeSignature = [...signature];
    largeSignature[k-1] = String(BigInt(modulus[k-1]) + 1n);
  
    const circuit = await wasmTester(
      path.join(
        __dirname,
        `../../circuits/tests/utils/rsapss/test_${algorithm.algo}_${algorithm.saltLength}.circom`
      ),
      {
        include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
      }
    );
  
    try {
      await circuit.calculateWitness({
        signature: largeSignature,
        modulus,
        message,
      });
      throw new Error('Circuit accepted signature >= modulus');
    } catch (error) {
      expect(error.message).to.include('Assert Failed');
    }
    });
    
    it('Should reject malleable signatures (signature + modulus)', async function () {
      const { signature, modulus, message } = generateMalleableRsaPssInputs(
        algorithm.algo,
        algorithm.saltLength
      );
    
      const circuit = await wasmTester(
        path.join(
          __dirname,
          `../../circuits/tests/utils/rsapss/test_${algorithm.algo}_${algorithm.saltLength}.circom`
        ),
        {
          include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
        }
      );
    
      try {
        await circuit.calculateWitness({
          signature,
          modulus,
          message,
        });
        throw new Error('Circuit accepted malleable signature');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });

    it('Should Fails when chunk has more bits than n', async function () {
      const { signature, modulus, message } = generateMockRsaPssInputs(
        algorithm.algo,
        algorithm.saltLength
      );

      let overflowSignature = [...signature];
      overflowSignature[0] = String(BigInt(2) ** BigInt(122));
    
      const circuit = await wasmTester(
        path.join(
          __dirname,
          `../../circuits/tests/utils/rsapss/test_${algorithm.algo}_${algorithm.saltLength}.circom`
        ),
        {
          include: ['node_modules', './node_modules/@zk-kit/binary-merkle-root.circom/src'],
        }
      );
    
      try {
        await circuit.calculateWitness({
          signature: overflowSignature,
          modulus,
          message,
        });
        throw new Error('Circuit accepted malleable signature');
      } catch (error) {
        expect(error.message).to.include('Assert Failed');
      }
    });
  });
});
