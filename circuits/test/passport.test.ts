import { describe } from 'mocha'
import chai, { assert, expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { hash, toUnsignedByte, arraysAreEqual, bytesToBigDecimal, formatAndConcatenateDataHashes, formatMrz, splitToWords } from '../../common/src/utils/utils'
import { groth16 } from 'snarkjs'
import { DataHash, PassportData } from '../../common/src/utils/types'
import { getPassportData } from '../../common/src/utils/passportData'
import { attributeToPosition } from '../../common/src/constants/constants'
const fs = require('fs');

chai.use(chaiAsPromised)

describe('Circuit tests', function () {
  this.timeout(0)

  let passportData: PassportData;
  let inputs: any;

  this.beforeAll(async () => {
    const passportData = getPassportData();

    const formattedMrz = formatMrz(passportData.mrz);
    const mrzHash = hash(formatMrz(passportData.mrz));
    const concatenatedDataHashes = formatAndConcatenateDataHashes(
      mrzHash,
      passportData.dataGroupHashes as DataHash[],
    );
    
    const concatenatedDataHashesHashDigest = hash(concatenatedDataHashes);

    // console.log('concatenatedDataHashesHashDigest', concatenatedDataHashesHashDigest)
    // console.log('passportData.eContent.slice(72, 72 + 32)', passportData.eContent.slice(72, 72 + 32))
    assert(
      arraysAreEqual(passportData.eContent.slice(72, 72 + 32), concatenatedDataHashesHashDigest),
      'concatenatedDataHashesHashDigest is at the right place in passportData.eContent'
    )

    const reveal_bitmap = Array.from({ length: 88 }, (_, i) => (i >= 16 && i <= 22) ? '1' : '0');

    inputs = {
      mrz: formattedMrz.map(byte => String(byte)),
      reveal_bitmap: reveal_bitmap.map(byte => String(byte)),
      dataHashes: concatenatedDataHashes.map(toUnsignedByte).map(byte => String(byte)),
      eContentBytes: passportData.eContent.map(toUnsignedByte).map(byte => String(byte)),
      pubkey: splitToWords(
        BigInt(passportData.pubKey.modulus),
        BigInt(64),
        BigInt(32)
      ),
      signature: splitToWords(
        BigInt(bytesToBigDecimal(passportData.encryptedDigest)),
        BigInt(64),
        BigInt(32)
      ),
      address: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    }
    
  })
  
  describe('Proof', function() {
    it('should prove and verify with valid inputs', async function () {
      // console.log('inputs', inputs)

      const { proof, publicSignals } = await groth16.fullProve(
        inputs,
        "build/proof_of_passport_js/proof_of_passport.wasm",
        "build/proof_of_passport_final.zkey"
      )

      // console.log('proof done');

      const revealChars = publicSignals.slice(0, 88).map((byte: string) => String.fromCharCode(parseInt(byte, 10))).join('');
      // console.log('reveal chars', revealChars);

      const vKey = JSON.parse(fs.readFileSync("build/verification_key.json"));
      const verified = await groth16.verify(
        vKey,
        publicSignals,
        proof
      )

      assert(verified == true, 'Should verifiable')

      // console.log('proof verified');
    })

    it('should fail to prove with invalid mrz', async function () {
      const invalidInputs = {
        ...inputs,
        mrz: inputs.mrz.map((byte: string) => String((parseInt(byte, 10) + 1) % 256)),
      }

      return expect(groth16.fullProve(
        invalidInputs,
        "build/proof_of_passport_js/proof_of_passport.wasm",
        "build/proof_of_passport_final.zkey"
      )).to.be.rejected;
    })

    it('should fail to prove with invalid eContentBytes', async function () {
      const invalidInputs = {
        ...inputs,
        eContentBytes: inputs.eContentBytes.map((byte: string) => String((parseInt(byte, 10) + 1) % 256)),
      }

      return expect(groth16.fullProve(
        invalidInputs,
        "build/proof_of_passport_js/proof_of_passport.wasm",
        "build/proof_of_passport_final.zkey"
      )).to.be.rejected;
    })
    
    it('should fail to prove with invalid signature', async function () {
      const invalidInputs = {
        ...inputs,
        signature: inputs.signature.map((byte: string) => String((parseInt(byte, 10) + 1) % 256)),
      }

      return expect(groth16.fullProve(
        invalidInputs,
        "build/proof_of_passport_js/proof_of_passport.wasm",
        "build/proof_of_passport_final.zkey"
      )).to.be.rejected;
    })
  })

  describe('Selective disclosure', function() {
    const attributeCombinations = [
      ['issuing_state', 'name'],
      ['passport_number', 'nationality', 'date_of_birth'],
      ['gender', 'expiry_date'],
    ];

    attributeCombinations.forEach(combination => {
      it(`Disclosing ${combination.join(", ")}`, async function () {
        const attributeToReveal = Object.keys(attributeToPosition).reduce((acc, attribute) => {
          acc[attribute] = combination.includes(attribute);
          return acc;
        }, {});
  
        const bitmap = Array(88).fill('0');

        Object.entries(attributeToReveal).forEach(([attribute, reveal]) => {
          if (reveal) {
            const [start, end] = attributeToPosition[attribute];
            bitmap.fill('1', start, end + 1);
          }
        });
  
        inputs = {
          ...inputs,
          reveal_bitmap: bitmap.map(String),
        }
  
        const { proof, publicSignals } = await groth16.fullProve(
          inputs,
          "build/proof_of_passport_js/proof_of_passport.wasm",
          "build/proof_of_passport_final.zkey"
        )
  
        console.log('proof done');
  
        const vKey = JSON.parse(fs.readFileSync("build/verification_key.json"));
        const verified = await groth16.verify(
          vKey,
          publicSignals,
          proof
        )
  
        assert(verified == true, 'Should verifiable')
  
        console.log('proof verified');
  
        const firstThreeElements = publicSignals.slice(0, 3);
        const bytesCount = [31, 31, 26]; // nb of bytes in each of the first three field elements
  
        const bytesArray = firstThreeElements.flatMap((element: string, index: number) => {
          const bytes = bytesCount[index];
          const elementBigInt = BigInt(element);
          const byteMask = BigInt(255); // 0xFF
        
          const bytesOfElement = [...Array(bytes)].map((_, byteIndex) => {
            return (elementBigInt >> (BigInt(byteIndex) * BigInt(8))) & byteMask;
          });
        
          return bytesOfElement;
        });
        
        const result = bytesArray.map((byte: bigint) => String.fromCharCode(Number(byte)));
  
        console.log(result);
  
        for(let i = 0; i < result.length; i++) {
          if (bitmap[i] == '1') {
            const char = String.fromCharCode(Number(inputs.mrz[i + 5]));
            assert(result[i] == char, 'Should reveal the right one');
          } else {
            assert(result[i] == '\x00', 'Should not reveal');
          }
        }
      });
    });


  })
})


