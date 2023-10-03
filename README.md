# Embassy

A monorepo for embassy, a proof of passport protocol.

Embassy lets users scan the NFC chip in their government-issued passport.
If the signature is valid, the user can generate a proof that can be verified onchain.
We are using that proof to mint them a Soulbound Token (SBT) they can use to show that they indeed hold
an official passport.

### Roadmap

- ✅ Make sure we can actually verify that a passport signature is signed by the issuing country
- ✅ Modify the Next.js frontend of `zkrsa` in order to accept an endpoint that stores signature data from someone scanning their passports
- ✅ Get zkrsa working with the signature format we are able to retrieve from the Android app
- ✅ Contract to mint the SBT when proof is valid
- ✅ WalletConnect integration to get the address
- ✅ Let user send their proof onchain to mint the SBT
- ✅ Commit to minter address in circuit to avoid front-running
- 🚧 On-chain registry of CSCA pubkeys based on the official ICAO masterlist
- 🚧 Decompose the hashed eContent of the passport into the private user data and reconstitute them in the circuit
- ✅ Modify the Android app to let people send their signature data to the Next.js backend (and store it temporarily)
- 🚧 Safe Module to claim a Safe if holding the right SBT
- 
