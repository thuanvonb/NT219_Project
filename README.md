# Repository for the project of the course NT230 - Cryptography

## About this repository:
This repo includes the sources for 2 new post-quantum cryptography standards:
  - FIPS 203: Module-Lattice-Based Key Encapsulation Mechanism Standard
  - FIPS 204: Module-Lattice-Based Digital Signature Standard

## References:
  - FIPS 203: https://csrc.nist.gov/pubs/fips/203/ipd
  - FIPS 204: https://csrc.nist.gov/pubs/fips/204/ipd

## Dependencies:
- `pycryptodome`

## How to use this repository
* Inside the repo, there are python sources implementing two new cryptographic standards: FIPS 203 and FIPS 204.
* The main file for ML-KEM is `ml_kem.py` and the main file for ML-DSA is `ml_dsa.py`. Other files in `KEM` and `DSA` folders are supporting components, respectively.
* Running each file will run a simple test on the implementation:
    * For ML-KEM, it will simply create key pair, encapsulate secret and decapsulate it. If nothing goes wrong, both parties should have the same secret, indicating that the ML-KEM works properly.
    * For ML-DSA, a pair of public key and secret key will be generated. A randomly generated 64-byte-long message will then be used to sign with secret key to create signature. After, the public key is used to verify that signture. If the code works flawlessly, the final result should be `True`.